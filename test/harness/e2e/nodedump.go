package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	hk8s "github.com/tripod-networks/wireguard-gateway-operator/test/harness/k8s"
)

// nodeCaptureMaxBytes bounds one captured command's output. The node's main route
// table carries a /32 per local pod and would bury the tunnel state printed next to it.
const nodeCaptureMaxBytes = 8192

// nodeCaptureTimeout bounds one pod capture, so a wedged exec does not spend the
// failure cleanup budget the GCP orphan drain shares.
const nodeCaptureTimeout = 30 * time.Second

// nodeDumpTimeout bounds the whole dump: sixteen 30s captures would exceed the 7 min
// failure cleanup budget, and the GCP orphan drain after it needs its 4 min.
const nodeDumpTimeout = 2 * time.Minute

// conntrackCaptureLines bounds the conntrack listing, which is per-flow and
// unbounded on a busy node.
const conntrackCaptureLines = 40

// nodeCapture is one command in the Local-mode node data-plane capture: argv (no
// shell) and the heading it is logged under.
type nodeCapture struct {
	label string
	argv  []string
}

// dumpLocalDataPlane logs the node-namespace state the Lease holder programmed. Commands
// run in the holder's hostNetwork link pod; it is a no-op outside Local mode.
func (s *Suite) dumpLocalDataPlane(ctx context.Context, t *testing.T, stack *Stack) {
	t.Helper()
	if stack.TrafficPolicy != hk8s.TrafficPolicyLocal {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, nodeDumpTimeout)
	defer cancel()

	holder, err := s.client.GetLeaseHolder(ctx, stack.Namespace, linkLeaseName(stack.GatewayName))
	if err != nil {
		s.log.Warn("dump local data plane: read lease holder", zap.Error(err))
		return
	}
	if holder == "" {
		s.log.Warn("dump local data plane: link Lease has no holder")
		return
	}

	status, err := s.client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
	if err != nil {
		s.log.Warn("dump local data plane: read gateway status", zap.Error(err))
		return
	}
	if status.LinkID == 0 {
		s.log.Warn("dump local data plane: gateway reports no status.link.id")
		return
	}
	identity := link.NewGatewayIdentity(status.LinkID)
	slots := []int{0}
	if raw, err := s.client.ConfigMapData(ctx, stack.Namespace, linkConfigMapName(stack.GatewayName), linkConfigMapKey); err != nil {
		s.log.Warn("dump local data plane: read runtime config", zap.Error(err))
	} else {
		var config link.RuntimeConfig
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			s.log.Warn("dump local data plane: decode runtime config", zap.Error(err))
		} else {
			for _, peer := range config.WireGuard.Peers {
				if peer.Slot != 0 {
					slots = append(slots, peer.Slot)
				}
			}
		}
	}

	node, err := s.client.PodNode(ctx, stack.Namespace, holder)
	if err != nil {
		s.log.Warn("dump local data plane: read holder node", zap.String("pod", holder), zap.Error(err))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "holder=%s node=%s id=%d nftTable=%s\n", holder, node, identity.ID, identity.NftTable)

	for _, slot := range slots {
		id := link.NewSlotIdentity(identity.ID, slot)
		fmt.Fprintf(&b, "slot=%d interface=%s routeTable=%d mark=%s/%s\n", slot, id.Interface, id.RouteTable, id.Mark, id.MarkMask)
		for _, c := range localNodeCaptures(identity, id) {
			fmt.Fprintf(&b, "-- %s --\n%s\n", c.label, s.captureInLinkPod(ctx, stack.Namespace, holder, c.argv))
		}
	}
	fmt.Fprintf(&b, "-- conntrack tcp dport %d (node %s) --\n%s\n",
		stack.TCPPublicPort, node, s.captureConntrack(ctx, node, stack.TCPPublicPort))

	t.Logf("---- local data plane %s/%s ----\n%s---- end local data plane ----", stack.Namespace, stack.GatewayName, b.String())
}

// localNodeCaptures derives the plan from the identity in status.link.id, and reads sysctls
// through the link's own mount. On a disagreement, dump.go's link ConfigMap section decides.
func localNodeCaptures(gateway link.GatewayIdentity, id link.SlotIdentity) []nodeCapture {
	confPath := link.HostProcSysNetPath + "/ipv4/conf/" + id.Interface
	return []nodeCapture{
		cmd("nft", "list", "table", "inet", gateway.NftTable),
		cmd("ip", "rule", "show"),
		cmd("ip", "route", "show", "table", strconv.Itoa(id.RouteTable)),
		cmd("ip", "route", "show", "table", "main"),
		cmd("ip", "-d", "link", "show", id.Interface),
		cmd("ip", "-s", "-s", "link", "show", id.Interface),
		cmd("ip", "route", "get", "1.1.1.1", "mark", id.Mark),
		cmd("ip", "addr", "show", id.Interface),
		cmd("wg", "show", id.Interface),
		{"net.ipv4.ip_forward", []string{"cat", link.HostProcSysNetPath + "/ipv4/ip_forward"}},
		{"net.ipv4.conf.all.rp_filter", []string{"cat", link.HostProcSysNetPath + "/ipv4/conf/all/rp_filter"}},
		{"net.ipv4.conf.default.rp_filter", []string{"cat", link.HostProcSysNetPath + "/ipv4/conf/default/rp_filter"}},
		{"net.ipv4.conf.all.src_valid_mark", []string{"cat", link.HostProcSysNetPath + "/ipv4/conf/all/src_valid_mark"}},
		{"net.ipv4.conf." + id.Interface + ".rp_filter", []string{"cat", confPath + "/rp_filter"}},
		{"net.ipv4.conf." + id.Interface + ".forwarding", []string{"cat", confPath + "/forwarding"}},
	}
}

// cmd is a capture whose heading is its own argv.
func cmd(argv ...string) nodeCapture { return nodeCapture{strings.Join(argv, " "), argv} }

// captureInLinkPod returns the output, or the error as the body so a failed capture is
// visible in the dump. stderr is kept: nft and ip report what they could not find there.
func (s *Suite) captureInLinkPod(ctx context.Context, namespace, pod string, argv []string) string {
	if ctx.Err() != nil {
		return "<skipped: dump budget exhausted>"
	}
	cctx, cancel := context.WithTimeout(ctx, nodeCaptureTimeout)
	defer cancel()
	stdout, stderr, err := s.client.ExecInPod(cctx, namespace, pod, argv)
	out := strings.TrimSpace(stdout)
	if e := strings.TrimSpace(stderr); e != "" {
		out = strings.TrimSpace(out + "\n" + e)
	}
	if err != nil {
		s.log.Warn("capture node state", zap.String("pod", pod), zap.Strings("argv", argv), zap.Error(err))
		marker := fmt.Sprintf("<unavailable: %v>", err)
		if ctx.Err() == nil && errors.Is(cctx.Err(), context.DeadlineExceeded) {
			marker = fmt.Sprintf("<unavailable: timed out after %s>", nodeCaptureTimeout)
		}
		return truncate(strings.TrimSpace(marker+"\n"+out), nodeCaptureMaxBytes)
	}
	if out == "" {
		return "<empty>"
	}
	return truncate(out, nodeCaptureMaxBytes)
}

// captureConntrack lists entries whose original destination port is the probed public
// port. conntrack ships on the kind node but not in the link image, hence the docker exec.
func (s *Suite) captureConntrack(ctx context.Context, node string, port int) string {
	if ctx.Err() != nil {
		return "<skipped: dump budget exhausted>"
	}
	if node == "" {
		return "<skipped: holder node unknown>"
	}
	out, err := hk8s.NodeExec(ctx, node,
		"conntrack", "-L", "-p", "tcp", "--orig-port-dst", strconv.Itoa(port))
	if err != nil {
		s.log.Warn("capture conntrack", zap.String("node", node), zap.Int("port", port), zap.Error(err))
		return truncate(strings.TrimSpace(fmt.Sprintf("<unavailable: %v>\n%s", err, out)), nodeCaptureMaxBytes)
	}
	if strings.TrimSpace(out) == "" {
		return "<empty>"
	}
	return truncate(headLines(out, conntrackCaptureLines), nodeCaptureMaxBytes)
}

// truncate caps s at limit bytes, marking the cut so a reader does not mistake a
// bounded capture for a short one.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "\n<truncated>"
}

// headLines keeps the first n lines of s, marking the cut.
func headLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n") + "\n<truncated>"
}
