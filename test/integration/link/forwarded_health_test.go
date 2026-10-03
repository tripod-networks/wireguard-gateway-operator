package linkint

// The holder DNATs the health port to a responder pod on its own node, the same way it DNATs a
// forward: reachability through that path is the probe's verdict.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/netns"
)

const (
	fhLinkID        = 9
	fhHealthPort    = 27009
	fhResponderIP   = "10.94.0.2"
	fhResponderPort = 8080
	fhNodeName      = "fh-node"
)

// fhLocalTopologyScript wires client <-> vm <-> node, plus a responder netns reached from the
// node over its own veth, standing in for a pod on the node's network.
func fhLocalTopologyScript(iface string) string {
	return fmt.Sprintf(`set -e
ip netns add client
ip netns add vm
ip link add vc-cl type veth peer name vc-vm
ip link set vc-cl netns client
ip link set vc-vm netns vm
ip netns exec client ip addr add 10.0.1.2/24 dev vc-cl
ip netns exec client ip link set vc-cl up
ip netns exec client ip link set lo up
ip netns exec client ip route add default via 10.0.1.1
ip netns exec vm ip addr add 10.0.1.1/24 dev vc-vm
ip netns exec vm ip link set vc-vm up
ip netns exec vm ip link set lo up

ip link add vt-vm type veth peer name %[1]s
ip link set vt-vm netns vm
ip netns exec vm ip addr add 10.99.0.1/24 dev vt-vm
ip netns exec vm ip link set vt-vm up
ip netns exec vm sysctl -w net.ipv4.ip_forward=1
ip netns exec vm sysctl -w net.ipv4.conf.vt-vm.proxy_arp=1
ip addr add 10.99.0.2/24 dev %[1]s
ip link set %[1]s up

ip netns add sink
ip link add ds-nd type veth peer name ds-sink
ip link set ds-sink netns sink
ip addr add 192.0.2.1/24 dev ds-nd
ip link set ds-nd up
ip netns exec sink ip addr add 192.0.2.2/24 dev ds-sink
ip netns exec sink ip link set ds-sink up
ip netns exec sink ip link set lo up

ip netns add responder
ip link add fh-nd type veth peer name fh-rp
ip link set fh-rp netns responder
ip addr add 10.94.0.1/24 dev fh-nd
ip link set fh-nd up
ip netns exec responder ip addr add %[2]s/24 dev fh-rp
ip netns exec responder ip link set fh-rp up
ip netns exec responder ip link set lo up
ip netns exec responder ip route add default via 10.94.0.1

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.%[1]s.rp_filter=0
ip route replace default via 192.0.2.2 dev ds-nd
`, iface, fhResponderIP)
}

// fhVMRuleset DNATs every port but 51820 to the node's tunnel address, matching
// traffic-policy=local's real VM ruleset (local_datapath_test.go's vmRuleset).
const fhVMRuleset = `add table inet gateway
flush table inet gateway
table inet gateway {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "vc-vm" meta l4proto { tcp, udp } th dport != 51820 dnat ip to 10.99.0.2
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "vt-vm" return
	}
}
`

// fhRuntimeConfig is the Local single-slot fixture health-forwarding tests build on. A blank
// responderIP omits the Responders entry, rendering no health DNAT.
func fhRuntimeConfig(responderIP string) link.RuntimeConfig {
	gwIdent := link.NewGatewayIdentity(fhLinkID)
	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		HealthPort:    fhHealthPort,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB="}}},
		ResponderPort: fhResponderPort,
	}
	if responderIP != "" {
		rc.Responders = map[string]string{fhNodeName: responderIP}
	}
	return rc
}

// TestForwardedHealth checks the health probe forwarded to a responder pod through the tunnel.
func TestForwardedHealth(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	slotIdent := link.NewSlotIdentity(fhLinkID, 0)
	rc := fhRuntimeConfig(fhResponderIP)

	ctr := netns.Start(ctx, t, "python3", "conntrack-tools")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", fhLocalTopologyScript(slotIdent.Interface)); code != 0 {
		t.Fatalf("set up local netns topology (exit %d):\n%s", code, out)
	}
	programLocalRoutes(ctx, t, ctr, slotIdent, nil)
	netns.Apply(ctx, t, ctr, renderRulesetOnNode(t, rc, nil, fhNodeName))
	applyInNetns(ctx, t, ctr, "vm", fhVMRuleset)
	startForwardedResponder(ctx, t, ctr, fhResponderPort)

	t.Run("local_forwarded_probe_external_source_returns_through_tunnel", func(t *testing.T) {
		if got := probeFrom(ctx, t, ctr, pfHTTPProbe, "client", "10.0.1.1", fhHealthPort); got != "HTTP/1.1 200 OK" {
			t.Fatalf("probe through the tunnel to the responder = %q, want %q", got, "HTTP/1.1 200 OK")
		}
		if got := conntrackDNATCount(ctx, t, ctr, fhHealthPort, fhResponderIP); got != 1 {
			t.Errorf("conntrack entries DNATing the health port to the responder = %d, want exactly 1", got)
		}
	})
}

// TestForwardedHealthNoResponderRendersNoHealthDNAT pins that a node absent from Responders
// renders a prerouting chain carrying exactly the forwards' DNAT lines.
func TestForwardedHealthNoResponderRendersNoHealthDNAT(t *testing.T) {
	rc := fhRuntimeConfig("")
	forward := link.ResolvedForward{Name: "tcp-8443", PublicPort: 8443, Protocol: "tcp", Target: "10.244.1.7", TargetPort: 9080}
	out, err := link.RenderNftables(rc, []link.ResolvedForward{forward}, fhNodeName)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	want := []string{
		"type nat hook prerouting priority dstnat; policy accept;",
		fmt.Sprintf(`iifname %q tcp dport 8443 counter dnat ip to 10.244.1.7 : 9080`, link.NewSlotIdentity(fhLinkID, 0).Interface),
	}
	if got := renderedChainLines(t, out, "prerouting"); !slices.Equal(got, want) {
		t.Errorf("prerouting chain with no responder entry = %v, want exactly the forwards' DNAT lines %v", got, want)
	}
}

// renderedChainLines returns chain's rendered lines, trimmed of indentation, in the exact order
// RenderNftables emitted them.
func renderedChainLines(t testing.TB, ruleset, chain string) []string {
	t.Helper()
	lines := []string{}
	inChain := false
	for line := range strings.SplitSeq(ruleset, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "chain "+chain+" {":
			inChain = true
		case inChain && trimmed == "}":
			return lines
		case inChain && trimmed != "":
			lines = append(lines, trimmed)
		}
	}
	t.Fatalf("ruleset carries no chain %q:\n%s", chain, ruleset)
	return nil
}

// TestMemberScopedFailures keeps member faults scoped to their own probes.
func TestMemberScopedFailures(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	t.Run("broken DNAT on one member fails only that probe", func(t *testing.T) {
		healthy := startDataPathContainer(ctx, t)
		broken := startDataPathContainer(ctx, t)

		rc := twoPeerClusterRC()
		goodForward := link.ResolvedForward{Name: "svc", PublicPort: dpRetargetPort, Protocol: "tcp", Target: dpClusterIPA, TargetPort: dpTargetPort}
		// The broken member's DNAT targets an address nothing backs: the member-local
		// equivalent of a misconfigured forward.
		badForward := link.ResolvedForward{Name: "svc", PublicPort: dpRetargetPort, Protocol: "tcp", Target: "10.96.0.99", TargetPort: dpTargetPort}

		netns.Apply(ctx, t, healthy, renderRuleset(t, rc, []link.ResolvedForward{goodForward}))
		netns.Apply(ctx, t, broken, renderRuleset(t, rc, []link.ResolvedForward{badForward}))

		if got := probeOnce(ctx, t, healthy); got != dpMarkerA {
			t.Errorf("healthy member's probe = %q, want %q", got, dpMarkerA)
		}
		err := probeErrorFrom(ctx, t, broken, tcpProbe, "client", dpGatewayAddr, dpRetargetPort)
		if !isHostUnreachable(err) {
			t.Errorf("broken member's probe = %q, want EHOSTUNREACH: its DNAT targets an address nothing backs", err)
		}
	})

	t.Run("broken_dnat_on_one_member_fails_only_that_probe (forwarded health)", func(t *testing.T) {
		healthy := netns.Start(ctx, t, "python3")
		broken := netns.Start(ctx, t, "python3")

		healthyIdent := link.NewSlotIdentity(fhLinkID, 0)
		healthyRC := fhRuntimeConfig(fhResponderIP)
		// The broken member's Responders entry names an address nothing on its node answers:
		// the health-DNAT equivalent of a misconfigured forward.
		brokenRC := fhRuntimeConfig("10.94.0.99")

		for _, ctr := range []testcontainers.Container{healthy, broken} {
			if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", fhLocalTopologyScript(healthyIdent.Interface)); code != 0 {
				t.Fatalf("set up local netns topology (exit %d):\n%s", code, out)
			}
			programLocalRoutes(ctx, t, ctr, healthyIdent, nil)
			applyInNetns(ctx, t, ctr, "vm", fhVMRuleset)
		}
		netns.Apply(ctx, t, healthy, renderRulesetOnNode(t, healthyRC, nil, fhNodeName))
		netns.Apply(ctx, t, broken, renderRulesetOnNode(t, brokenRC, nil, fhNodeName))
		startForwardedResponder(ctx, t, healthy, fhResponderPort)

		if got := probeFrom(ctx, t, healthy, pfHTTPProbe, "client", "10.0.1.1", fhHealthPort); got != "HTTP/1.1 200 OK" {
			t.Errorf("healthy member's forwarded probe = %q, want %q", got, "HTTP/1.1 200 OK")
		}
		err := probeErrorFrom(ctx, t, broken, tcpProbe, "client", "10.0.1.1", fhHealthPort)
		if !isTimeout(err) {
			t.Errorf("broken member's forwarded probe = %q, want a timeout: its DNAT targets an address nothing answers", err)
		}
	})

	t.Run("forwarding sysctl cleared fails only that member", func(t *testing.T) {
		gwIdent := link.NewGatewayIdentity(fhLinkID)
		slotIdent := link.NewSlotIdentity(fhLinkID, 0)
		rc := link.RuntimeConfig{
			TrafficPolicy: link.TrafficPolicyLocal,
			Identity:      &gwIdent,
			WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB="}}},
		}
		forwards := []link.ResolvedForward{{Name: "tcp-8443", PublicPort: lpPublicPort, Protocol: "tcp", Target: lpPodIP, TargetPort: lpPodPort}}

		healthy := startLocalForwardMember(ctx, t, slotIdent, rc, forwards, true)
		unhealthy := startLocalForwardMember(ctx, t, slotIdent, rc, forwards, false)

		if got := probeFrom(ctx, t, healthy, tcpProbe, "client", lpVMPublicAddr, lpPublicPort); !strings.Contains(got, lpMarker) {
			t.Errorf("member with ip_forward=1 forward probe = %q, want a reply carrying %q", got, lpMarker)
		}
		err := probeErrorFrom(ctx, t, unhealthy, tcpProbe, "client", lpVMPublicAddr, lpPublicPort)
		if !isTimeout(err) {
			t.Errorf("member with ip_forward=0 forward probe = %q, want a timeout: the kernel must refuse to forward between interfaces", err)
		}
	})
}

// fhClusterResponderScript adds a responder netns reachable over a veth pair, the same shape
// fhLocalTopologyScript wires for Local, so the Cluster health DNAT has a live target.
const fhClusterResponderScript = `set -e
ip netns add responder
ip link add fh-nd type veth peer name fh-rp
ip link set fh-rp netns responder
ip addr add 10.94.0.1/24 dev fh-nd
ip link set fh-nd up
ip netns exec responder ip addr add ` + fhResponderIP + `/24 dev fh-rp
ip netns exec responder ip link set fh-rp up
ip netns exec responder ip link set lo up
ip netns exec responder ip route add default via 10.94.0.1
`

// TestClusterForwardedProbeWithMasquerade checks the Cluster probe with masquerading, DNATed
// through the tunnel to a responder pod reached over its own veth, the same path a forward takes.
func TestClusterForwardedProbeWithMasquerade(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startDataPathContainer(ctx, t)
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", fhClusterResponderScript); code != 0 {
		t.Fatalf("set up responder netns (exit %d):\n%s", code, out)
	}
	startForwardedResponder(ctx, t, ctr, fhResponderPort)

	rc := twoPeerClusterRC()
	rc.HealthPort = fhHealthPort
	rc.ResponderTarget = fhResponderIP
	rc.ResponderPort = fhResponderPort
	forward := link.ResolvedForward{Name: "svc", PublicPort: dpRetargetPort, Protocol: "tcp", Target: dpClusterIPA, TargetPort: dpTargetPort}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, []link.ResolvedForward{forward}))

	if got := probeOnce(ctx, t, ctr); got != dpMarkerA {
		t.Errorf("forward probe through masquerading ruleset = %q, want %q", got, dpMarkerA)
	}

	if got := probeFrom(ctx, t, ctr, pfHTTPProbe, "client", dpGatewayAddr, fhHealthPort); got != "HTTP/1.1 200 OK" {
		t.Errorf("health probe through the responder DNAT = %q, want %q", got, "HTTP/1.1 200 OK")
	}
	if got := conntrackDNATCount(ctx, t, ctr, fhHealthPort, fhResponderIP); got != 1 {
		t.Errorf("conntrack entries DNATing the health port to the responder = %d, want exactly 1", got)
	}
}

// TestClusterForwardedProbeNoResponderTargetRendersNoHealthDNAT pins that a Cluster config with no
// ResponderTarget renders only the forwards' DNAT lines, plus the drop in the input chain.
func TestClusterForwardedProbeNoResponderTargetRendersNoHealthDNAT(t *testing.T) {
	rc := twoPeerClusterRC()
	rc.HealthPort = fhHealthPort
	forward := link.ResolvedForward{Name: "svc", PublicPort: dpRetargetPort, Protocol: "tcp", Target: dpClusterIPA, TargetPort: dpTargetPort}
	out, err := link.RenderNftables(rc, []link.ResolvedForward{forward}, "")
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	wantPrerouting := []string{
		"type nat hook prerouting priority dstnat; policy accept;",
		fmt.Sprintf(`iif "wg0" tcp dport %d dnat ip to %s : %d`, dpRetargetPort, dpClusterIPA, dpTargetPort),
	}
	if got := renderedChainLines(t, out, "prerouting"); !slices.Equal(got, wantPrerouting) {
		t.Errorf("prerouting chain with no responder target = %v, want %v", got, wantPrerouting)
	}
	wantInput := []string{
		"type filter hook input priority filter; policy accept;",
		`iif "wg0" drop`,
	}
	if got := renderedChainLines(t, out, "input"); !slices.Equal(got, wantInput) {
		t.Errorf("input chain with no responder target = %v, want %v", got, wantInput)
	}
}

// isHostUnreachable reports whether a probe failed with EHOSTUNREACH, the outcome a DNAT to an
// address no host answers for produces once the node's ARP for it goes unanswered.
func isHostUnreachable(err string) bool {
	return strings.Contains(err, "OSError(113")
}

// startLocalForwardMember starts a Local forwarding member for health tests.
func startLocalForwardMember(ctx context.Context, t testing.TB, id link.SlotIdentity, rc link.RuntimeConfig, forwards []link.ResolvedForward, forwardingEnabled bool) testcontainers.Container {
	t.Helper()
	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", localTopologyScript(id.Interface)); code != 0 {
		t.Fatalf("set up local netns topology (exit %d):\n%s", code, out)
	}
	startPeerBackend(ctx, t, ctr)
	programLocalRoutes(ctx, t, ctr, id, []string{lpPodIP})
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, forwards))
	applyInNetns(ctx, t, ctr, "vm", vmRuleset)

	forwardingValue := "1"
	if !forwardingEnabled {
		forwardingValue = "0"
	}
	if code, out := netns.Exec(ctx, t, ctr, "sysctl", "-w", "net.ipv4.ip_forward="+forwardingValue); code != 0 {
		t.Fatalf("set net.ipv4.ip_forward=%s failed (exit %d):\n%s", forwardingValue, code, out)
	}
	if code, out := netns.Exec(ctx, t, ctr, "sysctl", "-w", "net.ipv4.conf."+id.Interface+".forwarding="+forwardingValue); code != 0 {
		t.Fatalf("set net.ipv4.conf.%s.forwarding=%s failed (exit %d):\n%s", id.Interface, forwardingValue, code, out)
	}
	return ctr
}

type linkStatistics struct {
	Stats64 struct {
		RX struct {
			Packets uint64 `json:"packets"`
		} `json:"rx"`
		TX struct {
			Packets uint64 `json:"packets"`
		} `json:"tx"`
	} `json:"stats64"`
}

// interfacePacketCount reads iface's cumulative rx or tx packet count, from ns when non-empty
// or the container's own netns otherwise.
func interfacePacketCount(ctx context.Context, t testing.TB, ctr testcontainers.Container, ns, iface, direction string) uint64 {
	t.Helper()
	args := []string{"ip", "-j", "-s", "link", "show", "dev", iface}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	code, out := netns.Exec(ctx, t, ctr, args...)
	if code != 0 {
		t.Fatalf("ip link statistics for %s failed (exit %d):\n%s", iface, code, out)
	}
	var stats []linkStatistics
	if err := json.Unmarshal([]byte(out), &stats); err != nil || len(stats) != 1 {
		t.Fatalf("decode link statistics for %s: %v\n%s", iface, err, out)
	}
	if direction == "rx" {
		return stats[0].Stats64.RX.Packets
	}
	return stats[0].Stats64.TX.Packets
}

// conntrackDNATCount counts conntrack entries whose original destination port is healthPort and
// whose reply source is responderIP, the signature a health probe's DNAT to it leaves.
func conntrackDNATCount(ctx context.Context, t testing.TB, ctr testcontainers.Container, healthPort int, responderIP string) int {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "conntrack", "-L", "-p", "tcp", "--dport", strconv.Itoa(healthPort))
	if code != 0 && code != 1 {
		t.Fatalf("conntrack -L failed (exit %d):\n%s", code, out)
	}
	count := 0
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "dport="+strconv.Itoa(healthPort)) && strings.Contains(line, "src="+responderIP) {
			count++
		}
	}
	return count
}
