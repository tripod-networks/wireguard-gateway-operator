package linkint

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/netns"
)

// A three-netns topology forwards traffic through wg0 to a separate cluster netns
// so the accept rules are exercised, not bypassed by local delivery.

const (
	// dpRetargetPort is the public port the forward exposes on wg0.
	dpRetargetPort = 8453
	// dpGatewayAddr is the gateway's tunnel-side address, the address the client dials.
	dpGatewayAddr = "10.99.0.2"
	// dpTargetPort is the backend port both stand-in Services listen on.
	dpTargetPort = 443
	// dpClusterIPA and dpClusterIPB are the stand-in ClusterIPs the forward is
	// retargeted between; both are reachable in the cluster netns.
	dpClusterIPA = "10.96.0.10"
	dpClusterIPB = "10.96.0.20"
	// dpMarkerA and dpMarkerB are the per-backend response markers, so a probe's
	// reply identifies which backend served it.
	dpMarkerA = "AAAA"
	dpMarkerB = "BBBB"
	// dpProbeTimeout bounds a single in-container probe attempt.
	dpProbeTimeout = 5 * time.Second
)

// TestNftablesRetargetDataPathFollowsClusterIP asserts a fresh flow reaches the new target and
// that the production conntrack flush breaks an established flow pinned to the old one.
func TestNftablesRetargetDataPathFollowsClusterIP(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startDataPathContainer(ctx, t)

	forwardA := link.ResolvedForward{Name: "retarget", PublicPort: dpRetargetPort, Protocol: "tcp", Target: dpClusterIPA, TargetPort: dpTargetPort}
	forwardB := link.ResolvedForward{Name: "retarget", PublicPort: dpRetargetPort, Protocol: "tcp", Target: dpClusterIPB, TargetPort: dpTargetPort}

	netns.Apply(ctx, t, ctr, renderRuleset(t, twoPeerClusterRC(), []link.ResolvedForward{forwardA}))

	if got := probeOnce(ctx, t, ctr); got != dpMarkerA {
		t.Fatalf("before retarget: fresh probe = %q, want %q (DNAT to A not working)", got, dpMarkerA)
	}

	held := openHeldConnection(ctx, t, ctr)
	defer held.close(t)
	if got, err := held.request(ctx, t); err != nil || strings.TrimSpace(got) != dpMarkerA {
		t.Fatalf("before retarget: held connection bytes = %q, err = %v, want %q", []byte(got), err, dpMarkerA)
	}

	netns.Apply(ctx, t, ctr, renderRuleset(t, twoPeerClusterRC(), []link.ResolvedForward{forwardB}))
	assertClusterForwardRules(ctx, t, ctr, []link.ResolvedForward{forwardB}, "after retarget")

	// The production flush runs in the same netns the ruleset was loaded into (the container's root
	// netns, per setupTopology): the same argv link's applyConfig would run after the nft -f - step.
	if code, out := netns.Exec(ctx, t, ctr, append([]string{"conntrack"}, link.ConntrackFlushArgs(forwardA)...)...); code != 0 && !strings.Contains(out, "0 flow entries have been deleted") {
		t.Fatalf("flush forward A's conntrack entries (exit %d):\n%s", code, out)
	}

	_, requestErr := held.request(ctx, t)
	if requestErr == nil {
		t.Fatal("after retarget: held connection's next request succeeded, want the deleted conntrack entry to break the flow (reset or timeout)")
	}
	t.Logf("observed held-connection error after retarget: %v", requestErr)
	if !strings.Contains(requestErr.Error(), "held connection read:") {
		t.Fatalf("held connection error = %v, want one reporting the script's own read failure, not a missing reply file", requestErr)
	}

	if got := probeOnce(ctx, t, ctr); got != dpMarkerB {
		t.Errorf("after retarget: fresh probe = %q, want %q (a new connection must re-evaluate DNAT to B)", got, dpMarkerB)
	}
}

// startDataPathContainer gives wg0 a veth peer: the dummy wg0 the other tests use cannot
// carry forwarded traffic. python3 runs the stand-in backends and the probes.
func startDataPathContainer(ctx context.Context, t testing.TB) testcontainers.Container {
	t.Helper()

	ctr := netns.Start(ctx, t, "python3", "conntrack-tools")
	setupTopology(ctx, t, ctr)
	startBackends(ctx, t, ctr)
	return ctr
}

// topologyScript puts the stand-in ClusterIPs behind a second veth in the cluster netns,
// so DNAT'd packets are forwarded through the accept rules rather than delivered locally.
const topologyScript = `set -e
ip netns add client
ip link add vc-gw type veth peer name wg0
ip link set vc-gw netns client
ip addr add 10.99.0.2/24 dev wg0
ip link set wg0 up
ip netns exec client ip addr add 10.99.0.1/24 dev vc-gw
ip netns exec client ip link set vc-gw up
ip netns exec client ip link set lo up
ip netns exec client ip route add default via 10.99.0.2

ip netns add cluster
ip link add vs-gw type veth peer name vs-cl
ip link set vs-cl netns cluster
ip addr add 10.96.0.1/24 dev vs-gw
ip link set vs-gw up
ip netns exec cluster ip link set vs-cl up
ip netns exec cluster ip link set lo up
ip netns exec cluster ip addr add 10.96.0.2/24 dev vs-cl
ip netns exec cluster ip addr add 10.96.0.10/32 dev vs-cl
ip netns exec cluster ip addr add 10.96.0.20/32 dev vs-cl
ip netns exec cluster ip route add default via 10.96.0.1

ip route add 10.96.0.10/32 dev vs-gw
ip route add 10.96.0.20/32 dev vs-gw
sysctl -w net.ipv4.ip_forward=1
`

func setupTopology(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "sh", "-c", topologyScript)
	if code != 0 {
		t.Fatalf("set up netns topology (exit %d):\n%s", code, out)
	}
}

// backendScript keeps the connection open after replying with its marker, so one
// connection can carry several requests: the reuse the held-flow assertion depends on.
const backendScript = `import socket, sys
ip = sys.argv[1]
marker = sys.argv[2]
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((ip, 443))
srv.listen(16)
while True:
    conn, _ = srv.accept()
    while True:
        data = conn.recv(64)
        if not data:
            break
        conn.sendall((marker + "\n").encode())
    conn.close()
`

// startBackends launches the two marker servers in the cluster netns and waits
// for both to listen, so the first probe does not race bind.
func startBackends(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(backendScript), "/tmp/backend.py", 0o644); err != nil {
		t.Fatalf("copy backend script: %v", err)
	}
	for _, b := range []struct{ ip, marker string }{{dpClusterIPA, dpMarkerA}, {dpClusterIPB, dpMarkerB}} {
		cmd := fmt.Sprintf("ip netns exec cluster python3 /tmp/backend.py %s %s &", b.ip, b.marker)
		if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", cmd); code != 0 {
			t.Fatalf("start backend %s (exit %d):\n%s", b.ip, code, out)
		}
	}
	waitClusterListening(ctx, t, ctr)
}

func waitClusterListening(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	want := fmt.Sprintf(":%d", dpTargetPort)
	for time.Now().Before(deadline) {
		code, out := netns.Exec(ctx, t, ctr, "ip", "netns", "exec", "cluster", "ss", "-ltn")
		if code == 0 && strings.Count(out, want) >= 2 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("cluster backends did not start listening on port %d within deadline", dpTargetPort)
}

// probeScript dials a fresh connection per probe, which forces a prerouting DNAT
// re-evaluation, and prints the reply prefixed GOT: (or ERR: on failure).
const probeScript = `import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(float(sys.argv[3]))
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.sendall(b"r\n")
    print("GOT:" + s.recv(64).decode(errors="replace").strip())
except Exception as e:
    print("ERR:" + repr(e))
finally:
    s.close()
`

// probeOnce dials a fresh connection through the gateway and returns the backend
// marker, or "" if the probe failed (a blackhole or refusal).
func probeOnce(ctx context.Context, t testing.TB, ctr testcontainers.Container) string {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(probeScript), "/tmp/probe.py", 0o644); err != nil {
		t.Fatalf("copy probe script: %v", err)
	}
	secs := fmt.Sprintf("%.0f", dpProbeTimeout.Seconds())
	cmd := fmt.Sprintf("ip netns exec client python3 /tmp/probe.py %s %d %s", dpGatewayAddr, dpRetargetPort, secs)
	code, out := netns.Exec(ctx, t, ctr, "sh", "-c", cmd)
	if code != 0 {
		t.Fatalf("probe exec failed (exit %d):\n%s", code, out)
	}
	return parseMarker(out)
}

// heldConnection is a client connection kept open across a retarget, so the test can
// observe whether conntrack pins the established flow to the old target.
type heldConnection struct {
	ctr testcontainers.Container
	gen int
}

// heldScript keeps one socket open between requests, which is what makes the flow
// ESTABLISHED across the retarget; each reply lands in /tmp/held_reply.<gen>.
const heldScript = `import socket, os, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("10.99.0.2", 8453))
last = 0
while True:
    try:
        with open("/tmp/held_gen") as f:
            gen = int(f.read().strip() or "0")
    except (FileNotFoundError, ValueError):
        gen = 0
    if gen <= last:
        time.sleep(0.05)
        continue
    last = gen
    try:
        s.sendall(b"r\n")
        reply = s.recv(64).decode(errors="replace").strip()
    except Exception as e:
        reply = "ERR:" + repr(e)
    tmp = "/tmp/held_reply.%d.tmp" % gen
    with open(tmp, "w") as f:
        f.write(reply + "\n")
    os.rename(tmp, "/tmp/held_reply.%d" % gen)
`

func openHeldConnection(ctx context.Context, t testing.TB, ctr testcontainers.Container) *heldConnection {
	t.Helper()
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", "echo 0 > /tmp/held_gen"); code != 0 {
		t.Fatalf("init generation file (exit %d):\n%s", code, out)
	}
	if err := ctr.CopyToContainer(ctx, []byte(heldScript), "/tmp/held.py", 0o644); err != nil {
		t.Fatalf("copy held script: %v", err)
	}
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", "ip netns exec client python3 /tmp/held.py &"); code != 0 {
		t.Fatalf("start held connection (exit %d):\n%s", code, out)
	}
	h := &heldConnection{ctr: ctr}
	h.waitConnected(ctx, t)
	return h
}

// waitConnected polls the client netns until the held connection appears as an
// established socket to the public port, so request does not race the connect.
func (h *heldConnection) waitConnected(ctx context.Context, t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	want := fmt.Sprintf(":%d", dpRetargetPort)
	for time.Now().Before(deadline) {
		code, out := netns.Exec(ctx, t, h.ctr, "ip", "netns", "exec", "client", "ss", "-tn", "state", "established")
		if code == 0 && strings.Contains(out, want) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("held connection did not establish to port %d within deadline", dpRetargetPort)
}

func (h *heldConnection) request(ctx context.Context, t testing.TB) (string, error) {
	t.Helper()
	h.gen++
	if code, out := netns.Exec(ctx, t, h.ctr, "sh", "-c", fmt.Sprintf("echo %d > /tmp/held_gen", h.gen)); code != 0 {
		t.Fatalf("bump generation (exit %d):\n%s", code, out)
	}
	replyPath := fmt.Sprintf("/tmp/held_reply.%d", h.gen)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		code, out := netns.Exec(ctx, t, h.ctr, "sh", "-c", fmt.Sprintf("cat %s 2>/dev/null", replyPath))
		if code == 0 {
			reply := strings.TrimSpace(out)
			if strings.HasPrefix(reply, "ERR:") {
				return out, fmt.Errorf("held connection read: %s", reply)
			}
			return out, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return "", fmt.Errorf("read held connection reply: deadline exceeded")
}

// close runs on context.Background() because the test's own context may already be
// cancelled by cleanup time; Exec applies its own deadline.
func (h *heldConnection) close(t testing.TB) {
	t.Helper()
	_, _ = netns.Exec(context.Background(), t, h.ctr, "sh", "-c", "pkill -f held.py || true")
}

// parseMarker extracts the marker from a probe's GOT:/ERR: output, returning ""
// for an ERR line so callers treat a failed probe as a blackhole.
func parseMarker(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if m, ok := strings.CutPrefix(line, "GOT:"); ok {
			return m
		}
	}
	return ""
}
