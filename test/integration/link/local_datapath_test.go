package linkint

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/netns"
)

const (
	// lpLinkID is the link id every derived Local name in this test comes from.
	lpLinkID = 3
	// lpPublicPort is the port the client dials on the VM's public address.
	lpPublicPort = 8443
	// lpUDPPublicPort is the UDP forward's public port, dialled on the tunnel address.
	lpUDPPublicPort = 8445
	// lpPodIP and lpPodPort are the programmed backend: the only address and port
	// tunnel traffic may reach.
	lpPodIP   = "10.244.1.7"
	lpPodPort = 9080
	// lpUDPPodPort is the backend's UDP port, the only UDP port behind the tunnel with
	// a DNAT and an accept rule.
	lpUDPPodPort = 9081
	// lpUnprogrammedIP has no listener and no rule: a packet reaching it would be
	// refused, so a timeout there proves the forward-chain drop, not a missing route.
	lpUnprogrammedIP = "10.244.1.8"
	// lpBlackholePort is a forwarded port with no programmed DNAT; its packets keep
	// the tunnel destination and must be dropped by the input chain.
	lpBlackholePort = 8444
	// lpClientAddr is the client netns address the backend must observe as its peer.
	lpClientAddr = "10.0.1.2"
	// lpVMPublicAddr is the VM's public-side address, the address the client dials and
	// so the address a completing reply must be sourced from.
	lpVMPublicAddr = "10.0.1.1"
	// lpVMTunnelAddr is the VM's tunnel-side address and so the source of a datagram
	// sent from the vm netns; the backend must observe it unchanged.
	lpVMTunnelAddr = "10.99.0.1"
	// lpTunnelAddr is the node's tunnel-side address, the destination a forward's
	// public port is reached on from the vm netns.
	lpTunnelAddr = "10.99.0.2"
	// lpMarker is the backend's reply marker.
	lpMarker = "LOCAL"
	// lpEgressPort is the tunnel-side port an unsolicited backend connection aims at.
	// Nothing listens on it anywhere, so a refusal would mean the packet left the node.
	lpEgressPort = 8446
	// lpProbeTimeout bounds a single in-container probe attempt.
	lpProbeTimeout = 5 * time.Second
	// lpNodeBackendSideAddr is the node's address on the backend's link, the masquerade
	// source of a backend reaching itself.
	lpNodeBackendSideAddr = "10.244.1.1"
	// lpDecoyAddr is the decoy device's address, and so the node's source for any address
	// routed by the main-table default.
	lpDecoyAddr = "192.0.2.1"
	// lpHairpinPublicAddr is the gateway's public address in the hairpin test. No netns owns it.
	lpHairpinPublicAddr = "198.51.100.10"
	// lpHairpinPodAddr is the address of a client pod on the holder.
	lpHairpinPodAddr = "10.244.2.2"
)

// localTopologyScript builds client / vm / node / backend. The node's main-table
// default route is a decoy, so only the connmark rule and its table return the reply.
func localTopologyScript(iface string) string {
	return fmt.Sprintf(`set -e
ip netns add client
ip netns add vm
ip netns add backend

# client <-> vm
ip link add vc-cl type veth peer name vc-vm
ip link set vc-cl netns client
ip link set vc-vm netns vm
ip netns exec client ip addr add %[2]s/24 dev vc-cl
ip netns exec client ip link set vc-cl up
ip netns exec client ip link set lo up
ip netns exec client ip route add default via %[3]s
ip netns exec vm ip addr add %[3]s/24 dev vc-vm
ip netns exec vm ip link set vc-vm up
ip netns exec vm ip link set lo up

# vm <-> node (the tunnel stand-in; the node end carries the derived interface name)
ip link add vt-vm type veth peer name %[1]s
ip link set vt-vm netns vm
ip netns exec vm ip addr add %[4]s/24 dev vt-vm
ip netns exec vm ip link set vt-vm up
ip netns exec vm ip route add 10.244.1.0/24 via %[5]s
ip netns exec vm sysctl -w net.ipv4.ip_forward=1
ip netns exec vm sysctl -w net.ipv4.conf.all.rp_filter=0
# The product's route out of the per-Gateway table is a device route, which on this
# veth stand-in leaves the reply with no link-layer next hop unless the vm end answers
# for the addresses behind it.
ip netns exec vm sysctl -w net.ipv4.conf.vt-vm.proxy_arp=1
ip addr add %[5]s/24 dev %[1]s
ip link set %[1]s up

# node <-> backend
ip link add vb-nd type veth peer name vb-be
ip link set vb-be netns backend
ip addr add %[6]s/24 dev vb-nd
ip link set vb-nd up
ip netns exec backend ip link set vb-be up
ip netns exec backend ip link set lo up
ip netns exec backend ip addr add 10.244.1.2/24 dev vb-be
ip netns exec backend ip addr add %[7]s/32 dev vb-be
ip netns exec backend ip addr add %[8]s/32 dev vb-be
ip netns exec backend ip route add default via %[6]s

# node: forwarding on, conf.all rp_filter off, decoy main-table default. The route
# table and rule that carry the reply are the product's own plan, run separately. The
# pod-facing veth is strict and src_valid_mark is on, matching a kind node behind a
# tailscale host: the reply's reverse-path lookup carries the packet mark and so
# follows the ip rule into the Gateway table.
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.%[1]s.rp_filter=0
sysctl -w net.ipv4.conf.all.src_valid_mark=1
sysctl -w net.ipv4.conf.vb-nd.rp_filter=1
ip link add decoy0 type dummy
ip addr add %[9]s/24 dev decoy0
ip link set decoy0 up
ip route replace default dev decoy0
`, iface, lpClientAddr, lpVMPublicAddr, lpVMTunnelAddr, lpTunnelAddr,
		lpNodeBackendSideAddr, lpPodIP, lpUnprogrammedIP, lpDecoyAddr)
}

// vmRuleset is the VM half: a catch-all DNAT to the link tunnel address and no
// masquerade at all, which is what traffic-policy=local renders on a real gateway.
const vmRuleset = `add table inet gateway
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

// peerBackendScript replies with the caller's observed peer address and lpMarker, so
// the test can assert the source address survived every DNAT hop on either protocol.
const peerBackendScript = `import socket, selectors
sel = selectors.DefaultSelector()
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("10.244.1.7", 9080))
tcp.listen(16)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("10.244.1.7", 9081))
sel.register(tcp, selectors.EVENT_READ, "tcp")
sel.register(udp, selectors.EVENT_READ, "udp")
while True:
    for key, _ in sel.select():
        if key.data == "tcp":
            conn, addr = tcp.accept()
            conn.sendall((addr[0] + " LOCAL\n").encode())
            conn.close()
        else:
            _, addr = udp.recvfrom(64)
            udp.sendto((addr[0] + " LOCAL\n").encode(), addr)
`

// TestLocalDataPathPreservesClientSource proves the Local data path in a real kernel:
// the source address survives, and unprogrammed ports and addresses are dropped.
func TestLocalDataPathPreservesClientSource(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(lpLinkID)
	ident := link.NewSlotIdentity(lpLinkID, 0)

	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", localTopologyScript(ident.Interface)); code != 0 {
		t.Fatalf("set up local netns topology (exit %d):\n%s", code, out)
	}
	startPeerBackend(ctx, t, ctr)

	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		PublicAddress: lpVMPublicAddr,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB="}}},
	}
	forwards := []link.ResolvedForward{
		{Name: "tcp-8443", PublicPort: lpPublicPort, Protocol: "tcp", Target: lpPodIP, TargetPort: lpPodPort},
		{Name: "udp-8445", PublicPort: lpUDPPublicPort, Protocol: "udp", Target: lpPodIP, TargetPort: lpUDPPodPort},
	}
	programLocalRoutes(ctx, t, ctr, ident, []string{lpPodIP})

	t.Run("route plan is idempotent", func(t *testing.T) {
		// Every endpoint change re-applies the plan, so the kernel's rejection of the
		// identical fwmark rule must be tolerated.
		programLocalRoutes(ctx, t, ctr, ident, []string{lpPodIP})

		// The exit code alone would pass on a duplicate rule, which teardown would
		// then half-delete.
		if n := countPlanRules(ctx, t, ctr, ident); n != 1 {
			t.Fatalf("%d ip rules match the plan's fwmark %s and table %d, want exactly 1", n, ident.Mark, ident.RouteTable)
		}
	})

	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, forwards))
	applyInNetns(ctx, t, ctr, "vm", vmRuleset)

	t.Run("backend observes the client address", func(t *testing.T) {
		got := probeFrom(ctx, t, ctr, tcpProbe, "client", lpVMPublicAddr, lpPublicPort)
		peer, marker, ok := strings.Cut(got, " ")
		if !ok || marker != lpMarker {
			t.Fatalf("probe through the gateway = %q, want %q with a peer address prefix", got, lpMarker)
		}
		if peer != lpClientAddr {
			t.Errorf("backend observed peer %q, want the client's own address %q; a masquerade or a pod-netns tunnel would show something else", peer, lpClientAddr)
		}
	})

	t.Run("backend observes the tunnel source over udp", func(t *testing.T) {
		got := probeFrom(ctx, t, ctr, udpProbe, "vm", lpTunnelAddr, lpUDPPublicPort)
		peer, marker, ok := strings.Cut(got, " ")
		if !ok || marker != lpMarker {
			t.Fatalf("udp probe through the gateway = %q, want %q with a peer address prefix; the reply must return to the sender for the datagram to be read at all", got, lpMarker)
		}
		if peer != lpVMTunnelAddr {
			t.Errorf("backend observed udp peer %q, want the sender's own address %q; Local must not masquerade udp either", peer, lpVMTunnelAddr)
		}
	})

	t.Run("reverse dnat restores the reply source", func(t *testing.T) {
		// The exchange completing is the assertion: a reply sourced from the pod address
		// would be dropped by the client's stack before any payload was read.
		got := probeFrom(ctx, t, ctr, tcpProbe, "client", lpVMPublicAddr, lpPublicPort)
		if !strings.Contains(got, lpMarker) {
			t.Errorf("probe from the client = %q, want a reply carrying %q; the reverse DNAT must chain across both hops", got, lpMarker)
		}
	})

	t.Run("return path uses the connmark route table", func(t *testing.T) {
		code, out := netns.Exec(ctx, t, ctr, "ip", "route", "show", "default")
		if code != 0 || !strings.Contains(out, "decoy0") {
			t.Fatalf("node main-table default route = %q (exit %d), want the decoy device; the test cannot prove the connmark route otherwise", out, code)
		}
		got := probeFrom(ctx, t, ctr, tcpProbe, "client", lpVMPublicAddr, lpPublicPort)
		if !strings.Contains(got, lpMarker) {
			t.Errorf("probe with a decoy main-table default = %q, want a reply carrying %q; the connmark rule and table 100003, not a fallback route, must return the traffic", got, lpMarker)
		}
	})

	drops := []struct {
		name string
		kind probeKind
		ns   string
		addr string
		port int
		why  string
	}{
		{
			name: "unprogrammed forwarded port is blackholed",
			kind: tcpProbe, ns: "client", addr: lpVMPublicAddr, port: lpBlackholePort,
			why: "the input chain must drop, not reset",
		},
		{
			name: "tunnel traffic to an unprogrammed address is dropped",
			kind: tcpProbe, ns: "vm", addr: lpUnprogrammedIP, port: lpPodPort,
			why: "the forward chain's tunnel-scoped drop must contain it",
		},
		{
			name: "udp to an unprogrammed address is dropped",
			kind: udpProbe, ns: "vm", addr: lpUnprogrammedIP, port: lpUDPPodPort,
			why: "the udp forward-accept rule is scoped to the programmed target, so the trailing drop must take it",
		},
	}
	for _, tc := range drops {
		t.Run(tc.name, func(t *testing.T) {
			err := probeErrorFrom(ctx, t, ctr, tc.kind, tc.ns, tc.addr, tc.port)
			if !isTimeout(err) {
				t.Errorf("%s probe from %s to %s:%d failed with %q, want a timeout; %s", tc.kind.name, tc.ns, tc.addr, tc.port, err, tc.why)
			}
		})
	}

	t.Run("unsolicited connection from the backend towards the tunnel is dropped", func(t *testing.T) {
		before := egressDropPackets(ctx, t, ctr, gwIdent.NftTable, ident.Interface)

		err := probeErrorFrom(ctx, t, ctr, tcpProbe, "backend", lpVMTunnelAddr, lpEgressPort)
		if !isTimeout(err) {
			t.Fatalf("tcp probe from the backend to %s:%d failed with %q, want a timeout; a refusal means the packet left the node instead of hitting the egress drop", lpVMTunnelAddr, lpEgressPort, err)
		}

		after := egressDropPackets(ctx, t, ctr, gwIdent.NftTable, ident.Interface)
		if after <= before {
			t.Errorf("the forward chain's oifname %q drop counted %d packets before the probe and %d after, want an increase; the connection must die on that rule, not elsewhere", ident.Interface, before, after)
		}
	})
}

// hairpinTopologyScript adds a pod netns on the node, as a client pod on the holder, and gives
// the backend a route to the public address sourced from its pod address, as a real pod has.
var hairpinTopologyScript = fmt.Sprintf(`set -e
ip netns add pod
ip link add vp-nd type veth peer name vp-pd
ip link set vp-pd netns pod
ip addr add 10.244.2.1/24 dev vp-nd
ip link set vp-nd up
ip netns exec pod ip addr add %[1]s/24 dev vp-pd
ip netns exec pod ip link set vp-pd up
ip netns exec pod ip link set lo up
ip netns exec pod ip route add default via 10.244.2.1
ip netns exec backend ip route add %[2]s/32 via %[3]s src %[4]s
`, lpHairpinPodAddr, lpHairpinPublicAddr, lpNodeBackendSideAddr, lpPodIP)

// TestLocalDataPathHairpin proves a client on the holder reaches the forward's backend on the
// gateway's public address without the tunnel: from a pod, from the node, and from the backend.
func TestLocalDataPathHairpin(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(lpLinkID)
	ident := link.NewSlotIdentity(lpLinkID, 0)

	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", localTopologyScript(ident.Interface)); code != 0 {
		t.Fatalf("set up local netns topology (exit %d):\n%s", code, out)
	}
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", hairpinTopologyScript); code != 0 {
		t.Fatalf("set up hairpin clients (exit %d):\n%s", code, out)
	}
	startPeerBackend(ctx, t, ctr)

	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		PublicAddress: lpHairpinPublicAddr,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB="}}},
	}
	forwards := []link.ResolvedForward{{Name: "tcp-8443", PublicPort: lpPublicPort, Protocol: "tcp", Target: lpPodIP, TargetPort: lpPodPort}}
	programLocalRoutes(ctx, t, ctr, ident, []string{lpPodIP})
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, forwards))

	tcs := []struct {
		name     string
		ns       string
		wantPeer string
	}{
		{
			name:     "a pod on the holder reaches the backend with its own address",
			ns:       "pod",
			wantPeer: lpHairpinPodAddr,
		},
		{
			name:     "the holder node reaches the backend with its own source address",
			ns:       "",
			wantPeer: lpDecoyAddr,
		},
		{
			name:     "the backend reaches itself masqueraded to the node's pod-side address",
			ns:       "backend",
			wantPeer: lpNodeBackendSideAddr,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := probeFrom(ctx, t, ctr, tcpProbe, tc.ns, lpHairpinPublicAddr, lpPublicPort)
			peer, marker, ok := strings.Cut(got, " ")
			if !ok || marker != lpMarker {
				t.Fatalf("probe to %s:%d = %q, want %q with a peer address prefix", lpHairpinPublicAddr, lpPublicPort, got, lpMarker)
			}
			if peer != tc.wantPeer {
				t.Errorf("backend observed peer %q, want %q", peer, tc.wantPeer)
			}
		})
	}
}

// TestLocalDatapathTwoSlots proves each slot's mark and route table returns its own flow while
// the main-table default route is a separate decoy.
func TestLocalDatapathTwoSlots(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(lpLinkID)
	slot0 := link.NewSlotIdentity(lpLinkID, 0)
	slot1 := link.NewSlotIdentity(lpLinkID, 1)
	ctr := netns.Start(ctx, t, "python3")
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", localTopologyScript(slot0.Interface)); code != 0 {
		t.Fatalf("set up slot 0 topology (exit %d):\n%s", code, out)
	}
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", secondSlotTopologyScript(slot1.Interface)); code != 0 {
		t.Fatalf("set up slot 1 topology (exit %d):\n%s", code, out)
	}
	startPeerBackend(ctx, t, ctr)

	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		HealthPort:    gwIdent.HealthPort,
		WireGuard: link.WireGuard{Peers: []link.Peer{
			{Slot: 0, PublicKey: "PUB0="},
			{Slot: 1, PublicKey: "PUB1="},
		}},
	}
	forwards := []link.ResolvedForward{{Name: "tcp-8443", PublicPort: lpPublicPort, Protocol: "tcp", Target: lpPodIP, TargetPort: lpPodPort}}
	programLocalRoutes(ctx, t, ctr, slot0, []string{lpPodIP})
	programLocalRoutes(ctx, t, ctr, slot1, []string{lpPodIP})
	ruleset := renderRuleset(t, rc, forwards)
	netns.Apply(ctx, t, ctr, ruleset)

	for _, id := range []link.SlotIdentity{slot0, slot1} {
		for _, fragment := range []string{
			`iifname "` + id.Interface + `" ct state new counter ct mark set ct mark`,
			`iifname "` + id.Interface + `" tcp dport 8443 counter dnat`,
			`oifname "` + id.Interface + `" tcp flags syn counter`,
			`ct direction reply ct mark and ` + id.MarkMask + ` == ` + id.Mark,
		} {
			if !strings.Contains(ruleset, fragment) {
				t.Errorf("ruleset missing slot %s fragment %q", id.Interface, fragment)
			}
		}
		if n := countPlanRules(ctx, t, ctr, id); n != 1 {
			t.Errorf("slot %s has %d matching ip rules, want exactly 1", id.Interface, n)
		}
		code, out := netns.Exec(ctx, t, ctr, "ip", "route", "show", "table", strconv.Itoa(id.RouteTable))
		if code != 0 || !strings.Contains(out, "default dev "+id.Interface) {
			t.Errorf("slot %s route table %d = %q (exit %d), want its default through that slot", id.Interface, id.RouteTable, out, code)
		}
	}

	probes := []struct {
		name  string
		id    link.SlotIdentity
		ns    string
		addr  string
		iface string
	}{
		{name: "slot 0 probe is answered through its own reply path", id: slot0, ns: "vm", addr: lpTunnelAddr, iface: "vt-vm"},
		{name: "slot 1 probe is answered through its own reply path", id: slot1, ns: "vm2", addr: "10.98.0.2", iface: "vt2-vm"},
	}
	for _, tc := range probes {
		t.Run(tc.name, func(t *testing.T) {
			before := interfacePacketCount(ctx, t, ctr, "", tc.id.Interface, "tx")
			proberBefore := interfacePacketCount(ctx, t, ctr, tc.ns, tc.iface, "rx")
			if got := probeFrom(ctx, t, ctr, tcpProbe, tc.ns, tc.addr, lpPublicPort); !strings.Contains(got, lpMarker) {
				t.Fatalf("probe through %s = %q, want reply carrying %q", tc.id.Interface, got, lpMarker)
			}
			slotReplies := interfacePacketCount(ctx, t, ctr, "", tc.id.Interface, "tx") - before
			proberReplies := interfacePacketCount(ctx, t, ctr, tc.ns, tc.iface, "rx") - proberBefore
			if slotReplies == 0 || proberReplies == 0 {
				t.Errorf("slot %s reply path has %d slot packets and %d prober packets, want packets on both ends", tc.id.Interface, slotReplies, proberReplies)
			}
		})
	}
}

func secondSlotTopologyScript(iface string) string {
	return fmt.Sprintf(`set -e
ip netns add vm2
ip link add vt2-vm type veth peer name %[1]s
ip link set vt2-vm netns vm2
ip netns exec vm2 ip addr add 10.98.0.1/24 dev vt2-vm
ip netns exec vm2 ip link set vt2-vm up
ip netns exec vm2 ip link set lo up
ip netns exec vm2 sysctl -w net.ipv4.conf.vt2-vm.proxy_arp=1
ip addr add 10.98.0.2/24 dev %[1]s
ip link set %[1]s up
sysctl -w net.ipv4.conf.%[1]s.rp_filter=0
`, iface)
}

// nftRuleDump is the subset of `nft -j list chain` a rule is identified by: its ordered
// expressions, each a single-keyed object.
type nftRuleDump struct {
	Nftables []struct {
		Rule *struct {
			Expr []map[string]json.RawMessage `json:"expr"`
		} `json:"rule"`
	} `json:"nftables"`
}

// nftMetaMatch is the subset of a match expression that names an interface, e.g.
// `oifname "wg-gw3"`.
type nftMetaMatch struct {
	Left struct {
		Meta struct {
			Key string `json:"key"`
		} `json:"meta"`
	} `json:"left"`
	Right string `json:"right"`
}

// egressDropPackets counts hits on the rule that contains a backend originating into the
// tunnel. A missing rule fails the test: it would otherwise read as a counter at zero.
func egressDropPackets(ctx context.Context, t testing.TB, ctr testcontainers.Container, table, iface string) uint64 {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "nft", "-j", "list", "chain", "inet", table, "forward")
	if code != 0 {
		t.Fatalf("nft -j list chain inet %s forward failed (exit %d):\n%s", table, code, out)
	}
	var dump nftRuleDump
	if err := json.Unmarshal([]byte(out), &dump); err != nil {
		t.Fatalf("decode nft -j list chain output %q: %v", out, err)
	}

	for _, entry := range dump.Nftables {
		if entry.Rule == nil {
			continue
		}
		var (
			isDrop     bool
			matchesOif bool
			packets    uint64
			counted    bool
		)
		for _, expr := range entry.Rule.Expr {
			if _, ok := expr["drop"]; ok {
				isDrop = true
			}
			if raw, ok := expr["counter"]; ok {
				var c struct {
					Packets uint64 `json:"packets"`
				}
				if err := json.Unmarshal(raw, &c); err != nil {
					t.Fatalf("decode counter expression %s: %v", raw, err)
				}
				packets, counted = c.Packets, true
			}
			if raw, ok := expr["match"]; ok {
				var m nftMetaMatch
				// A match on anything but a meta key against a literal (a ct state set, for
				// one) does not decode into this shape and is not the rule being looked for.
				if err := json.Unmarshal(raw, &m); err != nil {
					continue
				}
				if m.Left.Meta.Key == "oifname" && m.Right == iface {
					matchesOif = true
				}
			}
		}
		if isDrop && matchesOif && counted {
			return packets
		}
	}

	t.Fatalf("no `oifname %q counter drop` rule in the forward chain of inet %s:\n%s", iface, table, out)
	return 0
}

// ipRule is the subset of `ip -j rule show` a plan rule is identified by. The kernel
// renders the mark in its own shortest form, so marks are compared as numbers.
type ipRule struct {
	FwMark string `json:"fwmark"`
	FwMask string `json:"fwmask"`
	Table  string `json:"table"`
}

func countPlanRules(ctx context.Context, t testing.TB, ctr testcontainers.Container, id link.SlotIdentity) int {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "ip", "-j", "rule", "show")
	if code != 0 {
		t.Fatalf("ip -j rule show in the node netns failed (exit %d):\n%s", code, out)
	}
	var rules []ipRule
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatalf("decode ip -j rule show output %q: %v", out, err)
	}

	n := 0
	for _, r := range rules {
		if hexValue(t, r.FwMark) == hexValue(t, id.Mark) &&
			hexValue(t, r.FwMask) == hexValue(t, id.MarkMask) &&
			r.Table == strconv.Itoa(id.RouteTable) {
			n++
		}
	}
	return n
}

// hexValue parses a 0x-prefixed mark, treating an absent one as 0.
func hexValue(t testing.TB, s string) uint64 {
	t.Helper()
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		t.Fatalf("parse mark %q: %v", s, err)
	}
	return v
}

// programLocalRoutes runs the product's own route plan, so the data path is programmed
// by the same steps apply emits. Only steps flagged TolerateExists may fail on EEXIST.
func programLocalRoutes(ctx context.Context, t testing.TB, ctr testcontainers.Container, id link.SlotIdentity, targets []string) {
	t.Helper()
	for _, step := range link.LocalRouteCommands(id, targets) {
		code, out := netns.Exec(ctx, t, ctr, append([]string{"ip"}, step.Args...)...)
		if code == 0 {
			continue
		}
		if step.TolerateExists && strings.Contains(out, "File exists") {
			t.Logf("ip %s in the node netns exited %d because its object is already installed:\n%s", strings.Join(step.Args, " "), code, out)
			continue
		}
		t.Fatalf("ip %s in the node netns failed (exit %d):\n%s", strings.Join(step.Args, " "), code, out)
	}
}

// startPeerBackend copies peerBackendScript into the container, launches it in the
// backend netns, and waits for both of its sockets to be bound so no probe races bind.
func startPeerBackend(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(peerBackendScript), "/tmp/peer_backend.py", 0o644); err != nil {
		t.Fatalf("copy peer backend script: %v", err)
	}
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c", "ip netns exec backend python3 /tmp/peer_backend.py &"); code != 0 {
		t.Fatalf("start peer backend (exit %d):\n%s", code, out)
	}
	waitBackendBound(ctx, t, ctr, "-ltn", lpPodPort)
	waitBackendBound(ctx, t, ctr, "-lun", lpUDPPodPort)
}

func waitBackendBound(ctx context.Context, t testing.TB, ctr testcontainers.Container, flags string, port int) {
	t.Helper()
	want := fmt.Sprintf(":%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		code, out := netns.Exec(ctx, t, ctr, "ip", "netns", "exec", "backend", "ss", flags)
		if code == 0 && strings.Contains(out, want) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("peer backend did not bind %s (ss %s) within deadline", want, flags)
}

// applyInNetns copies ruleset into the container and loads it into ns with `nft -f`,
// for a netns other than the container's own that netns.Apply always targets.
func applyInNetns(ctx context.Context, t testing.TB, ctr testcontainers.Container, ns, ruleset string) {
	t.Helper()
	path := "/tmp/ruleset-" + ns + ".nft"
	if err := ctr.CopyToContainer(ctx, []byte(ruleset), path, 0o644); err != nil {
		t.Fatalf("copy ruleset to container for netns %s: %v", ns, err)
	}
	code, out := netns.Exec(ctx, t, ctr, "ip", "netns", "exec", ns, "nft", "-f", path)
	if code != 0 {
		t.Fatalf("nft -f %s in netns %s failed (exit %d):\n%s\n--- ruleset ---\n%s", path, ns, code, out, ruleset)
	}
}

// udpProbeScript connects the socket before sending so an ICMP port-unreachable
// surfaces as a refusal, which is what lets isTimeout tell a drop from a refusal.
const udpProbeScript = `import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(float(sys.argv[3]))
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.send(b"r\n")
    print("GOT:" + s.recv(64).decode(errors="replace").strip())
except Exception as e:
    print("ERR:" + repr(e))
finally:
    s.close()
`

type probeKind struct {
	name   string
	script string
	path   string
}

var (
	tcpProbe = probeKind{name: "tcp", script: probeScript, path: "/tmp/probe.py"}
	udpProbe = probeKind{name: "udp", script: udpProbeScript, path: "/tmp/udp_probe.py"}
)

// probeFrom runs a probe under ip netns exec ns against addr:port, or in the node netns when
// ns is "", returning "" on an ERR: line.
func probeFrom(ctx context.Context, t testing.TB, ctr testcontainers.Container, kind probeKind, ns, addr string, port int) string {
	t.Helper()
	return parseMarker(runProbeScript(ctx, t, ctr, kind, ns, addr, port))
}

// probeErrorFrom runs the same probe as probeFrom and returns the raw ERR: text,
// failing the test when the probe unexpectedly succeeded.
func probeErrorFrom(ctx context.Context, t testing.TB, ctr testcontainers.Container, kind probeKind, ns, addr string, port int) string {
	t.Helper()
	out := runProbeScript(ctx, t, ctr, kind, ns, addr, port)
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if m, ok := strings.CutPrefix(line, "ERR:"); ok {
			return m
		}
	}
	t.Fatalf("%s probe from %s to %s:%d unexpectedly succeeded: %q", kind.name, ns, addr, port, out)
	return ""
}

func runProbeScript(ctx context.Context, t testing.TB, ctr testcontainers.Container, kind probeKind, ns, addr string, port int) string {
	t.Helper()
	if err := ctr.CopyToContainer(ctx, []byte(kind.script), kind.path, 0o644); err != nil {
		t.Fatalf("copy %s probe script: %v", kind.name, err)
	}
	secs := fmt.Sprintf("%.0f", lpProbeTimeout.Seconds())
	cmd := fmt.Sprintf("python3 %s %s %d %s", kind.path, addr, port, secs)
	if ns != "" {
		cmd = "ip netns exec " + ns + " " + cmd
	}
	code, out := netns.Exec(ctx, t, ctr, "sh", "-c", cmd)
	if code != 0 {
		t.Fatalf("%s probe exec failed (exit %d):\n%s", kind.name, code, out)
	}
	return out
}

// isTimeout distinguishes a forward-chain drop from a rejected connection. Both
// spellings are what CPython's exception repr produces.
func isTimeout(err string) bool {
	if strings.Contains(err, "ConnectionRefusedError") {
		return false
	}
	return strings.Contains(err, "timeout") || strings.Contains(err, "TimeoutError")
}
