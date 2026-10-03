package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	e2eharness "github.com/tripod-networks/wireguard-gateway-operator/test/harness/e2e"
	hk8s "github.com/tripod-networks/wireguard-gateway-operator/test/harness/k8s"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/shared"
)

type tunnelOutage struct {
	rules  [][]string
	lifted bool
}

// dropTunnelTraffic drops every UDP packet a kind node sends to the member addresses, which stops
// the WireGuard tunnels until lift runs; the operator cannot undo a node-level rule.
func dropTunnelTraffic(ctx context.Context, t *testing.T, suite *e2eharness.Suite, natIPs []string) *tunnelOutage {
	t.Helper()
	o := &tunnelOutage{}
	nodes, err := suite.Nodes()
	if err != nil {
		t.Fatalf("list kind nodes: %v", err)
	}
	for _, node := range nodes {
		for _, ip := range natIPs {
			for _, chain := range []string{"FORWARD", "OUTPUT"} {
				match := []string{"-d", ip + "/32", "-p", "udp", "-j", "DROP"}
				argv := append([]string{"iptables", "-w", "10", "-I", chain, "1"}, match...)
				if _, err := hk8s.NodeExec(ctx, node, argv...); err != nil {
					t.Fatalf("drop udp to %s on node %s: %v", ip, node, err)
				}
				o.rules = append(o.rules, append([]string{node, chain}, match...))
			}
		}
	}
	t.Cleanup(func() {
		if err := o.lift(context.Background()); err != nil {
			t.Logf("outage cleanup: %v", err)
		}
	})
	return o
}

func (o *tunnelOutage) lift(ctx context.Context) error {
	if o.lifted {
		return nil
	}
	o.lifted = true
	var errs []error
	for _, rule := range o.rules {
		argv := append([]string{"iptables", "-w", "10", "-D", rule[1]}, rule[2:]...)
		if _, err := hk8s.NodeExec(ctx, rule[0], argv...); err != nil {
			errs = append(errs, fmt.Errorf("restore udp on node %s: %w", rule[0], err))
		}
	}
	return errors.Join(errs...)
}

func instanceAddresses(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) []string {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "instances", "list", "--filter", "name~^"+stack.NamePrefix, "--format", "value(name,networkInterfaces[0].accessConfigs[0].natIP)")
	addresses := strings.FieldsFunc(out, func(r rune) bool { return r == '\n' })
	slices.Sort(addresses)
	return addresses
}

func assertSameInstanceAddresses(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, want []string) {
	t.Helper()
	if got := instanceAddresses(ctx, t, suite, stack); !slices.Equal(got, want) {
		t.Errorf("instance names and promoted addresses = %v, want %v", got, want)
	}
}

// assertPromotedAddresses verifies promoted external addresses for all members.
func assertPromotedAddresses(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) {
	t.Helper()
	var reserved map[string]string
	var got, want []string
	deadline := time.Now().Add(rolloutTimeout)
	for time.Now().Before(deadline) {
		reserved = reservedAddresses(ctx, t, suite, stack)
		got = slices.Sorted(maps.Values(reserved))
		want = append(memberNATAddresses(ctx, t, suite, stack), stack.Address)
		slices.Sort(want)
		if slices.Equal(got, want) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for the gateway's reservations: %v", ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Errorf("reservations %v hold %v, want exactly the member addresses and the forwarding rule's %v",
		slices.Sorted(maps.Keys(reserved)), got, want)
}

// reservedAddresses returns the gateway's static address reservations by name.
func reservedAddresses(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) map[string]string {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "addresses", "list", "--filter", "name~^"+stack.NamePrefix, "--format", "value(name,address)")
	reserved := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			t.Fatalf("address row = %q, want a name and an address", line)
		}
		reserved[fields[0]] = fields[1]
	}
	return reserved
}

// memberNATAddresses returns each member's promoted external address.
func memberNATAddresses(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) []string {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "instances", "list", "--filter", "name~^"+stack.NamePrefix,
		"--format", "value(networkInterfaces[0].accessConfigs[0].natIP)")
	return strings.Fields(out)
}

func assertProbe(ctx context.Context, t *testing.T, stack *e2eharness.Stack) {
	t.Helper()
	if _, err := probeGateway(ctx, stack); err != nil {
		t.Fatalf("probe load balancer: %v", err)
	}
}

func probeGateway(ctx context.Context, stack *e2eharness.Stack) (string, error) {
	return probeAddress(ctx, stack.Address)
}

func probeAddress(ctx context.Context, address string) (string, error) {
	out, err := shared.RunCmdStdout(ctx, nil, "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
		"http://"+address+":8443/hostname")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("backend marker was empty")
	}
	return out, nil
}

type probeFirewall struct {
	network        string
	serviceAccount string
	port           string
	sourceRanges   []string
}

// firewallConnection is one connection a logging firewall rule recorded: the source
// address, the address the receiver was addressed on, the port, and the receiving VM.
type firewallConnection struct {
	source      string
	destination string
	port        string
	instance    string
}

// observeSpec holds the firewall rule network, service account, source ranges, and allow terms.
type observeSpec struct {
	name           string
	network        string
	serviceAccount string
	sourceRanges   []string
	// allow holds gcloud --allow terms, each "<protocol>:<port>".
	allow []string
}

const (
	// firewallObservationTimeout bounds the wait for logged connections. The MIG check
	// polls every 30s and firewall logs are batched, so the window is minutes, not seconds.
	firewallObservationTimeout = 10 * time.Minute
	firewallObservationPoll    = 30 * time.Second
	// observedNameTimeout bounds the wait for the composite to publish a provider-generated
	// resource name. The gateway is Ready by then, so the name is a reconcile away.
	observedNameTimeout = 5 * time.Minute
	// bundleRereadTimeout bounds the wait for the rebooted guest's keyfetch unit to log its
	// bundle read on the serial console.
	bundleRereadTimeout = 10 * time.Minute
	bundleRereadPoll    = 15 * time.Second
)

// assertProbeArrival verifies the probe reaches the expected backend.
func assertProbeArrival(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) {
	t.Helper()
	firewall := readProbeFirewall(ctx, t, suite, stack)
	spec := observeSpec{
		name:           stack.NamePrefix + "-probe-observe",
		network:        firewall.network,
		serviceAccount: firewall.serviceAccount,
		sourceRanges:   firewall.sourceRanges,
		allow:          []string{"tcp:" + firewall.port},
	}
	startFirewallLogging(ctx, t, suite, spec)
	members := memberAddresses(ctx, t, suite, stack)
	connections := waitForFirewallConnections(ctx, t, suite, spec,
		func(logged []firewallConnection) bool {
			onLB, onMember := false, false
			for _, conn := range logged {
				if conn.destination == stack.Address {
					onLB = true
				}
				if slices.Contains(members, conn.destination) {
					onMember = true
				}
			}
			return onLB && onMember
		},
		fmt.Sprintf("probe connections on both the forwarding-rule address %s and a member address %v", stack.Address, members))

	prefixes := parsePrefixes(t, firewall.sourceRanges)
	for _, conn := range connections {
		t.Logf("health probe connection source=%s source_range=%s destination=%s port=%s",
			conn.source, sourceRange(t, prefixes, conn.source), conn.destination, conn.port)
		if conn.port != firewall.port {
			t.Errorf("probe connection %v port = %q, want the health port %q", conn, conn.port, firewall.port)
		}
		if sourceRange(t, prefixes, conn.source) == "" {
			t.Errorf("probe source %q lies outside the admitted ranges %v", conn.source, firewall.sourceRanges)
		}
		if conn.destination != stack.Address && !slices.Contains(members, conn.destination) {
			t.Errorf("probe destination %q is neither the forwarding-rule address %q nor a member address %v",
				conn.destination, stack.Address, members)
		}
	}
}

func readProbeFirewall(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) probeFirewall {
	t.Helper()
	name := stack.NamePrefix + "-firewall-probe"
	fields := strings.Fields(runGcloud(ctx, t, suite, "compute", "firewall-rules", "describe", name,
		"--format", "value(network,targetServiceAccounts[0],allowed[0].ports[0])"))
	if len(fields) != 3 {
		t.Fatalf("firewall rule %s = %v, want a network, a target service account and a port", name, fields)
	}
	ranges := strings.Split(strings.TrimSpace(runGcloud(ctx, t, suite, "compute", "firewall-rules", "describe", name,
		"--format", "value(sourceRanges.list())")), ",")
	if len(ranges) == 0 || ranges[0] == "" {
		t.Fatalf("firewall rule %s has no source ranges", name)
	}
	return probeFirewall{
		network:        path.Base(fields[0]),
		serviceAccount: fields[1],
		port:           fields[2],
		sourceRanges:   ranges,
	}
}

// startFirewallLogging raises spec's rule and registers its deletion, so the rule goes
// whether the assertion that follows passes or fails.
func startFirewallLogging(ctx context.Context, t *testing.T, suite *e2eharness.Suite, spec observeSpec) {
	t.Helper()
	args := []string{"compute", "firewall-rules", "create", spec.name,
		"--network", spec.network,
		"--direction", "INGRESS",
		"--priority", "900",
		"--source-ranges", strings.Join(spec.sourceRanges, ","),
		"--target-service-accounts", spec.serviceAccount,
		"--enable-logging",
		"--logging-metadata", "include-all",
		"--quiet"}
	for _, allow := range spec.allow {
		args = append(args, "--allow", allow)
	}
	runGcloud(ctx, t, suite, args...)
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		runGcloud(cctx, t, suite, "compute", "firewall-rules", "delete", spec.name, "--quiet")
	})
}

// waitForFirewallConnections waits for expected firewall connections.
func waitForFirewallConnections(ctx context.Context, t *testing.T, suite *e2eharness.Suite, spec observeSpec, satisfied func([]firewallConnection) bool, want string) []firewallConnection {
	t.Helper()
	deadline := time.Now().Add(firewallObservationTimeout)
	var connections []firewallConnection
	for time.Now().Before(deadline) {
		connections = readFirewallConnections(ctx, t, suite, spec)
		if satisfied(connections) {
			return connections
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for %s: %v", want, ctx.Err())
		case <-time.After(firewallObservationPoll):
		}
	}
	t.Fatalf("rule %s logged no %s within %s; logged %v", spec.name, want, firewallObservationTimeout, connections)
	return nil
}

func readFirewallConnections(ctx context.Context, t *testing.T, suite *e2eharness.Suite, spec observeSpec) []firewallConnection {
	t.Helper()
	filter := fmt.Sprintf(`logName:"compute.googleapis.com%%2Ffirewall" AND jsonPayload.rule_details.reference="network:%s/firewall:%s"`, spec.network, spec.name)
	out := runGcloud(ctx, t, suite, "logging", "read", filter,
		"--freshness", "15m",
		"--limit", "500",
		"--format", "value(jsonPayload.connection.src_ip,jsonPayload.connection.dest_ip,jsonPayload.connection.dest_port,jsonPayload.instance.vm_name)")
	var connections []firewallConnection
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("firewall log row = %q, want a source, a destination, a port and a vm name", line)
		}
		connections = append(connections, firewallConnection{
			source:      fields[0],
			destination: fields[1],
			port:        fields[2],
			instance:    fields[3],
		})
	}
	return connections
}

// assertMemberIngress verifies the forwarding rule and each member return the same marker.
func assertMemberIngress(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) {
	t.Helper()
	marker := probeBurst(ctx, t, stack)
	mig := migName(ctx, t, suite, stack)
	for _, member := range fleetMembers(ctx, t, suite, stack, mig) {
		if member.NATIP == "" {
			t.Fatalf("member %s has no promoted address for ingress", member.Name)
		}
		assertMemberMarker(ctx, t, member, marker)
	}
}

func probeBurst(ctx context.Context, t *testing.T, stack *e2eharness.Stack) string {
	t.Helper()
	var marker string
	for range 20 {
		body, err := probeGateway(ctx, stack)
		if err != nil {
			t.Fatalf("probe load balancer: %v", err)
		}
		if marker == "" {
			marker = body
			continue
		}
		if body != marker {
			t.Fatalf("load balancer marker = %q, want %q", body, marker)
		}
	}
	return marker
}

func assertMemberMarker(ctx context.Context, t *testing.T, member e2eharness.MIGMember, marker string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var lastBody string
	var lastErr error
	for time.Now().Before(deadline) {
		lastBody, lastErr = probeAddress(ctx, member.NATIP)
		if lastErr == nil && lastBody == marker {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for member %s at %s: %v", member.Name, member.NATIP, ctx.Err())
		case <-time.After(time.Second):
		}
	}
	t.Fatalf("member %s at %s marker = %q, error = %v, want %q", member.Name, member.NATIP, lastBody, lastErr, marker)
}

// memberAddresses returns every address a probe can reach a member on: nic0's internal
// address and its promoted external one.
func memberAddresses(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) []string {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "instances", "list", "--filter", "name~^"+stack.NamePrefix,
		"--format", "value(networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP)")
	addresses := strings.Fields(out)
	slices.Sort(addresses)
	return addresses
}

func parsePrefixes(t *testing.T, ranges []string) []netip.Prefix {
	t.Helper()
	prefixes := make([]netip.Prefix, 0, len(ranges))
	for _, raw := range ranges {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			t.Fatalf("parse admitted range %q: %v", raw, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// sourceRange returns the admitted range holding address, or "" when none does.
func sourceRange(t *testing.T, prefixes []netip.Prefix, address string) string {
	t.Helper()
	addr, err := netip.ParseAddr(address)
	if err != nil {
		t.Fatalf("parse probe source %q: %v", address, err)
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return prefix.String()
		}
	}
	return ""
}
