package linkint

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/netns"
)

func TestTeardownRemovesDataPlane(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := netns.Start(ctx, t)
	baseline := readTeardownState(ctx, t, ctr, nil)
	createWG0(ctx, t, ctr)

	// The rendered ruleset is the exact document the daemon loads, so the table the
	// teardown deletes is created by production code, not a stand-in.
	forwards := []link.ResolvedForward{
		{Name: "tcp-svc", PublicPort: 8443, Protocol: "tcp", Target: "10.96.1.1", TargetPort: 443},
		{Name: "udp-svc", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.2", TargetPort: 9000},
	}
	rc := link.RuntimeConfig{}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, forwards))

	// The teardown is only meaningful if there is a data plane to tear down.
	if !ifacePresent(ctx, t, ctr, "wg0") {
		t.Fatal("precondition failed: wg0 absent before teardown")
	}
	if !nftTablePresent(ctx, t, ctr, "gateway") {
		t.Fatal("precondition failed: inet gateway table absent before teardown")
	}

	runTeardownPlan(ctx, t, ctr, rc)

	assertTeardownState(ctx, t, ctr, nil, baseline, "after teardown; want the baseline from before link setup")
}

// TestLocalTeardownRemovesNodeState removes every configured slot's node state.
func TestLocalTeardownRemovesNodeState(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(lpLinkID)
	slots := []link.SlotIdentity{link.NewSlotIdentity(lpLinkID, 0), link.NewSlotIdentity(lpLinkID, 2)}
	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB0="}, {Slot: 2, PublicKey: "PUB2="}}},
	}
	forwards := []link.ResolvedForward{
		{Name: "tcp-8443", PublicPort: lpPublicPort, Protocol: "tcp", Target: lpPodIP, TargetPort: lpPodPort},
	}

	ctr := netns.Start(ctx, t)
	routeTables := []int{slots[0].RouteTable, slots[1].RouteTable}
	baseline := readTeardownState(ctx, t, ctr, routeTables)
	for _, id := range slots {
		// A dummy stands in for each WireGuard device: the ruleset and the route plan both
		// name it, and nft resolves iifname at load time.
		if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", id.Interface, "type", "dummy"); code != 0 {
			t.Fatalf("ip link add %s failed (exit %d):\n%s", id.Interface, code, out)
		}
		if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "set", id.Interface, "up"); code != 0 {
			t.Fatalf("ip link set %s up failed (exit %d):\n%s", id.Interface, code, out)
		}
		programLocalRoutes(ctx, t, ctr, id, []string{lpPodIP})
	}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, forwards))

	for _, id := range slots {
		if n := countPlanRules(ctx, t, ctr, id); n != 1 {
			t.Fatalf("precondition failed: %d ip rules match slot %d's plan before the teardown, want 1", n, id.RouteTable)
		}
	}
	if !nftTablePresent(ctx, t, ctr, gwIdent.NftTable) {
		t.Fatalf("precondition failed: inet %s table absent before the teardown", gwIdent.NftTable)
	}

	runTeardownPlan(ctx, t, ctr, rc)
	assertTeardownState(ctx, t, ctr, routeTables, baseline, "after teardown; want the baseline from before link setup")
}

// runTeardownPlan runs the product's teardown plan in order. The test programmed every
// object the plan removes, so each step must succeed.
func runTeardownPlan(ctx context.Context, t testing.TB, ctr testcontainers.Container, rc link.RuntimeConfig) {
	t.Helper()
	for _, step := range link.TeardownCommands(rc) {
		code, out := netns.Exec(ctx, t, ctr, append([]string{step.Name}, step.Args...)...)
		if code != 0 {
			t.Fatalf("teardown: %s %s failed (exit %d):\n%s", step.Name, strings.Join(step.Args, " "), code, out)
		}
	}
}

func ifacePresent(ctx context.Context, t testing.TB, ctr testcontainers.Container, iface string) bool {
	t.Helper()
	code, _ := netns.Exec(ctx, t, ctr, "ip", "link", "show", iface)
	return code == 0
}

func nftTablePresent(ctx context.Context, t testing.TB, ctr testcontainers.Container, table string) bool {
	t.Helper()
	code, _ := netns.Exec(ctx, t, ctr, "nft", "list", "table", "inet", table)
	return code == 0
}

type teardownState struct {
	Devices     []string
	Tables      []string
	Routes      map[int][]string
	PolicyRules []string
}

func readTeardownState(ctx context.Context, t testing.TB, ctr testcontainers.Container, routeTables []int) teardownState {
	t.Helper()
	devices := nodeLinkNames(ctx, t, ctr)
	slices.Sort(devices)
	return teardownState{
		Devices:     devices,
		Tables:      nftTableNames(ctx, t, ctr),
		Routes:      teardownRoutes(ctx, t, ctr, routeTables),
		PolicyRules: jsonEntries(ctx, t, ctr, "ip -j rule show", "ip", "-j", "rule", "show"),
	}
}

func assertTeardownState(ctx context.Context, t testing.TB, ctr testcontainers.Container, routeTables []int, want teardownState, stage string) {
	t.Helper()
	got := readTeardownState(ctx, t, ctr, routeTables)
	if !slices.Equal(got.Devices, want.Devices) {
		t.Errorf("network devices %s = %v, want %v", stage, got.Devices, want.Devices)
	}
	if !slices.Equal(got.Tables, want.Tables) {
		t.Errorf("nft tables %s = %v, want %v", stage, got.Tables, want.Tables)
	}
	for _, table := range routeTables {
		if !slices.Equal(got.Routes[table], want.Routes[table]) {
			t.Errorf("route table %d %s = %v, want %v", table, stage, got.Routes[table], want.Routes[table])
		}
	}
	if !slices.Equal(got.PolicyRules, want.PolicyRules) {
		t.Errorf("policy rules %s = %v, want %v", stage, got.PolicyRules, want.PolicyRules)
	}
}

func nftTableNames(ctx context.Context, t testing.TB, ctr testcontainers.Container) []string {
	t.Helper()
	names := []string{}
	for line := range strings.SplitSeq(netns.List(ctx, t, ctr, "tables"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" {
			names = append(names, fields[1]+" "+fields[2])
		}
	}
	slices.Sort(names)
	return names
}

func teardownRoutes(ctx context.Context, t testing.TB, ctr testcontainers.Container, routeTables []int) map[int][]string {
	t.Helper()
	routes := make(map[int][]string, len(routeTables))
	for _, table := range routeTables {
		command := "ip -j route show table " + strconv.Itoa(table)
		code, out := netns.Exec(ctx, t, ctr, "ip", "-j", "route", "show", "table", strconv.Itoa(table))
		if code != 0 && (!strings.HasPrefix(strings.TrimSpace(out), "[]") || !strings.Contains(out, "FIB table does not exist")) {
			t.Fatalf("%s failed (exit %d):\n%s", command, code, out)
		}
		routes[table] = decodeJSONEntries(t, command, out)
	}
	return routes
}

func jsonEntries(ctx context.Context, t testing.TB, ctr testcontainers.Container, command string, args ...string) []string {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, args...)
	if code != 0 {
		t.Fatalf("%s failed (exit %d):\n%s", command, code, out)
	}
	return decodeJSONEntries(t, command, out)
}

func decodeJSONEntries(t testing.TB, command, out string) []string {
	t.Helper()
	jsonOutput, _, _ := strings.Cut(out, "\nError:")
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(jsonOutput), &entries); err != nil {
		t.Fatalf("decode %s output %q: %v", command, out, err)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		normalized, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("normalize %s entry %q: %v", command, entry, err)
		}
		got = append(got, string(normalized))
	}
	slices.Sort(got)
	return got
}
