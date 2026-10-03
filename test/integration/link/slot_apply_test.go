package linkint

// Per-slot apply isolates failures, and reload removes state for the departed slot.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/netns"
)

const (
	// saLinkID is the link id the failed-slot fixture derives every name from.
	saLinkID = 11
	// srLinkID is the link id the reload fixture derives every name from.
	srLinkID = 12
	// sfLinkID is the link id the half-applied-slot fixture derives every name from.
	sfLinkID = 15
)

// TestSlotApplyContinuesPastFailedSlotRetriesNextPass retries only the failed slot.
func TestSlotApplyContinuesPastFailedSlotRetriesNextPass(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(saLinkID)
	slot0 := link.NewSlotIdentity(saLinkID, 0)
	slot1 := link.NewSlotIdentity(saLinkID, 1)
	rc := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB0="}, {Slot: 1, PublicKey: "PUB1="}}},
	}

	ctr := netns.Start(ctx, t)

	// slot 1's interface name is pre-occupied by a bridge, the same kind of EEXIST-but-wrong-
	// type obstruction a real apply's `ip link add ... type wireguard` step would fail on.
	if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", slot1.Interface, "type", "bridge"); code != 0 {
		t.Fatalf("pre-occupy %s failed (exit %d):\n%s", slot1.Interface, code, out)
	}

	applySlot := func(id link.SlotIdentity) (ok bool) {
		if code, _ := netns.Exec(ctx, t, ctr, "ip", "link", "add", id.Interface, "type", "dummy"); code != 0 {
			return false
		}
		if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "set", id.Interface, "up"); code != 0 {
			t.Fatalf("ip link set %s up failed (exit %d):\n%s", id.Interface, code, out)
		}
		programLocalRoutes(ctx, t, ctr, id, []string{lpPodIP})
		return true
	}

	slot0Applied := applySlot(slot0)
	slot1Applied := applySlot(slot1)
	// Matching apply.go's contract: the final nft -f ruleset still runs once for whatever
	// slots succeeded, regardless of a per-slot failure.
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, nil))

	if !slot0Applied {
		t.Fatal("slot 0's plan failed; it must run independently of slot 1's obstruction")
	}
	if slot1Applied {
		t.Fatal("slot 1's plan unexpectedly succeeded against a pre-occupied interface name")
	}

	obstructed := wantGatewayState(slot0)
	// The pre-occupying bridge still holds slot 1's name, so the name is present while none of
	// slot 1's routing state is.
	obstructed.Interfaces = append(obstructed.Interfaces, slot1.Interface)
	slices.Sort(obstructed.Interfaces)
	assertGatewayState(ctx, t, ctr, saLinkID, obstructed, "while slot 1 is obstructed")

	if !nftTablePresent(ctx, t, ctr, gwIdent.NftTable) {
		t.Error("the gateway-wide nft table is absent; the final ruleset apply must still run for the slots that succeeded")
	}

	// The obstruction clears, matching a re-apply on the next reconcile tick.
	if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "del", slot1.Interface); code != 0 {
		t.Fatalf("remove the pre-occupying %s failed (exit %d):\n%s", slot1.Interface, code, out)
	}

	if !applySlot(slot1) {
		t.Fatal("slot 1's plan still fails on the next pass after its obstruction was cleared")
	}
	netns.Apply(ctx, t, ctr, renderRuleset(t, rc, nil))

	assertGatewayState(ctx, t, ctr, saLinkID, wantGatewayState(slot0, slot1), "after slot 1's retrying pass")
}

// TestSlotReloadDropsDepartedSlot tears down a departed slot on reload.
func TestSlotReloadDropsDepartedSlot(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(srLinkID)
	slot0 := link.NewSlotIdentity(srLinkID, 0)
	slot2 := link.NewSlotIdentity(srLinkID, 2)
	twoSlot := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB0="}, {Slot: 2, PublicKey: "PUB2="}}},
	}
	oneSlot := twoSlot
	oneSlot.WireGuard.Peers = []link.Peer{{Slot: 0, PublicKey: "PUB0="}}

	ctr := netns.Start(ctx, t)
	for _, id := range []link.SlotIdentity{slot0, slot2} {
		addDummySlotInterface(ctx, t, ctr, id)
		programLocalRoutes(ctx, t, ctr, id, []string{lpPodIP})
	}
	netns.Apply(ctx, t, ctr, renderRuleset(t, twoSlot, nil))
	assertGatewayState(ctx, t, ctr, srLinkID, wantGatewayState(slot0, slot2), "after the two-slot apply")

	runDepartedTeardown(ctx, t, ctr, twoSlot, oneSlot)
	programLocalRoutes(ctx, t, ctr, slot0, []string{lpPodIP})
	netns.Apply(ctx, t, ctr, renderRuleset(t, oneSlot, nil))
	assertGatewayState(ctx, t, ctr, srLinkID, wantGatewayState(slot0), "after the reload to slot 0 alone")

	runTeardownPlan(ctx, t, ctr, oneSlot)
	assertGatewayState(ctx, t, ctr, srLinkID, wantGatewayState(), "after the shutdown teardown")
}

func addDummySlotInterface(ctx context.Context, t testing.TB, ctr testcontainers.Container, id link.SlotIdentity) {
	t.Helper()
	if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", id.Interface, "type", "dummy"); code != 0 {
		t.Fatalf("ip link add %s failed (exit %d):\n%s", id.Interface, code, out)
	}
	if code, out := netns.Exec(ctx, t, ctr, "ip", "link", "set", id.Interface, "up"); code != 0 {
		t.Fatalf("ip link set %s up failed (exit %d):\n%s", id.Interface, code, out)
	}
}

// runDepartedTeardown runs departure teardown in the network namespace.
func runDepartedTeardown(ctx context.Context, t testing.TB, ctr testcontainers.Container, previous, current link.RuntimeConfig) {
	t.Helper()
	for _, step := range link.TeardownCommands(departedConfig(previous, current)) {
		if step.Name != "ip" {
			continue
		}
		code, out := netns.Exec(ctx, t, ctr, append([]string{step.Name}, step.Args...)...)
		if code != 0 {
			t.Fatalf("departed slot teardown: %s %v failed (exit %d):\n%s", step.Name, step.Args, code, out)
		}
	}
}

// runDepartedTeardownOfHalfAppliedSlot tears down a partially applied slot.
func runDepartedTeardownOfHalfAppliedSlot(ctx context.Context, t testing.TB, ctr testcontainers.Container, previous, current link.RuntimeConfig) {
	t.Helper()
	for _, step := range link.TeardownCommands(departedConfig(previous, current)) {
		if step.Name != "ip" {
			continue
		}
		if code, out := netns.Exec(ctx, t, ctr, append([]string{step.Name}, step.Args...)...); code != 0 {
			t.Logf("departed slot teardown: %s %v exited %d:\n%s", step.Name, step.Args, code, out)
		}
	}
}

// departedConfig is previous carrying exactly the peers current dropped.
func departedConfig(previous, current link.RuntimeConfig) link.RuntimeConfig {
	kept := make(map[int]struct{}, len(current.WireGuard.Peers))
	for _, p := range current.WireGuard.Peers {
		kept[p.Slot] = struct{}{}
	}
	departed := previous
	departed.WireGuard.Peers = nil
	for _, p := range previous.WireGuard.Peers {
		if _, ok := kept[p.Slot]; !ok {
			departed.WireGuard.Peers = append(departed.WireGuard.Peers, p)
		}
	}
	return departed
}

// TestSlotFailingAfterInterfaceCreationIsTornDownOnDeparture cleans partial state on departure.
func TestSlotFailingAfterInterfaceCreationIsTornDownOnDeparture(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(sfLinkID)
	slot0 := link.NewSlotIdentity(sfLinkID, 0)
	slot1 := link.NewSlotIdentity(sfLinkID, 1)
	twoSlot := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB0="}, {Slot: 1, PublicKey: "PUB1="}}},
	}
	oneSlot := twoSlot
	oneSlot.WireGuard.Peers = []link.Peer{{Slot: 0, PublicKey: "PUB0="}}

	ctr := netns.Start(ctx, t, "wireguard-tools")

	addDummySlotInterface(ctx, t, ctr, slot0)
	programLocalRoutes(ctx, t, ctr, slot0, []string{lpPodIP})

	// The dummy interface makes wg syncconf fail before rules and routes are programmed.
	addDummySlotInterface(ctx, t, ctr, slot1)
	const slot1Conf = "/tmp/slot1.conf"
	if code, out := netns.Exec(ctx, t, ctr, "sh", "-c",
		`umask 077; printf '[Interface]\nPrivateKey = %s\n' "$(wg genkey)" > `+slot1Conf); code != 0 {
		t.Fatalf("write %s failed (exit %d):\n%s", slot1Conf, code, out)
	}
	code, out := netns.Exec(ctx, t, ctr, "wg", "syncconf", slot1.Interface, slot1Conf)
	if code == 0 {
		t.Fatalf("wg syncconf %s succeeded on a non-WireGuard device, so the fixture does not reproduce a slot failing after its interface creation", slot1.Interface)
	}
	t.Logf("slot 1's wg syncconf exited %d as the fixture requires:\n%s", code, out)
	netns.Apply(ctx, t, ctr, renderRuleset(t, twoSlot, nil))

	halfApplied := wantGatewayState(slot0)
	halfApplied.Interfaces = append(halfApplied.Interfaces, slot1.Interface)
	slices.Sort(halfApplied.Interfaces)
	assertGatewayState(ctx, t, ctr, sfLinkID, halfApplied, "after slot 1 failed at wg syncconf")

	runDepartedTeardownOfHalfAppliedSlot(ctx, t, ctr, twoSlot, oneSlot)
	programLocalRoutes(ctx, t, ctr, slot0, []string{lpPodIP})
	netns.Apply(ctx, t, ctr, renderRuleset(t, oneSlot, nil))

	assertGatewayState(ctx, t, ctr, sfLinkID, wantGatewayState(slot0), "after the pass that dropped slot 1")
}

// gatewayState is the node-global state one Gateway owns, read back from the kernel: its slot
// interfaces, its fwmark rules and its route tables, each sorted.
type gatewayState struct {
	Interfaces []string
	Rules      []string
	Tables     []string
}

// wantGatewayState is the state a node carries when exactly ids are programmed; with no id it is
// the state of a node this Gateway owns nothing on.
func wantGatewayState(ids ...link.SlotIdentity) gatewayState {
	state := gatewayState{Interfaces: []string{}, Rules: []string{}, Tables: []string{}}
	for _, id := range ids {
		state.Interfaces = append(state.Interfaces, id.Interface)
		state.Rules = append(state.Rules, fmt.Sprintf("%s/%s lookup %d", id.Mark, id.MarkMask, id.RouteTable))
		state.Tables = append(state.Tables, strconv.Itoa(id.RouteTable))
	}
	slices.Sort(state.Interfaces)
	slices.Sort(state.Rules)
	slices.Sort(state.Tables)
	return state
}

func assertGatewayState(ctx context.Context, t testing.TB, ctr testcontainers.Container, gatewayID int, want gatewayState, stage string) {
	t.Helper()
	got := readGatewayState(ctx, t, ctr, gatewayID)
	if !slices.Equal(got.Interfaces, want.Interfaces) {
		t.Errorf("gateway %d interfaces %s = %v, want %v", gatewayID, stage, got.Interfaces, want.Interfaces)
	}
	if !slices.Equal(got.Rules, want.Rules) {
		t.Errorf("gateway %d ip rules %s = %v, want %v", gatewayID, stage, got.Rules, want.Rules)
	}
	if !slices.Equal(got.Tables, want.Tables) {
		t.Errorf("gateway %d route tables %s = %v, want %v", gatewayID, stage, got.Tables, want.Tables)
	}
}

func readGatewayState(ctx context.Context, t testing.TB, ctr testcontainers.Container, gatewayID int) gatewayState {
	t.Helper()
	return gatewayState{
		Interfaces: gatewayInterfaces(ctx, t, ctr, gatewayID),
		Rules:      gatewayRules(ctx, t, ctr, gatewayID),
		Tables:     gatewayRouteTables(ctx, t, ctr, gatewayID),
	}
}

func gatewayInterfaces(ctx context.Context, t testing.TB, ctr testcontainers.Container, gatewayID int) []string {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "ip", "-j", "link", "show")
	if code != 0 {
		t.Fatalf("ip -j link show failed (exit %d):\n%s", code, out)
	}
	var links []struct {
		IfName string `json:"ifname"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		t.Fatalf("decode ip -j link show output %q: %v", out, err)
	}
	owned := regexp.MustCompile(`^wg-gw` + strconv.Itoa(gatewayID) + `(-[0-9]+)?$`)
	names := []string{}
	for _, l := range links {
		if owned.MatchString(l.IfName) {
			names = append(names, l.IfName)
		}
	}
	slices.Sort(names)
	return names
}

func gatewayRules(ctx context.Context, t testing.TB, ctr testcontainers.Container, gatewayID int) []string {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "ip", "-j", "rule", "show")
	if code != 0 {
		t.Fatalf("ip -j rule show failed (exit %d):\n%s", code, out)
	}
	var rules []ipRule
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatalf("decode ip -j rule show output %q: %v", out, err)
	}
	wantMask := hexValue(t, link.NewSlotIdentity(gatewayID, 0).MarkMask)
	got := []string{}
	for _, r := range rules {
		mark, mask := hexValue(t, r.FwMark), hexValue(t, r.FwMask)
		// The routing key's low byte is the Gateway id, so a rule of any slot of this
		// Gateway is recognised without enumerating slots.
		if mask != wantMask || (mark>>16)&0xff != uint64(gatewayID) {
			continue
		}
		got = append(got, fmt.Sprintf("0x%08x/0x%08x lookup %s", mark, mask, r.Table))
	}
	slices.Sort(got)
	return got
}

func gatewayRouteTables(ctx context.Context, t testing.TB, ctr testcontainers.Container, gatewayID int) []string {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "ip", "-j", "route", "show", "table", "all")
	if code != 0 {
		t.Fatalf("ip -j route show table all failed (exit %d):\n%s", code, out)
	}
	var routes []struct {
		Table string `json:"table"`
	}
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		t.Fatalf("decode ip -j route show table all output %q: %v", out, err)
	}
	base := link.NewSlotIdentity(gatewayID, 0).RouteTable
	tables := []string{}
	for _, r := range routes {
		n, err := strconv.Atoi(r.Table)
		if err != nil || n < base || (n-base)%256 != 0 || (n-base)/256 > 255 {
			continue
		}
		if !slices.Contains(tables, r.Table) {
			tables = append(tables, r.Table)
		}
	}
	slices.Sort(tables)
	return tables
}
