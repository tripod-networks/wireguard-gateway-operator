// Package linkint exercises the link daemon's rendered nftables ruleset against a
// real nft binary in a container, asserting the document is self-replacing and that
// dropping a forward removes its DNAT rule.
package linkint

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/netns"
)

func TestNftablesApplyIsSelfReplacing(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startNftContainer(ctx, t)

	twoForwards := []link.ResolvedForward{
		{Name: "tcp-svc", PublicPort: 8443, Protocol: "tcp", Target: "10.96.1.1", TargetPort: 443},
		{Name: "udp-svc", PublicPort: 30000, Protocol: "udp", Target: "10.96.2.2", TargetPort: 9000},
	}

	rulesetTwo := renderRuleset(t, twoPeerClusterRC(), twoForwards)

	netns.Apply(ctx, t, ctr, rulesetTwo)
	firstListing := listTable(ctx, t, ctr)
	firstDNAT := countDNATRules(firstListing)
	if firstDNAT != len(twoForwards) {
		t.Fatalf("after first apply: DNAT rule count = %d, want %d\n%s", firstDNAT, len(twoForwards), firstListing)
	}

	netns.Apply(ctx, t, ctr, rulesetTwo)
	secondListing := listTable(ctx, t, ctr)

	if got := countDNATRules(secondListing); got != firstDNAT {
		t.Errorf("DNAT rule count changed after re-applying the same ruleset: first=%d second=%d (flush did not clear)\n%s",
			firstDNAT, got, secondListing)
	}
	if firstListing != secondListing {
		t.Errorf("table listing differs after re-applying the same ruleset; the document is not self-replacing\nfirst:\n%s\nsecond:\n%s",
			firstListing, secondListing)
	}

	oneForward := []link.ResolvedForward{twoForwards[0]}
	rulesetOne := renderRuleset(t, twoPeerClusterRC(), oneForward)
	netns.Apply(ctx, t, ctr, rulesetOne)
	prunedListing := listTable(ctx, t, ctr)

	keptDNAT := dnatRuleFor(twoForwards[0])
	if !strings.Contains(prunedListing, keptDNAT) {
		t.Errorf("DNAT rule for the retained forward is missing after re-apply: %q\n%s", keptDNAT, prunedListing)
	}
	if got := countDNATRules(prunedListing); got != len(oneForward) {
		t.Errorf("after pruning to one forward: DNAT rule count = %d, want %d\n%s", got, len(oneForward), prunedListing)
	}
	assertClusterForwardRules(ctx, t, ctr, oneForward, "after pruning")
}

// TestNftablesRetargetReplacesClusterIP repoints a forward to a second ClusterIP: a rule
// left on the old one, or a DNAT and accept pair that diverge, blackholes traffic.
func TestNftablesRetargetReplacesClusterIP(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := startNftContainer(ctx, t)

	const (
		retargetPort     = 8453
		retargetProtocol = "tcp"
		retargetTarget   = 443
		clusterIPA       = "10.96.0.10"
		clusterIPB       = "10.96.0.20"
	)

	forwardA := link.ResolvedForward{Name: "retarget", PublicPort: retargetPort, Protocol: retargetProtocol, Target: clusterIPA, TargetPort: retargetTarget}
	forwardB := link.ResolvedForward{Name: "retarget", PublicPort: retargetPort, Protocol: retargetProtocol, Target: clusterIPB, TargetPort: retargetTarget}

	netns.Apply(ctx, t, ctr, renderRuleset(t, twoPeerClusterRC(), []link.ResolvedForward{forwardA}))
	beforeListing := listTable(ctx, t, ctr)
	if dnat := dnatRuleFor(forwardA); !strings.Contains(beforeListing, dnat) {
		t.Fatalf("before retarget: DNAT to ClusterIP_A missing: %q\n%s", dnat, beforeListing)
	}

	netns.Apply(ctx, t, ctr, renderRuleset(t, twoPeerClusterRC(), []link.ResolvedForward{forwardB}))
	afterListing := listTable(ctx, t, ctr)

	wantDNAT := dnatRuleFor(forwardB)
	if !strings.Contains(afterListing, wantDNAT) {
		t.Errorf("after retarget: DNAT to ClusterIP_B missing: %q\n%s", wantDNAT, afterListing)
	}
	wantAccept := acceptRuleFor(forwardB)
	if !strings.Contains(afterListing, wantAccept) {
		t.Errorf("after retarget: forward accept rule for daddr B missing: %q\n%s", wantAccept, afterListing)
	}

	assertClusterForwardRules(ctx, t, ctr, []link.ResolvedForward{forwardB}, "after retarget")
	if got := countDNATRules(afterListing); got != 1 {
		t.Errorf("after retarget: DNAT rule count = %d, want 1 (the single retargeted forward)\n%s", got, afterListing)
	}
}

// twoPeerClusterRC is the Cluster-mode fixture every rendering test in this package uses:
// two live members, exercising RenderNftables against a multi-peer WireGuard.Peers list.
func twoPeerClusterRC() link.RuntimeConfig {
	return link.RuntimeConfig{
		WireGuard: link.WireGuard{
			Peers: []link.Peer{
				{Slot: 0, PublicKey: "PUBA=", Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"10.99.0.2/32"}},
				{Slot: 1, PublicKey: "PUBB=", Endpoint: "203.0.113.2:51820", AllowedIPs: []string{"10.99.0.3/32"}},
			},
		},
	}
}

func startNftContainer(ctx context.Context, t testing.TB) testcontainers.Container {
	t.Helper()
	ctr := netns.Start(ctx, t)
	createWG0(ctx, t, ctr)
	return ctr
}

// createWG0 adds a dummy wg0: the rules match `iif "wg0"`, which nft resolves to an
// interface index at load time and rejects when the device is absent.
func createWG0(ctx context.Context, t testing.TB, ctr testcontainers.Container) {
	t.Helper()
	code, out := netns.Exec(ctx, t, ctr, "ip", "link", "add", "wg0", "type", "dummy")
	if code != 0 {
		t.Fatalf("ip link add wg0 failed (exit %d):\n%s", code, out)
	}
}

// renderRuleset renders forwards through RenderNftables as a replica with no node name would; a
// Local caller exercising Responders uses renderRulesetOnNode instead.
func renderRuleset(t testing.TB, rc link.RuntimeConfig, forwards []link.ResolvedForward) string {
	t.Helper()
	return renderRulesetOnNode(t, rc, forwards, "")
}

// renderRulesetOnNode is renderRuleset with the node name RenderNftables uses to pick this
// replica's entry from rc.Responders.
func renderRulesetOnNode(t testing.TB, rc link.RuntimeConfig, forwards []link.ResolvedForward, nodeName string) string {
	t.Helper()
	out, err := link.RenderNftables(rc, forwards, nodeName)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	return out
}

func listTable(ctx context.Context, t testing.TB, ctr testcontainers.Container) string {
	t.Helper()
	return netns.List(ctx, t, ctr, "table", "inet", "gateway")
}

// countDNATRules counts the DNAT rule lines in an `nft list table` dump. Each
// forward renders exactly one, so the count equals the forwards programmed.
func countDNATRules(listing string) int {
	return strings.Count(listing, "dnat ip to")
}

// dnatRuleFor returns the prerouting DNAT statement RenderNftables emits for f, as
// it appears in `nft list table` output.
func dnatRuleFor(f link.ResolvedForward) string {
	return fmt.Sprintf("%s dport %d dnat ip to %s:%d", f.Protocol, f.PublicPort, f.Target, f.TargetPort)
}

// acceptRuleFor keys on the post-DNAT destination (ClusterIP and target port), so a
// retarget must move the accept in lockstep with the DNAT.
func acceptRuleFor(f link.ResolvedForward) string {
	return fmt.Sprintf("iif \"wg0\" ip daddr %s %s dport %d accept", f.Target, f.Protocol, f.TargetPort)
}

var nftRuleNoise = regexp.MustCompile(` counter packets \d+ bytes \d+| comment "[^"]*"| # handle \d+`)

func assertClusterForwardRules(ctx context.Context, t testing.TB, ctr testcontainers.Container, forwards []link.ResolvedForward, stage string) {
	t.Helper()
	want := clusterForwardRules(forwards)
	got := append(nftChainRuleExpressions(ctx, t, ctr, "prerouting"), nftChainRuleExpressions(ctx, t, ctr, "forward")...)
	if !slices.Equal(got, want) {
		t.Errorf("cluster forwarding rules %s = %v, want %v", stage, got, want)
	}
}

func clusterForwardRules(forwards []link.ResolvedForward) []string {
	want := make([]string, 0, len(forwards)*2+2)
	for _, forward := range forwards {
		want = append(want, "prerouting: iif \"wg0\" "+dnatRuleFor(forward))
	}
	want = append(want,
		"forward: oifname \"wg0\" tcp flags syn tcp option maxseg size set rt mtu",
		"forward: ct state established,related accept",
	)
	for _, forward := range forwards {
		want = append(want, "forward: "+acceptRuleFor(forward))
	}
	return want
}

func nftChainRuleExpressions(ctx context.Context, t testing.TB, ctr testcontainers.Container, chain string) []string {
	t.Helper()
	listing := netns.List(ctx, t, ctr, "chain", "inet", "gateway", chain)
	rules := []string{}
	for line := range strings.SplitSeq(listing, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "}" || strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "chain ") || strings.HasPrefix(line, "type ") {
			continue
		}
		line = strings.TrimSpace(nftRuleNoise.ReplaceAllString(line, ""))
		rules = append(rules, chain+": "+strings.Join(strings.Fields(line), " "))
	}
	return rules
}
