package linkint

// Startup discovery finds leftover interfaces outside the config; the first standby pass
// removes them.

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/netns"
)

const (
	// inLinkID is the link id the inherited-slot fixture derives every name from.
	inLinkID = 16
	// inCoResidentLinkID is a second Gateway on the same node, whose interface the discovery
	// must not claim.
	inCoResidentLinkID = 17
)

// TestInheritedSlotIsHeldAndTornDown handles a crashed holder's inherited slot.
func TestInheritedSlotIsHeldAndTornDown(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	gwIdent := link.NewGatewayIdentity(inLinkID)
	slot2 := link.NewSlotIdentity(inLinkID, 2)
	coResident := link.NewSlotIdentity(inCoResidentLinkID, 0)
	// The config the replacement replica loads: slot 0 alone, the fleet the operator now
	// renders, with slot 2's member long gone.
	current := link.RuntimeConfig{
		TrafficPolicy: link.TrafficPolicyLocal,
		Identity:      &gwIdent,
		WireGuard:     link.WireGuard{Peers: []link.Peer{{Slot: 0, PublicKey: "PUB0="}}},
	}

	ctr := netns.Start(ctx, t)

	addDummySlotInterface(ctx, t, ctr, slot2)
	programLocalRoutes(ctx, t, ctr, slot2, []string{lpPodIP})
	addDummySlotInterface(ctx, t, ctr, coResident)
	assertGatewayState(ctx, t, ctr, inLinkID, wantGatewayState(slot2), "as the crashed holder left the node")

	held := link.InheritedSlots(nodeLinkNames(ctx, t, ctr), inLinkID)
	if want := []int{2}; !slices.Equal(held, want) {
		t.Fatalf("inherited slots = %v, want %v", held, want)
	}

	// The standby's first pass: every held slot the config does not list is torn down, and no
	// slot is brought up.
	inherited := current
	inherited.WireGuard.Peers = []link.Peer{{Slot: 2, PublicKey: "PUB2="}}
	runDepartedTeardown(ctx, t, ctr, inherited, link.RuntimeConfig{})

	// The pass tore slot 2 down and brought slot 0 up nowhere: a standby holds no slot.
	assertGatewayState(ctx, t, ctr, inLinkID, wantGatewayState(), "after the standby's first pass")
	if got := gatewayInterfaces(ctx, t, ctr, inCoResidentLinkID); !slices.Equal(got, []string{coResident.Interface}) {
		t.Errorf("co-resident gateway %d interfaces = %v, want %v", inCoResidentLinkID, got, []string{coResident.Interface})
	}
}

// nodeLinkNames is the enumeration of the node's link names the startup discovery reads.
func nodeLinkNames(ctx context.Context, t testing.TB, ctr testcontainers.Container) []string {
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
	names := make([]string, 0, len(links))
	for _, l := range links {
		names = append(names, l.IfName)
	}
	return names
}
