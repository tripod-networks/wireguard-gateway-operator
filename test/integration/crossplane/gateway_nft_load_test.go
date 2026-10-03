package crossplane

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/netns"
)

// TestGatewayNftLoadsIntoKernel loads the ruleset into a real nft so a syntax
// error or a construct this kernel rejects fails here, not on a booting gateway.
func TestGatewayNftLoadsIntoKernel(t *testing.T) {
	if os.Getenv("GATEWAY_INTEGRATION") == "" {
		t.Skip("set GATEWAY_INTEGRATION to run the nft kernel-load integration test")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	ctr := netns.Start(ctx, t)

	for _, mode := range nftModes {
		t.Run(mode.name, func(t *testing.T) {
			// The file has no add/flush prelude, so each mode needs a cleared netns.
			if code, out := netns.Exec(ctx, t, ctr, "nft", "flush", "ruleset"); code != 0 {
				t.Fatalf("nft flush ruleset failed (exit %d):\n%s", code, out)
			}

			netns.Apply(ctx, t, ctr, renderGatewayNft(t, mode.verdict))
			t.Logf("kernel ruleset after load:\n%s", netns.List(ctx, t, ctr, "ruleset"))

			// Scoped to the gateway table so the assertion cannot latch onto
			// another table's prerouting chain.
			table := netns.List(ctx, t, ctr, "table", "inet", "gateway")
			assertPreroutingOrder(t, preroutingChain(t, table))

			if strings.Contains(table, "masquerade") != (mode.verdict == "masquerade") {
				t.Errorf("traffic policy %s: kernel table masquerade presence wrong after nft's normalisation:\n%s",
					mode.policy, table)
			}
		})
	}
}
