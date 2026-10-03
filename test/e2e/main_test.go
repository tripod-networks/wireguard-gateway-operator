package e2e_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	e2eharness "github.com/tripod-networks/wireguard-gateway-operator/test/harness/e2e"
)

// sharedNetworkDrainTimeout: run 35412850047 on 2026-09-19 needed longer than the previous
// 4 minutes to delete the auto-mode VPC; the run before it drained in about 30 seconds.
const sharedNetworkDrainTimeout = 10 * time.Minute

const sharedNetworkDrainInterval = 5 * time.Second

// TestMain gates the package on GATEWAY_E2E and runs Setup before m.Run, outside the -timeout
// alarm; Teardown follows m.Run, which returns only after every Stack's GCP drain completes.
func TestMain(m *testing.M) {
	if os.Getenv("GATEWAY_E2E") == "" {
		os.Exit(0)
	}
	sharedSuite, setupErr = e2eharness.Setup(context.Background())
	code := m.Run()
	if sharedSuite != nil {
		sharedSuite.Teardown(context.Background(), code)
		code = assertSharedNetworkDrained(sharedSuite, code)
	}
	os.Exit(code)
}

// assertSharedNetworkDrained polls until the refcounted shared VPC is gone; the per-stack orphan
// check filters by prefix and never sees it. Skipped on a failing run and under GATEWAY_E2E_KEEP.
func assertSharedNetworkDrained(suite *e2eharness.Suite, code int) int {
	if code != 0 || suite.Env().Keep {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), sharedNetworkDrainTimeout)
	defer cancel()
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "e2e: "+format+"\n", args...)
	}
	start := time.Now()
	err := e2eharness.WaitDrained(ctx, sharedNetworkDrainInterval, suite.SharedNetworkResidual, logf)
	if err != nil {
		attachments, attachErr := suite.SharedNetworkAttachments(context.Background())
		if attachErr != nil {
			attachments = fmt.Sprintf("attachment lookup failed: %v", attachErr)
		}
		fmt.Fprintf(os.Stderr,
			"e2e: shared network %q leaked: %v; still attached: %s\n",
			e2eharness.SharedNetworkName, err, attachments)
		return 1
	}
	logf("shared network %q drained in %.0fs", e2eharness.SharedNetworkName, time.Since(start).Seconds())
	return code
}

// sharedSuite is built by TestMain before m.Run; parallel tests share the handle and
// a failed Setup fails each test in getSuite.
var (
	sharedSuite *e2eharness.Suite
	setupErr    error
)

// getSuite returns the suite TestMain built, failing the test when Setup failed.
func getSuite(t *testing.T) *e2eharness.Suite {
	t.Helper()
	if setupErr != nil {
		t.Fatalf("e2e suite setup: %v", setupErr)
	}
	return sharedSuite
}
