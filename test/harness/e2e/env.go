// Package e2e wires the gateway end-to-end harness: a kind cluster, Crossplane core
// plus the GCP/Kubernetes providers, and the gateway chart provisioning a real GCP
// gateway. It runs only under GATEWAY_E2E and is not part of `go test ./...`.
package e2e

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/shared"
)

// Env holds the GCP configuration the suite reads from the process
// environment. `make test-e2e` (and the operator) source these from .env.
type Env struct {
	// ProjectID is the GCP project that owns the gateway VM, its network, and its
	// Secret Manager secret.
	ProjectID string
	Region    string
	Zone      string
	// CredsFile is the path to the provider-gcp service-account JSON key, loaded
	// into the cluster as the crossplane creds Secret.
	CredsFile string
	// CredsNamespace is the creds Secret's namespace. Defaults to crossplane-system.
	CredsNamespace string
	// CredsSecret is the creds Secret name crossplane-config consumes. Defaults to
	// gcp-creds.
	CredsSecret string
	// Keep skips all teardown so the cluster and GCP VM survive for debugging. Unlike
	// GATEWAY_E2E_PRESERVE it ignores failure and leaks the VM until drained by hand; not for CI.
	Keep bool
}

// Environment variable names the suite reads.
const (
	envProjectID      = "GCP_PROJECT_ID"
	envRegion         = "GCP_REGION"
	envZone           = "GCP_ZONE"
	envCredsFile      = "GCP_CREDS_FILE"
	envCredsNamespace = "CROSSPLANE_NAMESPACE"
	envCredsSecret    = "CROSSPLANE_CREDS_SECRET"

	// EnvUseExisting, when set, makes the suite deploy into the cluster named
	// by $KUBECONFIG / the current context instead of creating a kind cluster.
	EnvUseExisting = "GATEWAY_E2E_USE_EXISTING"

	// EnvKeep, when set, makes the suite skip all teardown so the cluster and the
	// GCP gateway VM survive for live debugging. See Env.Keep.
	EnvKeep = "GATEWAY_E2E_KEEP"

	defaultCredsNamespace = "crossplane-system"
	defaultCredsSecret    = "gcp-creds"
)

// RequireEnv reads the GCP configuration, returning an error naming any missing or
// invalid variables. It returns the error rather than t.Fatal because it runs inside
// a sync.Once, where runtime.Goexit would abandon the once without a result.
func RequireEnv() (Env, error) {
	env := Env{
		ProjectID:      os.Getenv(envProjectID),
		Region:         os.Getenv(envRegion),
		Zone:           os.Getenv(envZone),
		CredsFile:      os.Getenv(envCredsFile),
		CredsNamespace: os.Getenv(envCredsNamespace),
		CredsSecret:    os.Getenv(envCredsSecret),
		Keep:           os.Getenv(EnvKeep) != "",
	}
	if env.CredsNamespace == "" {
		env.CredsNamespace = defaultCredsNamespace
	}
	if env.CredsSecret == "" {
		env.CredsSecret = defaultCredsSecret
	}

	var missing []string
	for name, val := range map[string]string{
		envProjectID: env.ProjectID,
		envRegion:    env.Region,
		envZone:      env.Zone,
		envCredsFile: env.CredsFile,
	} {
		if val == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Env{}, fmt.Errorf("GATEWAY_E2E is set but required GCP env vars are missing: %v "+
			"(source them from .env; see .env.example)", missing)
	}

	// Resolve a relative creds path against the repo root, not the test's working
	// directory, so direct `go test` and `make test-e2e` reach the same file.
	if !filepath.IsAbs(env.CredsFile) {
		env.CredsFile = filepath.Join(shared.RepoRoot(), env.CredsFile)
	}

	if _, err := os.Stat(env.CredsFile); err != nil {
		return Env{}, fmt.Errorf("%s=%q is not readable: %w", envCredsFile, env.CredsFile, err)
	}

	return env, nil
}

// useExisting reports whether the suite should target an existing cluster
// rather than provisioning a kind cluster.
func useExisting() bool {
	return os.Getenv(EnvUseExisting) != ""
}

// readCredsJSON reads the service-account key bytes from the configured path.
func (e Env) readCredsJSON() ([]byte, error) {
	data, err := os.ReadFile(e.CredsFile)
	if err != nil {
		return nil, fmt.Errorf("read creds file %s: %w", e.CredsFile, err)
	}
	return data, nil
}
