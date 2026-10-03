package k8s

import (
	"context"
	"fmt"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/shared"
)

// Helm drives helm releases against a single kube context, tee'ing each
// command's output to a per-release log under .test-output/.
type Helm struct {
	kubeCtx string
	repoDir string
	log     *zap.Logger
}

// NewHelm returns a Helm bound to the given kube context. repoDir is the
// repository root, used to resolve chart paths.
func NewHelm(kubeCtx, repoDir string, log *zap.Logger) *Helm {
	return &Helm{kubeCtx: kubeCtx, repoDir: repoDir, log: log}
}

// Install runs `helm upgrade --install` for one release. ValuesFiles are passed
// as -f in order (later files override earlier).
func (h *Helm) Install(ctx context.Context, rel ReleaseSpec) error {
	h.log.Info("helm install", zap.String("release", rel.Name), zap.String("namespace", rel.Namespace))
	rel.repoDir = h.repoDir

	args := []string{
		"upgrade", "--install", rel.Name, rel.chartRef(),
		"--namespace", rel.Namespace,
	}
	if rel.Wait {
		args = append(args, "--wait")
	}
	if h.kubeCtx != "" {
		args = append(args, "--kube-context", h.kubeCtx)
	}
	if rel.CreateNamespace {
		args = append(args, "--create-namespace")
	}
	if rel.Repo != "" {
		args = append(args, "--repo", rel.Repo)
	}
	if rel.Version != "" {
		args = append(args, "--version", rel.Version)
	}
	if rel.Timeout != "" {
		args = append(args, "--timeout", rel.Timeout)
	}
	for _, f := range rel.ValuesFiles {
		args = append(args, "-f", f)
	}
	for _, kv := range rel.SetValues {
		args = append(args, "--set", kv)
	}
	for _, kv := range rel.SetStringValues {
		args = append(args, "--set-string", kv)
	}

	logPath := filepath.Join(shared.TestOutputDir(), "helm-"+rel.Name+".log")
	out, err := shared.RunCmdTee(ctx, nil, logPath, "helm", args...)
	if err != nil {
		return fmt.Errorf("helm install %s: %w (full log: %s)\n%s", rel.Name, err, logPath, tail(out, 4000))
	}
	return nil
}

// Uninstall removes a release. Not-found is tolerated so teardown is
// idempotent.
func (h *Helm) Uninstall(ctx context.Context, name, namespace string) error {
	h.log.Info("helm uninstall", zap.String("release", name), zap.String("namespace", namespace))
	logPath := filepath.Join(shared.TestOutputDir(), "helm-uninstall-"+name+".log")
	args := []string{
		"uninstall", name,
		"--namespace", namespace,
		"--ignore-not-found",
		"--wait",
	}
	if h.kubeCtx != "" {
		args = append(args, "--kube-context", h.kubeCtx)
	}
	out, err := shared.RunCmdTee(ctx, nil, logPath, "helm", args...)
	if err != nil {
		return fmt.Errorf("helm uninstall %s: %w (full log: %s)\n%s", name, err, logPath, tail(out, 4000))
	}
	return nil
}

// ReleaseSpec describes one helm release.
type ReleaseSpec struct {
	Name            string
	Namespace       string
	CreateNamespace bool
	// Wait passes --wait, blocking until every release object is ready. Leave
	// unset when the caller polls readiness itself.
	Wait bool
	// ChartPath is the on-disk chart directory, relative to the repo root.
	// Mutually exclusive with RemoteChart.
	ChartPath string
	// RemoteChart is a chart name resolved from Repo. Mutually exclusive with
	// ChartPath.
	RemoteChart string
	// Repo is the chart repository URL for RemoteChart.
	Repo string
	// Version pins the chart version for remote charts.
	Version string
	// Timeout overrides helm's default --timeout (e.g. "5m").
	Timeout         string
	ValuesFiles     []string
	SetValues       []string
	SetStringValues []string

	repoDir string
}

func (r ReleaseSpec) chartRef() string {
	if r.RemoteChart != "" {
		return r.RemoteChart
	}
	if filepath.IsAbs(r.ChartPath) {
		return r.ChartPath
	}
	return filepath.Join(r.repoDir, r.ChartPath)
}

// tail returns the last n bytes of s, prefixed with an elision marker when
// truncated. Keeps error messages bounded; the full output is in the tee'd log.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "...(truncated; see log)...\n" + s[len(s)-n:]
}
