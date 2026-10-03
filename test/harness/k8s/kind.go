// Package k8s holds the gateway e2e harness drivers: the kind cluster, the Kubernetes
// API client, and the helm releases that deploy Crossplane and the gateway chart.
package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"time"

	"go.uber.org/zap"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	kindcmd "sigs.k8s.io/kind/pkg/cmd"

	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/shared"
)

// e2eClusterName is the kind cluster the e2e suite provisions.
const e2eClusterName = "gateway-e2e"

const (
	// kindReadyTimeout bounds the wait for every node to report Ready. Three nodes join
	// well inside it; exceeding it is a broken environment, not a slow one.
	kindReadyTimeout = 5 * time.Minute
	nodeExecTimeout  = 30 * time.Second
)

// Watch detection plus a 10s sync floor caps the mounted-ConfigMap lag, so a post-Ready
// forward edit reaches the link pod in time.
const kubeletConfigPatch = `apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
syncFrequency: 10s
configMapAndSecretChangeDetectionStrategy: Watch
`

// KindCluster manages the e2e kind cluster lifecycle via the kind Go API.
type KindCluster struct {
	name     string
	provider *cluster.Provider
	log      *zap.Logger
}

// NewKindCluster returns a KindCluster handle. Call Ensure to create the
// cluster.
func NewKindCluster(log *zap.Logger) *KindCluster {
	return &KindCluster{
		name: e2eClusterName,
		provider: cluster.NewProvider(
			cluster.ProviderWithLogger(kindcmd.NewLogger()),
			cluster.ProviderWithDocker(),
		),
		log: log,
	}
}

// Name returns the cluster name.
func (k *KindCluster) Name() string { return k.name }

// KubeContext returns the kubectl context name for this cluster.
func (k *KindCluster) KubeContext() string { return "kind-" + k.name }

// Ensure creates the cluster if it does not already exist. Idempotent: a
// pre-existing cluster of the same name is reused.
func (k *KindCluster) Ensure(_ context.Context) error {
	existing, err := k.provider.List()
	if err != nil {
		return fmt.Errorf("kind list clusters: %w", err)
	}
	if slices.Contains(existing, k.name) {
		k.log.Info("kind cluster already exists", zap.String("cluster", k.name))
		return nil
	}
	k.log.Info("creating kind cluster", zap.String("cluster", k.name))
	// kind clears the control-plane NoSchedule taint only for a single-node cluster, so
	// with workers present every workload lands on the two workers.
	config := &v1alpha4.Cluster{
		Nodes: []v1alpha4.Node{
			{Role: v1alpha4.ControlPlaneRole, KubeadmConfigPatches: []string{kubeletConfigPatch}},
			{Role: v1alpha4.WorkerRole, KubeadmConfigPatches: []string{kubeletConfigPatch}},
			{Role: v1alpha4.WorkerRole, KubeadmConfigPatches: []string{kubeletConfigPatch}},
		},
	}
	if err := k.provider.Create(k.name,
		cluster.CreateWithV1Alpha4Config(config),
		// Wait for every node to report Ready before the charts install, so a
		// DaemonSet readiness assertion cannot race a worker still joining.
		cluster.CreateWithWaitForReady(kindReadyTimeout),
	); err != nil {
		return fmt.Errorf("kind create cluster %s: %w", k.name, err)
	}
	return nil
}

// KubeConfigBytes returns the cluster's kubeconfig as raw YAML.
func (k *KindCluster) KubeConfigBytes() ([]byte, error) {
	raw, err := k.provider.KubeConfig(k.name, false)
	if err != nil {
		return nil, fmt.Errorf("kind kubeconfig %s: %w", k.name, err)
	}
	return []byte(raw), nil
}

// ExportKubeConfig writes the cluster's kubeconfig to path.
func (k *KindCluster) ExportKubeConfig(path string) error {
	if err := k.provider.ExportKubeConfig(k.name, path, false); err != nil {
		return fmt.Errorf("kind export kubeconfig: %w", err)
	}
	return nil
}

// Delete removes the cluster. Safe to call when the cluster does not exist.
func (k *KindCluster) Delete(_ context.Context) error {
	k.log.Info("deleting kind cluster", zap.String("cluster", k.name))
	if err := k.provider.Delete(k.name, ""); err != nil {
		return fmt.Errorf("kind delete cluster %s: %w", k.name, err)
	}
	return nil
}

// Nodes returns the node container names for per-node setup steps. The list comes from
// the kind provider, not a hardcoded suffix, so it tracks the node set.
func (k *KindCluster) Nodes() ([]string, error) {
	names, err := k.provider.ListNodes(k.name)
	if err != nil {
		return nil, fmt.Errorf("kind list nodes %s: %w", k.name, err)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n.String())
	}
	return out, nil
}

// LoadImage side-loads a local docker image into the cluster's nodes by shelling out, since the
// Go API does not expose image loading and kind must be on PATH. It writes a single-platform
// archive to work around containerd image store multi-platform indexes, which `kind load
// docker-image` fails on (kind issue 3795).
func (k *KindCluster) LoadImage(ctx context.Context, imageRef string) error {
	platform := "linux/" + runtime.GOARCH
	k.log.Info("loading image into kind cluster",
		zap.String("cluster", k.name),
		zap.String("image", imageRef),
		zap.String("platform", platform),
	)

	f, err := os.CreateTemp("", "kind-image-*.tar")
	if err != nil {
		return fmt.Errorf("create image archive temp file: %w", err)
	}
	archivePath := f.Name()
	if err := f.Close(); err != nil {
		return fmt.Errorf("close image archive temp file %s: %w", archivePath, err)
	}
	defer func() {
		if err := os.Remove(archivePath); err != nil {
			k.log.Warn("failed to remove image archive temp file",
				zap.String("path", archivePath), zap.Error(err))
		}
	}()

	if out, err := shared.RunCmd(ctx, nil, "docker", "image", "save",
		"--platform", platform, "-o", archivePath, imageRef); err != nil {
		return fmt.Errorf("docker image save %s: %w\n%s", imageRef, err, out)
	}

	out, err := shared.RunCmd(ctx, nil, "kind", "load", "image-archive",
		archivePath, "--name", k.name)
	if err != nil {
		return fmt.Errorf("kind load image-archive %s: %w\n%s", imageRef, err, out)
	}
	return nil
}

// NodeExec runs argv in the kind node's container and returns its combined output.
// The call is bounded by nodeExecTimeout: a wedged node must not consume the failure
// cleanup budget, which the GCP orphan drain shares.
func NodeExec(ctx context.Context, node string, argv ...string) (string, error) {
	return nodeExec(ctx, shared.RunCmd, node, argv...)
}

// NodeExecStdout is NodeExec returning stdout alone, for output that is parsed: a
// command's stderr warnings would otherwise parse as data.
func NodeExecStdout(ctx context.Context, node string, argv ...string) (string, error) {
	return nodeExec(ctx, shared.RunCmdStdout, node, argv...)
}

func nodeExec(
	ctx context.Context,
	run func(context.Context, []string, string, ...string) (string, error),
	node string,
	argv ...string,
) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("docker exec %s: no argv", node)
	}
	cctx, cancel := context.WithTimeout(ctx, nodeExecTimeout)
	defer cancel()
	out, err := run(cctx, nil, "docker", append([]string{"exec", node}, argv...)...)
	if err != nil {
		if ctx.Err() == nil && errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return out, fmt.Errorf("docker exec %s %s: timed out after %s: %w", node, argv[0], nodeExecTimeout, err)
		}
		return out, fmt.Errorf("docker exec %s %s: %w", node, argv[0], err)
	}
	return out, nil
}
