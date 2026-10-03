package k8s

import (
	"context"
	"fmt"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/shared"
)

// ImageRef is a built image's repository and tag, split for the chart's
// image.repository / image.tag values.
type ImageRef struct {
	Repository string
	Tag        string
}

// Ref returns the full repository:tag reference.
func (r ImageRef) Ref() string { return r.Repository + ":" + r.Tag }

// BuildImage builds the named multi-stage target from build/package/Dockerfile into
// the local docker store with a run-unique tag and returns its reference. Nothing is
// pushed, so LoadImage must side-load it into kind.
func BuildImage(ctx context.Context, repoDir, repository, tag, target string, log *zap.Logger) (ImageRef, error) {
	ref := ImageRef{Repository: repository, Tag: tag}
	log.Info("docker build image", zap.String("ref", ref.Ref()), zap.String("target", target))

	logPath := filepath.Join(shared.TestOutputDir(), "docker-build-"+target+"-"+tag+".log")
	out, err := shared.RunCmdTee(ctx, nil, logPath,
		"docker", "build",
		"-f", filepath.Join(repoDir, "build", "package", "Dockerfile"),
		"--target", target,
		"-t", ref.Ref(),
		repoDir,
	)
	if err != nil {
		return ImageRef{}, fmt.Errorf("docker build %s target: %w (full log: %s)\n%s", target, err, logPath, tail(out, 4000))
	}
	return ref, nil
}
