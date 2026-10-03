package e2e

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/k8s"
)

// operatorValues is the e2e overlay layered over the chart's values.yaml: images and
// nameOverride only, since every per-Gateway field lives on the Gateway CR.
type operatorValues struct {
	NameOverride string        `yaml:"nameOverride"`
	Operator     operatorBlock `yaml:"operator"`
	Link         imageBlock    `yaml:"link"`
	Responder    imageBlock    `yaml:"responder"`
}

type operatorBlock struct {
	Image imageValues `yaml:"image"`
}

type imageBlock struct {
	Image imageValues `yaml:"image"`
}

type imageValues struct {
	Repository string `yaml:"repository"`
	Tag        string `yaml:"tag"`
}

// valuesParams bundles the inputs that shape the operator overlay.
type valuesParams struct {
	nameOverride string
	// operatorImage and linkImage are the run's freshly built, kind-loaded images.
	operatorImage k8s.ImageRef
	linkImage     k8s.ImageRef
	// responderImage is the harness's pulled, kind-loaded default responder image.
	responderImage k8s.ImageRef
}

// writeValues renders the operator chart overlay to a temp file and returns its path, for the
// caller to pass to helm via -f.
func writeValues(dir string, p valuesParams) (string, error) {
	v := operatorValues{
		NameOverride: p.nameOverride,
		Operator: operatorBlock{
			Image: imageValues{Repository: p.operatorImage.Repository, Tag: p.operatorImage.Tag},
		},
		Link: imageBlock{
			Image: imageValues{Repository: p.linkImage.Repository, Tag: p.linkImage.Tag},
		},
		Responder: imageBlock{
			Image: imageValues{Repository: p.responderImage.Repository, Tag: p.responderImage.Tag},
		},
	}

	data, err := yaml.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal operator values: %w", err)
	}
	path := filepath.Join(dir, p.nameOverride+"-values.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write operator values %s: %w", path, err)
	}
	return path, nil
}
