package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
)

// newGCPDiscoveryClient builds the real gcpdiscovery.Client; a package var so tests can
// inject a counting stub without widening gcpCredentialCache's exported surface.
var newGCPDiscoveryClient = gcpdiscovery.NewClient

// gcpCredentialCache rebuilds the discovery client only when the Secret's bytes change,
// so a rotated key is picked up without an operator restart.
type gcpCredentialCache struct {
	mu       sync.Mutex
	lastHash [32]byte
	hasHash  bool
	client   gcpdiscovery.Client
}

// clientFor rebuilds the cached client only when credential bytes change.
func (c *gcpCredentialCache) clientFor(ctx context.Context, apiReader client.Reader, secretNamespace, secretName, key string) (gcpdiscovery.Client, error) {
	secretID := secretNamespace + "/" + secretName

	var credentialJSON []byte
	if secretNamespace != "" {
		var secret corev1.Secret
		if err := apiReader.Get(ctx, client.ObjectKey{Namespace: secretNamespace, Name: secretName}, &secret); err != nil {
			return nil, fmt.Errorf("reading gcp credentials secret %q: %w", secretID, err)
		}
		raw, ok := secret.Data[key]
		if !ok || len(raw) == 0 {
			return nil, fmt.Errorf("gcp credentials secret %q: key %q is missing or empty", secretID, key)
		}
		credentialJSON = raw
	}

	hash := sha256.Sum256(credentialJSON)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hasHash && c.lastHash == hash {
		return c.client, nil
	}

	built, err := newGCPDiscoveryClient(ctx, credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("building gcp discovery client from secret %q: %w", secretID, err)
	}
	c.lastHash = hash
	c.hasHash = true
	c.client = built
	return c.client, nil
}

// parseCredentialsSecretRef accepts an empty setting or exactly "<namespace>/<name>".
func parseCredentialsSecretRef(setting string) (namespace, name string, err error) {
	if setting == "" {
		return "", "", nil
	}
	namespace, name, found := strings.Cut(setting, "/")
	if !found || namespace == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("gcp credentials secret %q: want \"<namespace>/<name>\"", setting)
	}
	return namespace, name, nil
}
