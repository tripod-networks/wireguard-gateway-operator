package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/stretchr/testify/mock"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
	gcpdiscoverymocks "github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery/mocks"
)

func fakeClientWithSecret(t *testing.T, namespace, name, key string, data []byte) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data:       map[string][]byte{key: data},
	}
	return fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
}

// stubbedConstructor replaces newGCPDiscoveryClient for the test's lifetime and reports how
// many times it was invoked, restoring the original on cleanup.
func stubbedConstructor(t *testing.T) *int {
	t.Helper()
	calls := 0
	orig := newGCPDiscoveryClient
	newGCPDiscoveryClient = func(_ context.Context, _ []byte) (gcpdiscovery.Client, error) {
		calls++
		client := gcpdiscoverymocks.NewMockClient(t)
		client.EXPECT().List(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(gcpdiscovery.Snapshot{}, nil).Maybe()
		return client, nil
	}
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	return &calls
}

func TestGCPCredentialCacheRebuildsOnChangedBytes(t *testing.T) {
	calls := stubbedConstructor(t)
	ctx := context.Background()
	cl := fakeClientWithSecret(t, "crossplane-system", "gcp-creds", "credentials.json", []byte("v1"))

	var cache gcpCredentialCache
	first, err := cache.clientFor(ctx, cl, "crossplane-system", "gcp-creds", "credentials.json")
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}

	var secret corev1.Secret
	if err := cl.Get(ctx, client.ObjectKey{Namespace: "crossplane-system", Name: "gcp-creds"}, &secret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	secret.Data["credentials.json"] = []byte("v2")
	if err := cl.Update(ctx, &secret); err != nil {
		t.Fatalf("update secret: %v", err)
	}

	second, err := cache.clientFor(ctx, cl, "crossplane-system", "gcp-creds", "credentials.json")
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}

	if *calls != 2 {
		t.Errorf("constructor calls = %d, want 2", *calls)
	}
	if first == second {
		t.Errorf("client rebuilt on changed bytes: got the same instance twice")
	}
}

func TestGCPCredentialCacheKeepsClientOnUnchangedBytes(t *testing.T) {
	calls := stubbedConstructor(t)
	ctx := context.Background()
	cl := fakeClientWithSecret(t, "crossplane-system", "gcp-creds", "credentials.json", []byte("v1"))

	var cache gcpCredentialCache
	first, err := cache.clientFor(ctx, cl, "crossplane-system", "gcp-creds", "credentials.json")
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}
	second, err := cache.clientFor(ctx, cl, "crossplane-system", "gcp-creds", "credentials.json")
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}

	if *calls != 1 {
		t.Errorf("constructor calls = %d, want 1", *calls)
	}
	if first != second {
		t.Errorf("client rebuilt on unchanged bytes: got distinct instances")
	}
}

// TestParseCredentialsSecretRef covers GATEWAY_GCP_CREDENTIALS_SECRET's shape: empty selects
// ambient credentials, anything else must name both a namespace and a name.
func TestParseCredentialsSecretRef(t *testing.T) {
	tests := []struct {
		name          string
		setting       string
		wantNamespace string
		wantName      string
		wantErr       bool
	}{
		{name: "empty selects ambient credentials", setting: ""},
		{name: "namespace and name", setting: "ns/name", wantNamespace: "ns", wantName: "name"},
		{name: "bare name", setting: "name", wantErr: true},
		{name: "extra slash", setting: "a/b/c", wantErr: true},
		{name: "empty namespace", setting: "/name", wantErr: true},
		{name: "empty name", setting: "ns/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace, name, err := parseCredentialsSecretRef(tt.setting)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseCredentialsSecretRef(%q) error = nil, want an error", tt.setting)
				}
				if !strings.Contains(err.Error(), tt.setting) || !strings.Contains(err.Error(), "<namespace>/<name>") {
					t.Errorf("error = %q, want it to name %q and the expected shape", err, tt.setting)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCredentialsSecretRef(%q): %v", tt.setting, err)
			}
			if namespace != tt.wantNamespace || name != tt.wantName {
				t.Errorf("parseCredentialsSecretRef(%q) = (%q, %q), want (%q, %q)",
					tt.setting, namespace, name, tt.wantNamespace, tt.wantName)
			}
		})
	}
}
