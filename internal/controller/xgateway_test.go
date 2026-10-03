package controller

import (
	"encoding/base32"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpmembers"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

func TestGCPID(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		objName   string
	}{
		{"short", "default", "gw1"},
		{"long names", "a-very-long-namespace-name", "an-equally-long-gateway-resource-name"},
		{"unicode-ish", "ns", "gateway-with-dashes-and-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gcpID(tt.namespace, tt.objName)

			if len(got) > gcpIDMaxLen {
				t.Fatalf("gcpID length = %d, want <= %d (%q)", len(got), gcpIDMaxLen, got)
			}
			if !strings.HasPrefix(got, gcpIDPrefix) {
				t.Fatalf("gcpID = %q, want prefix %q", got, gcpIDPrefix)
			}
			if got[0] < 'a' || got[0] > 'z' {
				t.Fatalf("gcpID = %q, want leading letter", got)
			}
			body := strings.TrimPrefix(got, gcpIDPrefix)
			for _, r := range body {
				isLower := r >= 'a' && r <= 'z'
				isB32Digit := r >= '2' && r <= '7'
				if !isLower && !isB32Digit {
					t.Fatalf("gcpID body %q has out-of-charset rune %q (want [a-z2-7])", body, r)
				}
			}

			if again := gcpID(tt.namespace, tt.objName); again != got {
				t.Fatalf("gcpID not deterministic: %q then %q", got, again)
			}
		})
	}

	t.Run("namespace qualified", func(t *testing.T) {
		a := gcpID("ns-a", "gw")
		b := gcpID("ns-b", "gw")
		if a == b {
			t.Fatalf("gcpID collides across namespaces: %q", a)
		}
	})
}

func TestBuildXGatewayGCP(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP},
		},
		[]string{"edge.example.com"},
	)

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	if got := u.GetAPIVersion(); got != xgatewayGCPAPIVersion {
		t.Errorf("apiVersion = %q, want %q", got, xgatewayGCPAPIVersion)
	}
	if got := u.GetKind(); got != xgatewayGCPKind {
		t.Errorf("kind = %q, want %q", got, xgatewayGCPKind)
	}
	if got := u.GetName(); got != "edge" {
		t.Errorf("name = %q, want edge", got)
	}
	if got := u.GetNamespace(); got != "wg-system" {
		t.Errorf("namespace = %q, want wg-system", got)
	}

	assertNestedString(t, u, "us-central1", "spec", "region")
	assertNestedString(t, u, "us-central1-a", "spec", "zone")
	assertNestedString(t, u, "e2-small", "spec", "machineType")
	assertNestedString(t, u, cfg.UserData, "spec", "userData")

	// sharedNetworkName flows from operator config; every other input flows from
	// gw.Spec (here all defaulted).
	assertNestedString(t, u, cfg.SharedNetworkName, "spec", "sharedNetworkName")
	assertNestedString(t, u, cfg.ProviderConfigName, "spec", "providerConfigName")

	assertNestedString(t, u, "test-project", "spec", "projectID")
	assertNestedString(t, u, effectiveGCPImage(gw), "spec", "image")
	assertNestedString(t, u, effectiveWGGatewayAddress(gw), "spec", "wgGatewayAddress")
	assertNestedString(t, u, effectiveWGLinkAddress(gw), "spec", "wgLinkAddress")
	assertNestedString(t, u, effectiveWGSubnet(gw), "spec", "wgSubnet")

	wantWGPort := int64(effectiveWireguardPort(gw))
	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgListenPort"); got != wantWGPort {
		t.Errorf("wgListenPort = %d, want %d", got, wantWGPort)
	}
	wantWGMTU := int64(effectiveWGMTU(gw))
	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgMTU"); got != wantWGMTU {
		t.Errorf("wgMTU = %d, want %d", got, wantWGMTU)
	}
	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "diskSizeGB"); got != int64(effectiveGCPDiskSizeGB(gw)) {
		t.Errorf("diskSizeGB = %d, want %d", got, effectiveGCPDiskSizeGB(gw))
	}
	wantAddr := map[string]any{"type": "Reserved"}
	gotAddr, found, err := unstructured.NestedMap(u.Object, "spec", "address")
	if err != nil || !found {
		t.Fatalf("read spec.address: found=%v err=%v", found, err)
	}
	if !reflect.DeepEqual(gotAddr, wantAddr) {
		t.Errorf("spec.address = %#v, want %#v", gotAddr, wantAddr)
	}
	if got, _, _ := unstructured.NestedBool(u.Object, "spec", "enableOsLogin"); got != cfg.EnableOSLogin {
		t.Errorf("enableOsLogin = %v, want %v", got, cfg.EnableOSLogin)
	}

	assertNestedString(t, u, gcpID(gw.Namespace, gw.Name), "spec", "serviceAccountId")
	assertNestedString(t, u, testRecordNameBase(t, gw), "spec", "secretId")

	ports, _, err := unstructured.NestedSlice(u.Object, "spec", "allowedPorts")
	if err != nil {
		t.Fatalf("read allowedPorts: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("allowedPorts len = %d, want 2", len(ports))
	}
	byPort := map[int64]string{}
	for _, raw := range ports {
		p, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("allowedPort entry is %T, want map", raw)
		}
		port, ok := p["port"].(int64)
		if !ok {
			t.Fatalf("allowedPort port is %T, want int64", p["port"])
		}
		proto, _ := p["protocol"].(string)
		byPort[port] = proto
	}
	if byPort[443] != "tcp" {
		t.Errorf("allowedPort 443 protocol = %q, want tcp (lowercased)", byPort[443])
	}
	if byPort[1194] != "udp" {
		t.Errorf("allowedPort 1194 protocol = %q, want udp (lowercased)", byPort[1194])
	}

	if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "status"); found {
		t.Errorf("buildXGatewayGCP must not set status; serviceAccountEmail is GCP-observed")
	}
}

// TestBuildXGatewayGCPAddress pins the 1:1 mapping from spec.gcp.address to the composite's
// spec.address for each form, including the zero block's Reserved default.
func TestBuildXGatewayGCPAddress(t *testing.T) {
	cfg := testConfig()
	tests := []struct {
		name string
		addr wgnetv1alpha1.GatewayGCPAddressSpec
		want map[string]any
	}{
		{
			name: "zero block defaults to Reserved",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{},
			want: map[string]any{"type": "Reserved"},
		},
		{
			name: "explicit reserved",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressReserved},
			want: map[string]any{"type": "Reserved"},
		},
		{
			name: "ephemeral",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressEphemeral},
			want: map[string]any{"type": "Ephemeral"},
		},
		{
			name: "external by name",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{
				Type:     wgnetv1alpha1.GatewayGCPAddressExternal,
				External: &wgnetv1alpha1.GatewayGCPExternalAddress{Name: "prod-edge-ip"},
			},
			want: map[string]any{"type": "External", "external": map[string]any{"name": "prod-edge-ip"}},
		},
		{
			name: "external by ip",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{
				Type:     wgnetv1alpha1.GatewayGCPAddressExternal,
				External: &wgnetv1alpha1.GatewayGCPExternalAddress{IP: "34.76.10.20"},
			},
			want: map[string]any{"type": "External", "external": map[string]any{"ip": "34.76.10.20"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.GCP.Address = tt.addr

			u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			got, found, err := unstructured.NestedMap(u.Object, "spec", "address")
			if err != nil || !found {
				t.Fatalf("read spec.address: found=%v err=%v", found, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("spec.address = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestTemplateRevision verifies template-affecting inputs change the revision.
func TestTemplateRevision(t *testing.T) {
	cfg := testConfig()
	base := func(t *testing.T, gw *wgnetv1alpha1.Gateway) string {
		t.Helper()
		return testRecordNameBase(t, gw)
	}

	tests := []struct {
		name          string
		mutate        func(gw *wgnetv1alpha1.Gateway)
		wantIdentical bool
	}{
		{name: "unchanged inputs", mutate: func(*wgnetv1alpha1.Gateway) {}, wantIdentical: true},
		{name: "same name, new uid", mutate: func(gw *wgnetv1alpha1.Gateway) {
			gw.UID = types.UID("99998888-7777-6666-5555-444433332222")
		}},
		{name: "new project", mutate: func(gw *wgnetv1alpha1.Gateway) { gw.Spec.GCP.ProjectID = "other-project" }},
		{name: "new machine type", mutate: func(gw *wgnetv1alpha1.Gateway) { gw.Spec.GCP.MachineType = "e2-medium" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			first := templateRevision(gw, cfg, base(t, gw))

			other := newGateway("edge", "wg-system", nil, nil)
			tt.mutate(other)
			second := templateRevision(other, cfg, base(t, other))

			if identical := first == second; identical != tt.wantIdentical {
				t.Errorf("templateRevision = %q and %q, identical=%v, want identical=%v",
					first, second, identical, tt.wantIdentical)
			}
		})
	}
}

// testRecordNameBase is the record naming base the VM reads as its "secret-id" metadata
// value and suffixes with its own name to derive its bundle id.
func testRecordNameBase(t *testing.T, gw *wgnetv1alpha1.Gateway) string {
	t.Helper()
	base, err := gcpmembers.NameBase(string(gw.UID), gw.Spec.GCP.ProjectID)
	if err != nil {
		t.Fatalf("gcpmembers.NameBase(...) returned unexpected error: %v", err)
	}
	return base
}

// TestBuildXGatewayGCPBranches verifies the composite for both provisioning branches.
func TestBuildXGatewayGCPBranches(t *testing.T) {
	cfg := testConfig()
	singleInstanceKeys := []string{
		"address", "crossplane", "diskSizeGB", "enableOsLogin", "image", "machineType",
		"projectID", "providerConfigName", "region", "secretId", "serviceAccountId",
		"sharedNetworkName", "spot", "trafficPolicy", "userData", "wgGatewayAddress",
		"wgLinkAddress", "wgListenPort", "wgMTU", "wgSubnet", "zone",
	}
	loadBalancedKeys := append(append([]string{}, singleInstanceKeys...),
		"healthPort", "loadBalanced", "members", "sessionAffinity", "targetSize",
		"templateRevision", "zones")
	slices.Sort(loadBalancedKeys)

	roster := func(t *testing.T, gw *wgnetv1alpha1.Gateway, name string) []gcpmembers.RosterEntry {
		t.Helper()
		names, err := gcpmembers.NameResourceNames(string(gw.UID), gw.Spec.GCP.ProjectID, name)
		if err != nil {
			t.Fatalf("gcpmembers.NameResourceNames(...) returned unexpected error: %v", err)
		}
		return []gcpmembers.RosterEntry{{Name: name, Slot: 0, TunnelAddress: "10.99.0.1", ManagedResourceNames: names}}
	}

	tests := []struct {
		name           string
		loadBalanced   bool
		replicas       int32
		result         func(t *testing.T, gw *wgnetv1alpha1.Gateway) *gcpmembers.Result
		wantKeys       []string
		wantTargetSize int64
		wantMembers    []any
	}{
		{
			name:     "single instance without an observed name renders no roster",
			wantKeys: singleInstanceKeys,
		},
		{
			name: "single instance with an observed name renders one member",
			result: func(t *testing.T, gw *wgnetv1alpha1.Gateway) *gcpmembers.Result {
				return &gcpmembers.Result{Roster: roster(t, gw, "gw-edge-9x2k")}
			},
			wantKeys:    slices.Sorted(slices.Values(append(append([]string{}, singleInstanceKeys...), "members"))),
			wantMembers: []any{memberEntry("gw-edge-9x2k")},
		},
		{
			name:           "load balanced without a result renders an empty roster",
			loadBalanced:   true,
			replicas:       2,
			wantKeys:       loadBalancedKeys,
			wantTargetSize: 2,
			wantMembers:    []any{},
		},
		{
			name:         "load balanced with a result renders its roster",
			loadBalanced: true,
			replicas:     2,
			result: func(t *testing.T, gw *wgnetv1alpha1.Gateway) *gcpmembers.Result {
				return &gcpmembers.Result{TargetSize: 1, Roster: roster(t, gw, "gw-edge-7f31")}
			},
			wantKeys:       loadBalancedKeys,
			wantTargetSize: 1,
			wantMembers:    []any{memberEntry("gw-edge-7f31")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.GCP.Replicas = tt.replicas
			if tt.loadBalanced {
				gw.Spec.GCP.LoadBalancer = &wgnetv1alpha1.GatewayGCPLoadBalancerSpec{SessionAffinity: "NONE"}
			}
			var result *gcpmembers.Result
			if tt.result != nil {
				result = tt.result(t, gw)
			}

			u, err := buildXGatewayGCP(gw, cfg, nil, tt.loadBalanced, result, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			specMap, found, err := unstructured.NestedMap(u.Object, "spec")
			if err != nil || !found {
				t.Fatalf("read spec: found=%v err=%v", found, err)
			}
			if got := slices.Sorted(maps.Keys(specMap)); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("spec keys = %v, want %v", got, tt.wantKeys)
			}
			if tt.loadBalanced {
				if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "targetSize"); got != tt.wantTargetSize {
					t.Errorf("spec.targetSize = %d, want %d", got, tt.wantTargetSize)
				}
				if got, _, _ := unstructured.NestedBool(u.Object, "spec", "loadBalanced"); !got {
					t.Errorf("spec.loadBalanced = %v, want true", got)
				}
			}
			if tt.wantMembers != nil {
				got, _, err := unstructured.NestedSlice(u.Object, "spec", "members")
				if err != nil {
					t.Fatalf("read spec.members: %v", err)
				}
				if !reflect.DeepEqual(got, tt.wantMembers) {
					t.Errorf("spec.members = %#v, want %#v", got, tt.wantMembers)
				}
			}
		})
	}
}

// memberEntry is the exact roster entry the composite carries for instanceName on the
// fixture Gateway: names derived from the base plus the instance's own name.
func memberEntry(instanceName string) map[string]any {
	base := "gw-" + string(testGatewayUID) + "-test-project-" + instanceName
	return map[string]any{
		"name":                     instanceName,
		"slot":                     int64(0),
		"tunnelAddress":            "10.99.0.1",
		"kubernetesSecretName":     base,
		"cloudSecretName":          base,
		"cloudSecretVersionName":   base + "-version",
		"cloudSecretIamMemberName": base + "-iam",
	}
}

// TestBuildXGatewayGCPKeySet pins the composite's exact spec key set: a stray or
// dropped field fails here even when no other test reads it.
func TestBuildXGatewayGCPKeySet(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP}},
		nil,
	)

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}
	specMap, found, err := unstructured.NestedMap(u.Object, "spec")
	if err != nil || !found {
		t.Fatalf("read spec: found=%v err=%v", found, err)
	}
	got := slices.Sorted(maps.Keys(specMap))
	want := []string{
		"address", "allowedPorts", "crossplane", "diskSizeGB", "enableOsLogin", "image",
		"machineType", "projectID", "providerConfigName", "region", "secretId",
		"serviceAccountId", "sharedNetworkName", "spot", "trafficPolicy", "userData",
		"wgGatewayAddress", "wgLinkAddress", "wgListenPort", "wgMTU",
		"wgSubnet", "zone",
	}
	if !slices.Equal(got, want) {
		t.Errorf("spec keys = %v, want %v", got, want)
	}
}

// TestBuildXGatewayGCPOptionalFields pins the fields the builder omits when unconfigured
// against image and diskSizeGB, which carry CRD defaults and are always set.
func TestBuildXGatewayGCPOptionalFields(t *testing.T) {
	cfg := testConfig()
	cfg.UserData = ""
	cfg.EnableOSLogin = false

	gw := newGateway("edge", "wg-system", nil, nil)

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	// enableOsLogin is set unconditionally from config, so a false config value
	// surfaces as an explicit false rather than an omitted field.
	if got, _, _ := unstructured.NestedBool(u.Object, "spec", "enableOsLogin"); got != false {
		t.Errorf("enableOsLogin = %v, want false", got)
	}

	for _, field := range []string{"userData", "allowedPorts"} {
		if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", field); found {
			t.Errorf("spec.%s set, want omitted when unconfigured/empty", field)
		}
	}

	// image and diskSizeGB are always present once defaulting is applied.
	for _, field := range []string{"image", "diskSizeGB"} {
		if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", field); !found {
			t.Errorf("spec.%s absent, want always set from defaulted gw.Spec", field)
		}
	}
}

// TestBuildXGatewayGCPWireguardListenPort pins that a non-default listen port flows
// verbatim onto wgListenPort, so the gateway VM boots on the port the link dials.
func TestBuildXGatewayGCPWireguardListenPort(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Wireguard.ListenPort = 51999

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgListenPort"); got != 51999 {
		t.Errorf("wgListenPort = %d, want 51999 (non-default spec.wireguard.listenPort)", got)
	}
}

// TestBuildXGatewayGCPWireguardMTU pins that a non-default mtu flows verbatim onto wgMTU, so
// the VM sets wg0 to the same MTU the link uses rather than leaving it at the kernel default.
func TestBuildXGatewayGCPWireguardMTU(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Wireguard.MTU = 1280

	u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "wgMTU"); got != 1280 {
		t.Errorf("wgMTU = %d, want 1280 (non-default spec.wireguard.mtu)", got)
	}
}

// TestBuildXGatewayGCPHealthPort pins that a custom health port flows verbatim onto the
// load-balanced composite's healthPort, the field the health check and firewall read.
func TestBuildXGatewayGCPHealthPort(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.GCP.LoadBalancer = &wgnetv1alpha1.GatewayGCPLoadBalancerSpec{SessionAffinity: "NONE"}

	u, err := buildXGatewayGCP(gw, cfg, nil, true, nil, 8181)
	if err != nil {
		t.Fatalf("buildXGatewayGCP: %v", err)
	}

	if got, _, _ := unstructured.NestedInt64(u.Object, "spec", "healthPort"); got != 8181 {
		t.Errorf("healthPort = %d, want 8181", got)
	}
}

// TestBuildXGatewayGCPProviderSelector pins the compositionSelector provider label, so a
// second provider's Composition cannot collide with the gcp one.
func TestBuildXGatewayGCPProviderSelector(t *testing.T) {
	cfg := testConfig()
	tests := []struct {
		name     string
		provider wgnetv1alpha1.CloudProvider
		want     string
	}{
		{"defaults to gcp when empty", "", "gcp"},
		{"honors explicit provider", wgnetv1alpha1.ProviderGCP, "gcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.Provider = tt.provider

			u, err := buildXGatewayGCP(gw, cfg, gw.Spec.Forwards, false, nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			assertNestedString(t, u, tt.want, "spec", "crossplane", "compositionSelector", "matchLabels", "provider")
		})
	}
}

// TestBuildXGatewayNetwork pins the singleton shared-VPC composite, which carries no
// ownerReference so deleting a Gateway never GCs the shared network.
func TestBuildXGatewayNetwork(t *testing.T) {
	cfg := testConfig()

	u := buildXGatewayNetwork(cfg)

	if got := u.GetAPIVersion(); got != xgatewayGCPAPIVersion {
		t.Errorf("apiVersion = %q, want %q", got, xgatewayGCPAPIVersion)
	}
	if got := u.GetKind(); got != xgatewayNetworkKind {
		t.Errorf("kind = %q, want %q", got, xgatewayNetworkKind)
	}
	if got := u.GetName(); got != cfg.SharedNetworkName {
		t.Errorf("name = %q, want %q", got, cfg.SharedNetworkName)
	}
	if got := u.GetNamespace(); got != cfg.PodNamespace {
		t.Errorf("namespace = %q, want %q", got, cfg.PodNamespace)
	}

	assertNestedString(t, u, cfg.SharedNetworkName, "spec", "name")
	assertNestedString(t, u, cfg.ProviderConfigName, "spec", "providerConfigName")
	assertNestedString(t, u, "gcp", "spec", "crossplane", "compositionSelector", "matchLabels", "provider")

	if refs := u.GetOwnerReferences(); len(refs) != 0 {
		t.Errorf("ownerReferences = %d, want 0 (shared network is refcount-managed, not Gateway-owned)", len(refs))
	}
}

// TestGCPIDBase32Length documents the bound truncation relies on: sha256 base32-encodes to
// 52 chars, so prefix+hash always exceeds the 30-char cap.
func TestGCPIDBase32Length(t *testing.T) {
	full := base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(32)
	if full+len(gcpIDPrefix) <= gcpIDMaxLen {
		t.Fatalf("base32 length %d + prefix does not exceed cap %d; truncation untested", full, gcpIDMaxLen)
	}
}

// TestBuildXGatewayGCPTrafficPolicy pins that the composite carries the mode lowercased,
// which is the form the composition renders into the VM's traffic-policy metadata key.
func TestBuildXGatewayGCPTrafficPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		want   string
	}{
		{"unset renders cluster", "", "cluster"},
		{"Cluster renders cluster", wgnetv1alpha1.TrafficPolicyCluster, "cluster"},
		{"Local renders local", wgnetv1alpha1.TrafficPolicyLocal, "local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy

			u, err := buildXGatewayGCP(gw, testConfig(), nil, false, nil, clusterHealthPort)
			if err != nil {
				t.Fatalf("buildXGatewayGCP: %v", err)
			}
			assertNestedString(t, u, tt.want, "spec", "trafficPolicy")
		})
	}
}
