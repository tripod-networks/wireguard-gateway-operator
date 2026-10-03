package controller

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

func TestGatewayAddressDefault(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const ns = "addr-default"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

	gw := newGateway(ns, ns, nil, nil)
	if err := cl.Create(ctx, gw); err != nil {
		t.Fatalf("create Gateway with omitted spec.gcp.address: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: ns}, &got)

	want := wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressReserved}
	if got.Spec.GCP.Address != want {
		t.Errorf("defaulted spec.gcp.address = %+v, want %+v", got.Spec.GCP.Address, want)
	}
}

// TestGatewayAddressAdmission exercises the whole spec.gcp.address admission surface: the type
// enum, the external block's presence rule, its exactly-one rule and its field validation.
func TestGatewayAddressAdmission(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const (
		wantExternalRequired = "spec.gcp.address.external is required when type is External and forbidden otherwise"
		wantExactlyOne       = "spec.gcp.address.external must set exactly one of name and ip"
		wantIPPattern        = `spec.gcp.address.external.ip in body should match ` +
			`'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'`
		wantNameMinLength = "spec.gcp.address.external.name in body should be at least 1 chars long"
	)

	external := func(ext wgnetv1alpha1.GatewayGCPExternalAddress) wgnetv1alpha1.GatewayGCPAddressSpec {
		return wgnetv1alpha1.GatewayGCPAddressSpec{
			Type:     wgnetv1alpha1.GatewayGCPAddressExternal,
			External: &ext,
		}
	}

	tests := []struct {
		name string
		addr wgnetv1alpha1.GatewayGCPAddressSpec
		// build overrides the typed fixture for a row a typed Gateway cannot express.
		build       func(t *testing.T, ns string) client.Object
		accept      bool
		wantMessage string
	}{
		{
			name:   "reserved accepted",
			addr:   wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressReserved},
			accept: true,
		},
		{
			name:   "ephemeral accepted",
			addr:   wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressEphemeral},
			accept: true,
		},
		{
			name:   "external with ip accepted",
			addr:   external(wgnetv1alpha1.GatewayGCPExternalAddress{IP: "34.76.10.20"}),
			accept: true,
		},
		{
			name:   "external with name accepted",
			addr:   external(wgnetv1alpha1.GatewayGCPExternalAddress{Name: "my-addr"}),
			accept: true,
		},
		{
			name:        "off-enum type rejected",
			addr:        wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressType("Bogus")},
			wantMessage: `spec.gcp.address.type: Unsupported value: "Bogus": supported values: "Ephemeral", "Reserved", "External"`,
		},
		{
			name:        "external without block rejected",
			addr:        wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressExternal},
			wantMessage: wantExternalRequired,
		},
		{
			name: "reserved with external block rejected",
			addr: wgnetv1alpha1.GatewayGCPAddressSpec{
				Type:     wgnetv1alpha1.GatewayGCPAddressReserved,
				External: &wgnetv1alpha1.GatewayGCPExternalAddress{IP: "34.76.10.20"},
			},
			wantMessage: wantExternalRequired,
		},
		{
			name:        "external with both name and ip rejected",
			addr:        external(wgnetv1alpha1.GatewayGCPExternalAddress{Name: "my-addr", IP: "34.76.10.20"}),
			wantMessage: wantExactlyOne,
		},
		{
			name:        "external with neither name nor ip rejected",
			addr:        external(wgnetv1alpha1.GatewayGCPExternalAddress{}),
			wantMessage: wantExactlyOne,
		},
		{
			name:        "three octets rejected",
			addr:        external(wgnetv1alpha1.GatewayGCPExternalAddress{IP: "34.76.10"}),
			wantMessage: wantIPPattern,
		},
		{
			name:        "non-numeric ip rejected",
			addr:        external(wgnetv1alpha1.GatewayGCPExternalAddress{IP: "not-an-ip"}),
			wantMessage: wantIPPattern,
		},
		{
			name:        "octet over 255 rejected",
			addr:        external(wgnetv1alpha1.GatewayGCPExternalAddress{IP: "34.76.10.256"}),
			wantMessage: wantIPPattern,
		},
		{
			name:        "empty name rejected",
			build:       unstructuredGatewayWithEmptyExternalName,
			wantMessage: wantNameMinLength,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("addr-admission-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

			var obj client.Object
			if tt.build != nil {
				obj = tt.build(t, ns)
			} else {
				gw := newGateway(ns, ns, nil, nil)
				gw.Spec.GCP.Address = tt.addr
				obj = gw
			}
			assertAdmission(ctx, t, cl, obj, cl.Create(ctx, obj), tt.accept, tt.wantMessage)
		})
	}
}

func TestGatewayAddressMutable(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const ns = "addr-mutable"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

	gw := newGateway(ns, ns, nil, nil)
	gw.Spec.GCP.Address = wgnetv1alpha1.GatewayGCPAddressSpec{Type: wgnetv1alpha1.GatewayGCPAddressReserved}
	if err := cl.Create(ctx, gw); err != nil {
		t.Fatalf("create Gateway: %v", err)
	}

	key := client.ObjectKey{Namespace: ns, Name: ns}
	updates := []wgnetv1alpha1.GatewayGCPAddressSpec{
		{Type: wgnetv1alpha1.GatewayGCPAddressEphemeral},
		{
			Type:     wgnetv1alpha1.GatewayGCPAddressExternal,
			External: &wgnetv1alpha1.GatewayGCPExternalAddress{IP: "34.76.10.20"},
		},
	}

	for _, want := range updates {
		var cur wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &cur)
		cur.Spec.GCP.Address = want
		if err := cl.Update(ctx, &cur); err != nil {
			t.Fatalf("update spec.gcp.address to %+v: %v", want, err)
		}

		var got wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &got)
		if !reflect.DeepEqual(got.Spec.GCP.Address, want) {
			t.Errorf("spec.gcp.address = %+v, want %+v", got.Spec.GCP.Address, want)
		}
	}
}

// unstructuredGatewayWithEmptyExternalName builds the fixture as raw JSON so
// external.name reaches admission as an empty string rather than a dropped key.
func unstructuredGatewayWithEmptyExternalName(t *testing.T, ns string) client.Object {
	t.Helper()
	gw := newGatewayNoWireguard(ns, ns, nil)
	addr := map[string]any{
		"type":     string(wgnetv1alpha1.GatewayGCPAddressExternal),
		"external": map[string]any{"name": ""},
	}
	if err := unstructured.SetNestedMap(gw.Object, addr, "spec", "gcp", "address"); err != nil {
		t.Fatalf("set spec.gcp.address: %v", err)
	}
	return gw
}

// assertAdmission checks the API server's verdict err on obj; a rejection must be Invalid
// and, when wantMessage is set, must mention it. An accepted obj is deleted again.
func assertAdmission(ctx context.Context, t *testing.T, cl client.Client, obj client.Object, err error, accept bool, wantMessage string) {
	t.Helper()
	if accept {
		if err != nil {
			t.Fatalf("accepted Gateway: %v", err)
		}
		if delErr := cl.Delete(ctx, obj); delErr != nil {
			t.Errorf("delete Gateway: %v", delErr)
		}
		return
	}
	if !apierrors.IsInvalid(err) {
		t.Fatalf("rejected Gateway: err = %v, want Invalid", err)
	}
	if wantMessage != "" && !strings.Contains(err.Error(), wantMessage) {
		t.Errorf("rejection = %v, want it to mention %q", err, wantMessage)
	}
}
