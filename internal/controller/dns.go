package controller

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

const (
	// dnsEndpointAPIVersion and dnsEndpointKind identify the published external-dns
	// DNSEndpoint; unstructured because its CRD is an optional install prerequisite.
	dnsEndpointAPIVersion = "externaldns.k8s.io/v1alpha1"
	dnsEndpointKind       = "DNSEndpoint"
	// cloudflareProxiedAnnotation keeps published records DNS-only: gateway
	// traffic is raw WireGuard/TCP and must never sit behind a proxy.
	cloudflareProxiedAnnotation = "external-dns.alpha.kubernetes.io/cloudflare-proxied"
)

// buildDNSEndpoint maps each hostname to the gateway address as an A record, returning
// nil when there are no hostnames or the address is not yet known.
func buildDNSEndpoint(gw *wgnetv1alpha1.Gateway, address string) *unstructured.Unstructured {
	if len(gw.Spec.DNSHostnames) == 0 || address == "" {
		return nil
	}

	endpoints := make([]any, 0, len(gw.Spec.DNSHostnames))
	for _, host := range gw.Spec.DNSHostnames {
		endpoints = append(endpoints, map[string]any{
			"dnsName":    host,
			"recordType": "A",
			"targets":    []any{address},
		})
	}

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": dnsEndpointAPIVersion,
		"kind":       dnsEndpointKind,
		"spec":       map[string]any{"endpoints": endpoints},
	}}
	u.SetName(gw.Name)
	u.SetNamespace(gw.Namespace)
	u.SetLabels(commonLabels(gw, "dns"))
	u.SetAnnotations(map[string]string{cloudflareProxiedAnnotation: "false"})
	return u
}

// ensureDNSEndpoint applies the DNSEndpoint once hostnames and the address are known.
// It is owner-ref'd but not watched, so startup does not depend on the external-dns CRD.
func (r *GatewayReconciler) ensureDNSEndpoint(ctx context.Context, gw *wgnetv1alpha1.Gateway, address string) error {
	desired := buildDNSEndpoint(gw, address)
	if desired == nil {
		return nil
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set dns endpoint owner reference: %w", err)
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal dns endpoint: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply dns endpoint: %w", err)
	}
	return nil
}
