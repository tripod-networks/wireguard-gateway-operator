package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	gcp "github.com/tripod-networks/wireguard-gateway-operator/internal/crossplane/gcp"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpmembers"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

const (
	// gcpIDPrefix supplies the leading letter GCP requires on hash-derived
	// service-account and secret IDs and namespaces them apart from other tenants.
	gcpIDPrefix = "gw-"
	// gcpIDMaxLen is GCP's service-account-ID length cap; secret IDs share the
	// derived value so both fit this bound.
	gcpIDMaxLen = 30
	// xgatewayGCPAPIVersion and xgatewayGCPKind identify the Crossplane composite the
	// operator builds; it is unstructured because the typed view models only spec/status.
	xgatewayGCPAPIVersion = "infra.wgnet.dev/v1alpha1"
	xgatewayGCPKind       = "XGatewayGCP"
	// xgatewayNetworkKind is the singleton composite that provisions the shared VPC. It
	// shares xgatewayGCPAPIVersion: both composites live in the same group/version.
	xgatewayNetworkKind = "XGatewayNetwork"
	// providerLabelKey is the matchLabels key under spec.crossplane.compositionSelector
	// pinning the provider-specific Composition, so two providers can coexist.
	providerLabelKey = "provider"
	// bootstrapScriptRevision is bumped whenever files/gcp/keyfetch.sh's contract changes,
	// folding that change into templateRevision's hash.
	bootstrapScriptRevision = "v1"
)

// gcpID derives a project-unique, GCP-valid service-account/secret ID.
func gcpID(namespace, name string) string {
	return hashedName(gcpIDPrefix, namespace, name, gcpIDMaxLen)
}

// gatewayProvider defaults an empty provider to gcp, guarding in-memory Gateways
// that bypassed CRD defaulting.
func gatewayProvider(gw *wgnetv1alpha1.Gateway) wgnetv1alpha1.CloudProvider {
	if gw.Spec.Provider == "" {
		return wgnetv1alpha1.ProviderGCP
	}
	return gw.Spec.Provider
}

// XGatewayGCPGVK is the composite's GroupVersionKind, exported so the manager can
// register an unstructured Owns watch on it.
var XGatewayGCPGVK = schema.GroupVersionKind{Group: "infra.wgnet.dev", Version: "v1alpha1", Kind: "XGatewayGCP"}

// newXGatewayGCP returns an empty unstructured XGatewayGCP with its GVK set, for Get,
// CreateOrUpdate, and the Owns watch.
func newXGatewayGCP() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(XGatewayGCPGVK)
	return u
}

// XGatewayNetworkGVK is the shared-VPC composite's GroupVersionKind, exported so
// the manager can register an unstructured watch on it.
var XGatewayNetworkGVK = schema.GroupVersionKind{Group: "infra.wgnet.dev", Version: "v1alpha1", Kind: "XGatewayNetwork"}

// newXGatewayNetwork returns an empty unstructured XGatewayNetwork with its GVK
// set, for Get, CreateOrUpdate, and the watch.
func newXGatewayNetwork() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(XGatewayNetworkGVK)
	return u
}

const (
	gcpDefaultImage            = "projects/kinvolk-public/global/images/family/flatcar-stable"
	gcpDefaultDiskSizeGB int32 = 20
)

// effectiveGCPImage returns the gateway VM boot image, defaulting an unset value.
func effectiveGCPImage(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.GCP.Image == "" {
		return gcpDefaultImage
	}
	return gw.Spec.GCP.Image
}

// effectiveGCPDiskSizeGB returns the gateway VM boot disk size, defaulting an
// unset value.
func effectiveGCPDiskSizeGB(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.GCP.DiskSizeGB == 0 {
		return gcpDefaultDiskSizeGB
	}
	return gw.Spec.GCP.DiskSizeGB
}

// effectiveGCPAddress returns the address block, defaulting an unset Type to Reserved
// for in-memory Gateways that bypassed CRD defaulting.
func effectiveGCPAddress(gw *wgnetv1alpha1.Gateway) wgnetv1alpha1.GatewayGCPAddressSpec {
	addr := gw.Spec.GCP.Address
	if addr.Type == "" {
		addr.Type = wgnetv1alpha1.GatewayGCPAddressReserved
	}
	return addr
}

func effectiveGCPSpot(gw *wgnetv1alpha1.Gateway) bool {
	return gw.Spec.GCP.Spot
}

// templateRevision hashes only inputs that affect the instance template.
func templateRevision(gw *wgnetv1alpha1.Gateway, cfg Config, secretID string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%d\x00%t\x00%t\x00%s\x00%s\x00%d\x00%d\x00%s\x00%s\x00%s\x00%s",
		bootstrapScriptRevision, effectiveGCPImage(gw), gw.Spec.GCP.MachineType,
		effectiveGCPDiskSizeGB(gw), effectiveGCPSpot(gw), cfg.EnableOSLogin, cfg.UserData,
		cfg.SharedNetworkName, effectiveWireguardPort(gw), effectiveWGMTU(gw),
		effectiveWGLinkAddress(gw), strings.ToLower(string(effectiveTrafficPolicy(gw))),
		gw.Spec.GCP.ProjectID, secretID)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// buildXGatewayGCP builds the composite for either gateway provisioning branch.
func buildXGatewayGCP(gw *wgnetv1alpha1.Gateway, cfg Config, forwards []wgnetv1alpha1.Forward, loadBalanced bool, result *gcpmembers.Result, healthPort int) (*unstructured.Unstructured, error) {
	id := gcpID(gw.Namespace, gw.Name)
	secretID, err := gcpmembers.NameBase(string(gw.UID), gw.Spec.GCP.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("derive bundle secret id: %w", err)
	}
	image := effectiveGCPImage(gw)
	diskSizeGB := int(effectiveGCPDiskSizeGB(gw))
	addr := effectiveGCPAddress(gw)
	addrType := string(addr.Type)
	xgAddress := &struct {
		External *struct {
			Ip   *string `json:"ip,omitempty"` //nolint:revive // name fixed by the generated composite schema
			Name *string `json:"name,omitempty"`
		} `json:"external,omitempty"`
		Type *string `json:"type,omitempty"`
	}{Type: &addrType}
	if addr.External != nil {
		extName := addr.External.Name
		extIP := addr.External.IP
		ext := &struct {
			Ip   *string `json:"ip,omitempty"` //nolint:revive // name fixed by the generated composite schema
			Name *string `json:"name,omitempty"`
		}{}
		if extName != "" {
			ext.Name = &extName
		}
		if extIP != "" {
			ext.Ip = &extIP
		}
		xgAddress.External = ext
	}
	spot := effectiveGCPSpot(gw)
	projectID := gw.Spec.GCP.ProjectID
	wgGatewayAddress := effectiveWGGatewayAddress(gw)
	wgLinkAddress := effectiveWGLinkAddress(gw)
	wgSubnet := effectiveWGSubnet(gw)

	spec := gcp.XGatewayGCPSpec{
		Address:            xgAddress,
		Region:             gw.Spec.GCP.Region,
		Zone:               gw.Spec.GCP.Zone,
		MachineType:        gw.Spec.GCP.MachineType,
		SharedNetworkName:  cfg.SharedNetworkName,
		ProviderConfigName: &cfg.ProviderConfigName,
		Image:              &image,
		DiskSizeGB:         &diskSizeGB,
		WgListenPort:       int(effectiveWireguardPort(gw)),
		WgMTU:              int(effectiveWGMTU(gw)),
		WgGatewayAddress:   &wgGatewayAddress,
		WgLinkAddress:      &wgLinkAddress,
		WgSubnet:           &wgSubnet,
		ProjectID:          &projectID,
		TrafficPolicy:      new(strings.ToLower(string(effectiveTrafficPolicy(gw)))),
		Spot:               &spot,
		EnableOsLogin:      new(cfg.EnableOSLogin),
		ServiceAccountId:   &id,
		SecretId:           secretID,
	}

	if cfg.UserData != "" {
		spec.UserData = &cfg.UserData
	}

	if loadBalanced {
		enabled := true
		sessionAffinity := gw.Spec.GCP.LoadBalancer.SessionAffinity
		targetSize := int(gw.Spec.GCP.Replicas)
		if result != nil {
			targetSize = int(result.TargetSize)
		}
		zones := effectiveZones(gw)
		revision := templateRevision(gw, cfg, secretID)
		hp := healthPort

		spec.LoadBalanced = &enabled
		spec.SessionAffinity = &sessionAffinity
		spec.TargetSize = &targetSize
		spec.Zones = &zones
		spec.TemplateRevision = &revision
		spec.HealthPort = &hp

		members := rosterMembers(rosterOf(result))
		spec.Members = &members
	} else if roster := rosterOf(result); len(roster) > 0 {
		members := rosterMembers(roster)
		spec.Members = &members
	}

	if len(forwards) > 0 {
		ports := make([]struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		}, 0, len(forwards))
		for _, f := range forwards {
			ports = append(ports, struct {
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
			}{Port: int(f.Port), Protocol: strings.ToLower(string(f.Protocol))})
		}
		spec.AllowedPorts = &ports
	}

	specMap, err := toUnstructuredMap(&spec)
	if err != nil {
		return nil, fmt.Errorf("encode xgatewaygcp spec: %w", err)
	}

	specMap["crossplane"] = map[string]any{
		"compositionSelector": map[string]any{
			"matchLabels": map[string]any{providerLabelKey: string(gatewayProvider(gw))},
		},
	}

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": xgatewayGCPAPIVersion,
		"kind":       xgatewayGCPKind,
		"spec":       specMap,
	}}
	u.SetName(gw.Name)
	u.SetNamespace(gw.Namespace)
	u.SetLabels(commonLabels(gw, "gateway"))
	return u, nil
}

// buildXGatewayNetwork builds the singleton shared-VPC composite in cfg.PodNamespace.
// It carries no ownerReference: its lifecycle is refcount-managed across Gateways.
func buildXGatewayNetwork(cfg Config) *unstructured.Unstructured {
	spec := map[string]any{
		"name":               cfg.SharedNetworkName,
		"providerConfigName": cfg.ProviderConfigName,
		"crossplane": map[string]any{
			"compositionSelector": map[string]any{
				"matchLabels": map[string]any{providerLabelKey: string(wgnetv1alpha1.ProviderGCP)},
			},
		},
	}

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": xgatewayGCPAPIVersion,
		"kind":       xgatewayNetworkKind,
		"spec":       spec,
	}}
	u.SetName(cfg.SharedNetworkName)
	u.SetNamespace(cfg.PodNamespace)
	u.SetLabels(map[string]string{
		"app.kubernetes.io/name":       "wireguard-gateway-operator",
		"app.kubernetes.io/component":  "shared-network",
		"app.kubernetes.io/managed-by": "gateway-operator",
	})
	return u
}

// toUnstructuredMap converts via the runtime converter, so integers become int64 rather
// than the float64 a JSON round-trip yields (which NestedInt64 and the API server reject).
func toUnstructuredMap(v any) (map[string]any, error) {
	return runtime.DefaultUnstructuredConverter.ToUnstructured(v)
}

// ensureXGatewayGCP server-side applies the composite without changing its status.
func (r *GatewayReconciler) ensureXGatewayGCP(ctx context.Context, gw *wgnetv1alpha1.Gateway, forwards []wgnetv1alpha1.Forward, loadBalanced bool, result *gcpmembers.Result, healthPort int) error {
	if result != nil {
		roster, err := r.passRoster(ctx, gw, result)
		if err != nil {
			return err
		}
		pass := *result
		pass.Roster = roster
		result = &pass
	}
	desired, err := buildXGatewayGCP(gw, r.Config, forwards, loadBalanced, result, healthPort)
	if err != nil {
		return err
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set xgatewaygcp owner reference: %w", err)
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal xgatewaygcp: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply xgatewaygcp: %w", err)
	}
	return nil
}

// applyOverCapacityXGatewayGCP preserves the existing target size and roster.
func (r *GatewayReconciler) applyOverCapacityXGatewayGCP(ctx context.Context, gw *wgnetv1alpha1.Gateway, forwards []wgnetv1alpha1.Forward, healthPort int) error {
	exists, err := r.xgatewayGCPExists(ctx, gw)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	targetSize, err := r.readXGatewayGCPTargetSize(ctx, gw)
	if err != nil {
		return err
	}
	// The unusable result retains the applied roster.
	return r.ensureXGatewayGCP(ctx, gw, forwards, true, &gcpmembers.Result{TargetSize: targetSize, Unusable: true}, healthPort)
}

// ensureXGatewayNetwork applies the singleton shared-VPC composite before anything
// references it. It is unowned and re-created here if a racing last-delete tore it down.
func (r *GatewayReconciler) ensureXGatewayNetwork(ctx context.Context) error {
	desired := buildXGatewayNetwork(r.Config)
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal xgatewaynetwork: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply xgatewaynetwork: %w", err)
	}
	return nil
}

// xgatewayGCPExists reports whether the Gateway provisioned at least once, so it keeps
// its VM under an all-invalid forward set. Errors other than NotFound are surfaced.
func (r *GatewayReconciler) xgatewayGCPExists(ctx context.Context, gw *wgnetv1alpha1.Gateway) (bool, error) {
	xg := newXGatewayGCP()
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get xgatewaygcp: %w", err)
	}
	return true, nil
}

// compositeStatus holds observed Crossplane values used by reconciliation.
type compositeStatus struct {
	Address             string
	ServiceAccountEmail string
	Message             string
	MIGName             string
	InstanceName        string
}

// readXGatewayGCPStatus reads the composite's observed status. A missing composite yields
// zero values: the apply has not yet propagated.
func (r *GatewayReconciler) readXGatewayGCPStatus(ctx context.Context, gw *wgnetv1alpha1.Gateway) (compositeStatus, error) {
	xg := newXGatewayGCP()
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return compositeStatus{}, nil
		}
		return compositeStatus{}, fmt.Errorf("get xgatewaygcp: %w", err)
	}
	var status compositeStatus
	into := []struct {
		field string
		dest  *string
	}{
		{"address", &status.Address},
		{"serviceAccountEmail", &status.ServiceAccountEmail},
		{"message", &status.Message},
		{"migName", &status.MIGName},
		{"instanceName", &status.InstanceName},
	}
	for _, f := range into {
		value, _, err := unstructured.NestedString(xg.Object, "status", f.field)
		if err != nil {
			return compositeStatus{}, fmt.Errorf("read status.%s: %w", f.field, err)
		}
		*f.dest = value
	}
	return status, nil
}

// readXGatewayGCPTargetSize reads the composite's own current spec.targetSize (0 when the
// composite does not exist yet), gcpmembers.Reconcile's lastAcceptedTargetSize input.
func (r *GatewayReconciler) readXGatewayGCPTargetSize(ctx context.Context, gw *wgnetv1alpha1.Gateway) (int32, error) {
	xg := newXGatewayGCP()
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("get xgatewaygcp for target size: %w", err)
	}
	v, found, err := unstructured.NestedInt64(xg.Object, "spec", "targetSize")
	if err != nil {
		return 0, fmt.Errorf("read spec.targetSize: %w", err)
	}
	if !found {
		return 0, nil
	}
	return int32(v), nil
}
