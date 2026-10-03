// Package gcpmembers implements the allocation and retirement state machine for a
// load-balanced Gateway's GCP fleet: slot/address/key allocation, the durable
// per-member Kubernetes Secret record, the departure debounce and the three-step
// retirement protocol.
package gcpmembers

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// Record is the durable per-name allocation record's decoded view: the Secret's bundle
// payload (private, never logged) plus its public labels.
type Record struct {
	UID             types.UID
	ResourceVersion string
	Name            string // instance name
	Zone            string
	Slot            int
	PrivateKey      string
	// PublicKey is derived from PrivateKey, never stored: the bundle payload carries no
	// public key.
	PublicKey string
	// TunnelAddress is the bare host address; the bundle payload renders it as
	// "<TunnelAddress>/<SubnetPrefix>".
	TunnelAddress string
	SubnetPrefix  int
	// PeerPublicKey and PeerAllowedIPs are the Gateway's link public key and its link
	// address as a /32, uniform across the fleet and authoritative for the member's peer.
	PeerPublicKey   string
	PeerAllowedIPs  string
	ExternalAddress string
	InstanceID      string
	Revision        string
	// DepartureCount is the departure debounce counter: the number of
	// consecutive usable snapshots the name has been absent from, 0 while listed or departed.
	DepartureCount int
	// PendingConfirmation is set once the one-pass removal has run (peer and triple
	// unrendered) and cleared only by DeleteRecord's caller on confirmed release.
	PendingConfirmation bool
	// GatewayUID and Project let Reconcile validate record ownership.
	GatewayUID types.UID
	Project    string
}

// ManagedResourceNames is the three per-member cloud resource names the composite
// roster carries: the Secret Manager Secret, its SecretVersion and
// its SecretIAMMember, plus the member's own Kubernetes Secret name.
type ManagedResourceNames struct {
	KubernetesSecretName     string
	CloudSecretName          string
	CloudSecretVersionName   string
	CloudSecretIAMMemberName string
}

const (
	k8sObjectNameMaxLength      = 253
	secretManagerSecretIDMaxLen = 255
)

// validResourceNameSegment matches the record naming contract's charset:
// lowercase alphanumeric or "-", never leading or trailing with "-".
var validResourceNameSegment = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// NameBase is the record naming contract's base, "gw-<gatewayUID>-<project>"
// : the bundle id prefix every member name suffixes and the VM's
// "secret-id" metadata value in both branches.
func NameBase(gatewayUID, project string) (string, error) {
	base := strings.ToLower(fmt.Sprintf("gw-%s-%s", gatewayUID, project))
	if !validResourceNameSegment.MatchString(base) {
		return "", fmt.Errorf("gcpmembers: derived resource name %q is not lowercase alphanumeric or hyphen", base)
	}
	return base, nil
}

// NameResourceNames derives bounded names for member Kubernetes and cloud resources.
func NameResourceNames(gatewayUID, project, instanceName string) (ManagedResourceNames, error) {
	prefix, err := NameBase(gatewayUID, project)
	if err != nil {
		return ManagedResourceNames{}, err
	}
	base := strings.ToLower(prefix + "-" + instanceName)
	if !validResourceNameSegment.MatchString(base) {
		return ManagedResourceNames{}, fmt.Errorf("gcpmembers: derived resource name %q is not lowercase alphanumeric or hyphen", base)
	}
	if len(base) > secretManagerSecretIDMaxLen {
		return ManagedResourceNames{}, fmt.Errorf("gcpmembers: derived resource name %q exceeds the %d-character Secret Manager secret id bound", base, secretManagerSecretIDMaxLen)
	}
	if len(base) > k8sObjectNameMaxLength {
		return ManagedResourceNames{}, fmt.Errorf("gcpmembers: derived resource name %q exceeds the %d-character Kubernetes object name bound", base, k8sObjectNameMaxLength)
	}
	versionName := base + "-version"
	iamName := base + "-iam"
	for _, n := range []string{versionName, iamName} {
		if len(n) > k8sObjectNameMaxLength {
			return ManagedResourceNames{}, fmt.Errorf("gcpmembers: derived resource name %q exceeds the %d-character Kubernetes object name bound", n, k8sObjectNameMaxLength)
		}
	}
	return ManagedResourceNames{
		KubernetesSecretName:     base,
		CloudSecretName:          base,
		CloudSecretVersionName:   versionName,
		CloudSecretIAMMemberName: iamName,
	}, nil
}

// Deps are the effects Reconcile performs through the caller's Kubernetes client: reading,
// creating and deleting the per-name Secret record, and the uncached confirmation reads.
type Deps interface {
	// GetRecord reads name's durable Secret record (cached is fine: this is not a
	// confirmation read). Returns (nil, false, nil) when absent.
	GetRecord(ctx context.Context, gatewayNamespace, gatewayName, name string) (*Record, bool, error)
	// CreateRecord creates name's durable Secret record, owner-referenced by the Gateway.
	CreateRecord(ctx context.Context, gatewayNamespace, gatewayName string, rec Record) error
	// UpdateRecordLabels preserves the write-once bundle payload.
	UpdateRecordLabels(ctx context.Context, gatewayNamespace, gatewayName, name string, labels map[string]string) error
	// DeleteRecord deletes name's Secret with UID and resourceVersion preconditions
	//. Tolerates NotFound.
	DeleteRecord(ctx context.Context, gatewayNamespace, gatewayName, name string, uid types.UID, resourceVersion string) error
	// ConfirmManagedResourcesAbsent issues one uncached GET per name in names (the three
	// Secret Manager kinds) and reports whether every one is NotFound.
	ConfirmManagedResourcesAbsent(ctx context.Context, names ManagedResourceNames) (bool, string, error)
	// CompositeSynced requires an uncached read of current generation.
	CompositeSynced(ctx context.Context, gatewayNamespace, gatewayName string) (bool, string, error)
	// GenerateKeypair returns a fresh WireGuard keypair, injected for deterministic tests.
	GenerateKeypair() (privateKey, publicKey string, err error)
	// ListRecordNames finds records absent from the current discovery snapshot.
	ListRecordNames(ctx context.Context, gatewayNamespace, gatewayName string) ([]string, error)
}

// kubernetesDeps uses uncached reads for confirmation to avoid stale informer state.
type kubernetesDeps struct {
	client     client.Client
	uncached   client.Reader
	gatewayUID types.UID
	project    string
}

// NewKubernetesDeps builds the real Deps implementation for one Gateway's Reconcile pass.
// gatewayUID and project scope every derived resource name (NameResourceNames); uncached
// must bypass any client cache for ConfirmManagedResourcesAbsent and CompositeSynced.
func NewKubernetesDeps(c client.Client, uncached client.Reader, gatewayUID types.UID, project string) Deps {
	return &kubernetesDeps{client: c, uncached: uncached, gatewayUID: gatewayUID, project: project}
}

func (d *kubernetesDeps) resolveNames(name string) (ManagedResourceNames, error) {
	return NameResourceNames(string(d.gatewayUID), d.project, name)
}

// Record label keys. All are internal to this package's Secret encoding; no other domain
// reads them directly (Deps hides the Secret shape behind Record).
const (
	labelName                = "wgnet.dev/gcp-member-name"
	labelZone                = "wgnet.dev/gcp-member-zone"
	labelSlot                = "wgnet.dev/gcp-member-slot"
	labelInstanceID          = "wgnet.dev/gcp-member-instance-id"
	labelExternalAddress     = "wgnet.dev/gcp-member-external-address"
	labelProject             = "wgnet.dev/gcp-member-project"
	labelRevision            = "wgnet.dev/gcp-member-revision"
	labelDepartureCount      = "wgnet.dev/gcp-member-departure-count"
	labelPendingConfirmation = "wgnet.dev/gcp-member-pending-confirmation"
	labelState               = "wgnet.dev/gcp-member-state"
	labelGatewayUID          = "wgnet.dev/gcp-member-gateway-uid"
)

// bundlePayload is the write-once Secret data read by the VM.
type bundlePayload struct {
	PrivateKey     string `json:"privateKey"`
	Address        string `json:"address"`
	Slot           string `json:"slot"`
	PeerPublicKey  string `json:"peerPublicKey"`
	PeerAllowedIPs string `json:"peerAllowedIPs"`
}

// payloadFromRecord renders rec's bundle payload. It is built before the write-once record
// is created and never rewritten afterwards.
func payloadFromRecord(rec Record) bundlePayload {
	return bundlePayload{
		PrivateKey:     rec.PrivateKey,
		Address:        fmt.Sprintf("%s/%d", rec.TunnelAddress, rec.SubnetPrefix),
		Slot:           strconv.Itoa(rec.Slot),
		PeerPublicKey:  rec.PeerPublicKey,
		PeerAllowedIPs: rec.PeerAllowedIPs,
	}
}

// publicKeyOf derives a member's WireGuard public key from its private key.
func publicKeyOf(privateKey string) (string, error) {
	if privateKey == "" {
		return "", nil
	}
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("gcpmembers: parsing member private key: %w", err)
	}
	return key.PublicKey().String(), nil
}

func recordLabels(rec Record) map[string]string {
	return map[string]string{
		labelName:                rec.Name,
		labelZone:                rec.Zone,
		labelSlot:                strconv.Itoa(rec.Slot),
		labelInstanceID:          rec.InstanceID,
		labelExternalAddress:     rec.ExternalAddress,
		labelProject:             rec.Project,
		labelRevision:            rec.Revision,
		labelDepartureCount:      strconv.Itoa(rec.DepartureCount),
		labelPendingConfirmation: strconv.FormatBool(rec.PendingConfirmation),
		labelGatewayUID:          string(rec.GatewayUID),
	}
}

func recordFromSecret(s *corev1.Secret) (Record, error) {
	var bundle bundlePayload
	if raw, ok := s.Data[wg.BundleKey]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &bundle); err != nil {
			return Record{}, fmt.Errorf("gcpmembers: decoding bundle for secret %s/%s: %w", s.Namespace, s.Name, err)
		}
	}
	slot, _ := strconv.Atoi(s.Labels[labelSlot])
	departureCount, _ := strconv.Atoi(s.Labels[labelDepartureCount])
	publicKey, err := publicKeyOf(bundle.PrivateKey)
	if err != nil {
		return Record{}, fmt.Errorf("gcpmembers: secret %s/%s: %w", s.Namespace, s.Name, err)
	}
	tunnelAddress, subnetPrefix, err := splitCIDR(bundle.Address)
	if err != nil {
		return Record{}, fmt.Errorf("gcpmembers: secret %s/%s: %w", s.Namespace, s.Name, err)
	}
	return Record{
		UID:                 s.UID,
		ResourceVersion:     s.ResourceVersion,
		Name:                s.Labels[labelName],
		Zone:                s.Labels[labelZone],
		Slot:                slot,
		PrivateKey:          bundle.PrivateKey,
		PublicKey:           publicKey,
		TunnelAddress:       tunnelAddress,
		SubnetPrefix:        subnetPrefix,
		PeerPublicKey:       bundle.PeerPublicKey,
		PeerAllowedIPs:      bundle.PeerAllowedIPs,
		ExternalAddress:     s.Labels[labelExternalAddress],
		InstanceID:          s.Labels[labelInstanceID],
		Revision:            s.Labels[labelRevision],
		DepartureCount:      departureCount,
		PendingConfirmation: s.Labels[labelPendingConfirmation] == "true",
		GatewayUID:          types.UID(s.Labels[labelGatewayUID]),
		Project:             s.Labels[labelProject],
	}, nil
}

func secretFromRecord(gatewayNamespace, gatewayName, secretName string, rec Record) (*corev1.Secret, error) {
	data, err := json.Marshal(payloadFromRecord(rec))
	if err != nil {
		return nil, fmt.Errorf("gcpmembers: encoding bundle for %q: %w", rec.Name, err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: gatewayNamespace,
			Labels:    recordLabels(rec),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         wgnetv1alpha1.GroupVersion.String(),
				Kind:               "Gateway",
				Name:               gatewayName,
				UID:                rec.GatewayUID,
				Controller:         new(true),
				BlockOwnerDeletion: new(true),
			}},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{wg.BundleKey: data},
	}, nil
}

//go:fix inline

// splitCIDR splits a bundle payload's "<address>/<prefix>" into its parts. An empty value
// is a record written before any address was assigned and yields the zero pair.
func splitCIDR(address string) (string, int, error) {
	if address == "" {
		return "", 0, nil
	}
	host, prefix, found := strings.Cut(address, "/")
	if !found {
		return "", 0, fmt.Errorf("gcpmembers: bundle address %q is not in CIDR form", address)
	}
	ones, err := strconv.Atoi(prefix)
	if err != nil {
		return "", 0, fmt.Errorf("gcpmembers: bundle address %q has an unparsable prefix: %w", address, err)
	}
	return host, ones, nil
}

func (d *kubernetesDeps) GetRecord(ctx context.Context, gatewayNamespace, _, name string) (*Record, bool, error) {
	names, err := d.resolveNames(name)
	if err != nil {
		return nil, false, err
	}
	secret := &corev1.Secret{}
	if err := d.client.Get(ctx, client.ObjectKey{Namespace: gatewayNamespace, Name: names.KubernetesSecretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("gcpmembers: reading record secret %s/%s: %w", gatewayNamespace, names.KubernetesSecretName, err)
	}
	rec, err := recordFromSecret(secret)
	if err != nil {
		return nil, false, err
	}
	return &rec, true, nil
}

func (d *kubernetesDeps) CreateRecord(ctx context.Context, gatewayNamespace, gatewayName string, rec Record) error {
	names, err := d.resolveNames(rec.Name)
	if err != nil {
		return err
	}
	secret, err := secretFromRecord(gatewayNamespace, gatewayName, names.KubernetesSecretName, rec)
	if err != nil {
		return err
	}
	if err := d.client.Create(ctx, secret); err != nil {
		return fmt.Errorf("gcpmembers: creating record secret %s/%s: %w", gatewayNamespace, names.KubernetesSecretName, err)
	}
	return nil
}

func (d *kubernetesDeps) UpdateRecordLabels(ctx context.Context, gatewayNamespace, _, name string, labels map[string]string) error {
	names, err := d.resolveNames(name)
	if err != nil {
		return err
	}
	secret := &corev1.Secret{}
	if err := d.client.Get(ctx, client.ObjectKey{Namespace: gatewayNamespace, Name: names.KubernetesSecretName}, secret); err != nil {
		return fmt.Errorf("gcpmembers: reading record secret %s/%s for label update: %w", gatewayNamespace, names.KubernetesSecretName, err)
	}
	if secret.Labels == nil {
		secret.Labels = make(map[string]string, len(labels))
	}
	maps.Copy(secret.Labels, labels)
	if err := d.client.Update(ctx, secret); err != nil {
		return fmt.Errorf("gcpmembers: updating record secret %s/%s labels: %w", gatewayNamespace, names.KubernetesSecretName, err)
	}
	return nil
}

func (d *kubernetesDeps) DeleteRecord(ctx context.Context, gatewayNamespace, _, name string, uid types.UID, resourceVersion string) error {
	names, err := d.resolveNames(name)
	if err != nil {
		return err
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace:       gatewayNamespace,
		Name:            names.KubernetesSecretName,
		UID:             uid,
		ResourceVersion: resourceVersion,
	}}
	if err := d.client.Delete(ctx, secret, client.Preconditions{UID: &uid, ResourceVersion: &resourceVersion}); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("gcpmembers: deleting record secret %s/%s: %w", gatewayNamespace, names.KubernetesSecretName, err)
	}
	return nil
}

func (d *kubernetesDeps) ListRecordNames(ctx context.Context, gatewayNamespace, _ string) ([]string, error) {
	var secrets corev1.SecretList
	if err := d.client.List(ctx, &secrets, client.InNamespace(gatewayNamespace), client.MatchingLabels{labelGatewayUID: string(d.gatewayUID)}); err != nil {
		return nil, fmt.Errorf("gcpmembers: listing record secrets in %s: %w", gatewayNamespace, err)
	}
	names := make([]string, 0, len(secrets.Items))
	for _, s := range secrets.Items {
		if n := s.Labels[labelName]; n != "" {
			names = append(names, n)
		}
	}
	return names, nil
}

func (d *kubernetesDeps) GenerateKeypair() (string, string, error) {
	return wg.GenerateKeypair()
}

// The three secretmanager.gcp.m.upbound.io v1beta1 managed-resource kinds the composition
// renders per member (k8s/infra/crossplane/crossplane-providers/templates/gate-job.yaml:61-63,
// .test-output/helm-template.yaml:329-367): the confirmation read targets these by name.
var (
	gcpSecretManagerGroupVersion = schema.GroupVersion{Group: "secretmanager.gcp.m.upbound.io", Version: "v1beta1"}

	secretManagerSecretGVK          = gcpSecretManagerGroupVersion.WithKind("Secret")
	secretManagerSecretVersionGVK   = gcpSecretManagerGroupVersion.WithKind("SecretVersion")
	secretManagerSecretIAMMemberGVK = gcpSecretManagerGroupVersion.WithKind("SecretIAMMember")

	// Keep this local to avoid an import cycle with controller.
	xGatewayGCPGVK = schema.GroupVersionKind{Group: "infra.wgnet.dev", Version: "v1alpha1", Kind: "XGatewayGCP"}
)

// ConfirmManagedResourcesAbsent issues one uncached Get per of the three names, always all
// three (never short-circuiting on the first found), so the caller sees a stable "exactly
// one Get per name" interaction count regardless of which name is blocking.
func (d *kubernetesDeps) ConfirmManagedResourcesAbsent(ctx context.Context, names ManagedResourceNames) (bool, string, error) {
	checks := []struct {
		gvk   schema.GroupVersionKind
		name  string
		label string
	}{
		{secretManagerSecretGVK, names.CloudSecretName, "Secret Manager Secret"},
		{secretManagerSecretVersionGVK, names.CloudSecretVersionName, "Secret Manager SecretVersion"},
		{secretManagerSecretIAMMemberGVK, names.CloudSecretIAMMemberName, "Secret Manager SecretIAMMember"},
	}
	blockedReason := ""
	for _, c := range checks {
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(c.gvk)
		err := d.uncached.Get(ctx, client.ObjectKey{Name: c.name}, obj)
		switch {
		case err == nil:
			if blockedReason == "" {
				blockedReason = fmt.Sprintf("%s %q still present", c.label, c.name)
			}
		case apierrors.IsNotFound(err):
			continue
		default:
			return false, "", fmt.Errorf("gcpmembers: confirming %s %q absent: %w", c.label, c.name, err)
		}
	}
	if blockedReason != "" {
		return false, blockedReason, nil
	}
	return true, "", nil
}

func (d *kubernetesDeps) CompositeSynced(ctx context.Context, gatewayNamespace, gatewayName string) (bool, string, error) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(xGatewayGCPGVK)
	if err := d.uncached.Get(ctx, client.ObjectKey{Namespace: gatewayNamespace, Name: gatewayName}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return false, "composite not found", nil
		}
		return false, "", fmt.Errorf("gcpmembers: reading composite %s/%s: %w", gatewayNamespace, gatewayName, err)
	}
	conditions, _, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil {
		return false, "", fmt.Errorf("gcpmembers: reading composite %s/%s status.conditions: %w", gatewayNamespace, gatewayName, err)
	}
	generation := obj.GetGeneration()
	for _, raw := range conditions {
		cond, ok := raw.(map[string]any)
		if !ok || cond["type"] != "Synced" {
			continue
		}
		status, _ := cond["status"].(string)
		if status != "True" {
			return false, "composite Synced condition is not True", nil
		}
		observedGeneration, ok := conditionObservedGeneration(cond)
		if !ok || observedGeneration != generation {
			return false, "composite Synced condition has a stale observedGeneration", nil
		}
		return true, "", nil
	}
	return false, "composite has no Synced condition", nil
}

func conditionObservedGeneration(cond map[string]any) (int64, bool) {
	switch v := cond["observedGeneration"].(type) {
	case int64:
		return v, true
	case float64:
		return int64(v), true
	default:
		return 0, false
	}
}
