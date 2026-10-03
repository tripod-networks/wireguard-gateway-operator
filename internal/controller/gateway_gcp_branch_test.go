package controller

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stretchr/testify/mock"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
	gcpdiscoverymocks "github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery/mocks"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpmembers"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// TestReconcileOverCapacityChangesNothing verifies the over-capacity branch.
func TestReconcileOverCapacityChangesNothing(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)

	const ns = "gcp-over-capacity"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, te.client, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
	gw := gcpLBGateway(ns, ns)
	gw.Spec.GCP.Replicas = 6 // the default /29 holds 5
	gw.Spec.Forwards = []wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}
	mustCreate(ctx, t, te.client, gw)

	recorder := &fakeEventRecorder{}
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
		Config: reconcileConfig(), Recorder: recorder}
	for _, pass := range []string{"finalizer", "capacity", "capacity repeat"} {
		reconcileOnce(ctx, t, r, gw, pass)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), &got)
	condition := findCondition(got.Status.Conditions, conditionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse ||
		condition.Reason != reasonInsufficientTunnelAddresses || !strings.Contains(condition.Message, "capacity 5") {
		t.Errorf("Ready condition = %+v, want False %q mentioning %q", condition, reasonInsufficientTunnelAddresses, "capacity 5")
	}

	gotEvents := make([]string, 0, len(recorder.events))
	for _, ev := range recorder.events {
		gotEvents = append(gotEvents, ev.reason)
	}
	if want := []string{reasonInsufficientTunnelAddresses}; !slices.Equal(gotEvents, want) {
		t.Errorf("event reasons = %v, want exactly %v", gotEvents, want)
	}

	var secrets corev1.SecretList
	if err := te.client.List(ctx, &secrets, client.InNamespace(ns)); err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	names := make([]string, 0, len(secrets.Items))
	for _, s := range secrets.Items {
		names = append(names, s.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{}) {
		t.Errorf("secrets in %s = %v, want exactly none: the capacity check precedes every write", ns, names)
	}

	assertXGatewayGCPNames(ctx, t, te.client, ns, []string{})
}

// assertXGatewayGCPNames compares the composites in a namespace as a whole: the complete
// inventory of the Gateway's composite children there.
func assertXGatewayGCPNames(ctx context.Context, t *testing.T, cl client.Client, namespace string, want []string) {
	t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(XGatewayGCPGVK.GroupVersion().WithKind(XGatewayGCPGVK.Kind + "List"))
	if err := cl.List(ctx, list, client.InNamespace(namespace)); err != nil {
		t.Fatalf("list xgatewaygcps in %s: %v", namespace, err)
	}
	got := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		got = append(got, item.GetName())
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("xgatewaygcps in %s = %v, want exactly %v", namespace, got, want)
	}
}

// TestReconcileSingleInstanceRoster verifies the single-instance roster branch.
func TestReconcileSingleInstanceRoster(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)

	const ns = "gcp-single-roster"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, te.client, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
	gw := newGateway(ns, ns, []wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}, nil)
	// The apiserver assigns the UID the record naming base derives from.
	gw.UID = ""
	mustCreate(ctx, t, te.client, gw)
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)

	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
		Config: reconcileConfig(), Recorder: &fakeEventRecorder{}}
	reconcileOnce(ctx, t, r, gw, "finalizer")
	reconcileOnce(ctx, t, r, gw, "composite creation")

	base, err := gcpmembers.NameBase(string(gw.UID), gw.Spec.GCP.ProjectID)
	if err != nil {
		t.Fatalf("gcpmembers.NameBase: %v", err)
	}
	xg := newXGatewayGCP()
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), xg)
	secretID, _, err := unstructured.NestedString(xg.Object, "spec", "secretId")
	if err != nil {
		t.Fatalf("read spec.secretId: %v", err)
	}
	if secretID != base {
		t.Errorf("spec.secretId = %q, want the record naming base %q", secretID, base)
	}
	const instanceName = "gw-edge-9x2k"
	setXGatewayGCPInstanceName(ctx, t, te.client, client.ObjectKeyFromObject(gw), instanceName)
	reconcileOnce(ctx, t, r, gw, "instance name published")

	names, err := gcpmembers.NameResourceNames(string(gw.UID), gw.Spec.GCP.ProjectID, instanceName)
	if err != nil {
		t.Fatalf("gcpmembers.NameResourceNames: %v", err)
	}
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), xg)
	members, _, err := unstructured.NestedSlice(xg.Object, "spec", "members")
	if err != nil {
		t.Fatalf("read spec.members: %v", err)
	}
	want := []any{map[string]any{
		"name":                     instanceName,
		"slot":                     int64(0),
		"tunnelAddress":            effectiveWGGatewayAddress(gw),
		"kubernetesSecretName":     names.KubernetesSecretName,
		"cloudSecretName":          names.CloudSecretName,
		"cloudSecretVersionName":   names.CloudSecretVersionName,
		"cloudSecretIamMemberName": names.CloudSecretIAMMemberName,
	}}
	if !reflect.DeepEqual(members, want) {
		t.Fatalf("spec.members = %#v, want %#v", members, want)
	}

	var bundleSecret corev1.Secret
	mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: bundleSecretName(gw)}, &bundleSecret)
	gatewayPrivateKey, rest, _ := strings.Cut(string(bundleSecret.Data[wg.BundleKey]), "\n")
	linkPublicKey, _, _ := strings.Cut(rest, "\n")

	var record corev1.Secret
	mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: names.KubernetesSecretName}, &record)
	var payload map[string]string
	if err := json.Unmarshal(record.Data[wg.BundleKey], &payload); err != nil {
		t.Fatalf("decode member bundle payload: %v", err)
	}
	wantPayload := map[string]string{
		"privateKey":     gatewayPrivateKey,
		"address":        effectiveWGGatewayAddress(gw) + "/29",
		"slot":           "0",
		"peerPublicKey":  linkPublicKey,
		"peerAllowedIPs": effectiveWGLinkAddress(gw) + "/32",
	}
	if !maps.Equal(payload, wantPayload) {
		t.Errorf("member bundle payload = %#v, want %#v", payload, wantPayload)
	}
}

func setXGatewayGCPInstanceName(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, instanceName string) {
	t.Helper()
	xg := newXGatewayGCP()
	mustGet(ctx, t, cl, key, xg)
	if err := unstructured.SetNestedField(xg.Object, instanceName, "status", "instanceName"); err != nil {
		t.Fatalf("set status.instanceName: %v", err)
	}
	if err := cl.Status().Update(ctx, xg); err != nil {
		t.Fatalf("update xgatewaygcp status: %v", err)
	}
}

// TestReconcileLinkPeerBranch verifies link peers for each gateway branch.
func TestReconcileLinkPeerBranch(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)

	tests := []struct {
		name      string
		namespace string
		build     func(ns string) *wgnetv1alpha1.Gateway
		// arrange runs between the two passes, so a row can publish link state the second
		// pass reads back.
		arrange func(t *testing.T, gw *wgnetv1alpha1.Gateway)
		// wantPeers renders the expected peer list from the key material the pass generated.
		wantPeers      func(t *testing.T, ns string, gw *wgnetv1alpha1.Gateway) []link.Peer
		wantHealthPort int32
		wantReason     string
		wantMessage    string
	}{
		{
			name:      "load-balanced, MIG not observed",
			namespace: "gcp-lb-pending",
			build:     func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			wantPeers: func(*testing.T, string, *wgnetv1alpha1.Gateway) []link.Peer {
				return []link.Peer{}
			},
			wantHealthPort: 27000,
			wantReason:     reasonMembersNotReady,
			wantMessage:    "no fleet member observed yet",
		},
		{
			name:      "load-balanced, MIG not observed, holder pod ready",
			namespace: "gcp-lb-pending-holder-ready",
			build:     func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			arrange: func(t *testing.T, gw *wgnetv1alpha1.Gateway) {
				t.Helper()
				setLinkLeaseActive(ctx, t, te.client, client.ObjectKeyFromObject(gw),
					linkComponentName(gw)+"-0", true, "node-a")
			},
			wantPeers: func(*testing.T, string, *wgnetv1alpha1.Gateway) []link.Peer {
				return []link.Peer{}
			},
			wantHealthPort: 27000,
			wantReason:     reasonMembersNotReady,
			wantMessage:    "no fleet member observed yet",
		},
		{
			name:      "single instance",
			namespace: "gcp-single-pending",
			build: func(ns string) *wgnetv1alpha1.Gateway {
				return newGateway(ns, ns, nil, nil)
			},
			wantPeers: func(t *testing.T, ns string, gw *wgnetv1alpha1.Gateway) []link.Peer {
				t.Helper()
				var secret corev1.Secret
				mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: linkSecretName(gw)}, &secret)
				return []link.Peer{{
					Slot:                0,
					PublicKey:           string(secret.Data[wg.LinkPeerPublicKey]),
					AllowedIPs:          []string{effectiveWGSubnet(gw)},
					PersistentKeepalive: int(effectiveWGKeepalive(gw)),
				}}
			},
			wantHealthPort: 27000,
			wantReason:     reasonProvisioning,
		},
		{
			name:      "single instance, custom health port",
			namespace: "gcp-single-custom-health-port",
			build: func(ns string) *wgnetv1alpha1.Gateway {
				gw := newGateway(ns, ns, nil, nil)
				gw.Spec.Link.HealthPort = 8181
				return gw
			},
			wantPeers: func(t *testing.T, ns string, gw *wgnetv1alpha1.Gateway) []link.Peer {
				t.Helper()
				var secret corev1.Secret
				mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: linkSecretName(gw)}, &secret)
				return []link.Peer{{
					Slot:                0,
					PublicKey:           string(secret.Data[wg.LinkPeerPublicKey]),
					AllowedIPs:          []string{effectiveWGSubnet(gw)},
					PersistentKeepalive: int(effectiveWGKeepalive(gw)),
				}}
			},
			wantHealthPort: 8181,
			wantReason:     reasonProvisioning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := tt.namespace
			mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
			mustCreate(ctx, t, te.client, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
			gw := tt.build(ns)
			gw.Spec.Forwards = []wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}
			mustCreate(ctx, t, te.client, gw)

			r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
				Config: reconcileConfig(), Recorder: &fakeEventRecorder{}}
			reconcileOnce(ctx, t, r, gw, "finalizer")
			if tt.arrange != nil {
				tt.arrange(t, gw)
			}
			reconcileOnce(ctx, t, r, gw, "link rendered")

			var responderSvc corev1.Service
			mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: responderComponentName(gw)}, &responderSvc)
			if responderSvc.Spec.ClusterIP == "" {
				t.Fatalf("responder service %s/%s has no ClusterIP", ns, responderComponentName(gw))
			}

			var cm corev1.ConfigMap
			mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: linkComponentName(gw)}, &cm)
			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)
			want := link.RuntimeConfig{
				TrafficPolicy:   string(wgnetv1alpha1.TrafficPolicyCluster),
				HealthPort:      int(tt.wantHealthPort),
				ResponderPort:   int(effectiveResponderPort(gw)),
				ResponderTarget: responderSvc.Spec.ClusterIP,
				WireGuard: link.WireGuard{
					Address: effectiveWGLinkAddress(gw) + "/29",
					MTU:     int(effectiveWGMTU(gw)),
					Peers:   tt.wantPeers(t, ns, gw),
				},
				Forwards: []link.Forward{{
					Name:       "tcp-443",
					PublicPort: 443,
					Protocol:   "tcp",
					Service:    forwardServiceFQDN(gw.Spec.Forwards[0], gw),
					TargetPort: 443,
				}},
			}
			if !reflect.DeepEqual(rc, want) {
				t.Errorf("link runtime config = %#v, want %#v", rc, want)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), &got)
			condition := findCondition(got.Status.Conditions, conditionReady)
			if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != tt.wantReason {
				t.Fatalf("Ready condition = %+v, want False %q", condition, tt.wantReason)
			}
			if tt.wantMessage != "" && condition.Message != tt.wantMessage {
				t.Errorf("Ready message = %q, want %q", condition.Message, tt.wantMessage)
			}
		})
	}
}

// TestReconcileOverCapacityComposite verifies the retained composite state.
func TestReconcileOverCapacityComposite(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)

	tests := []struct {
		name            string
		namespace       string
		createComposite bool
		wantApplied     bool
	}{
		{name: "keeps the existing composite when the fleet is at capacity", namespace: "gcp-cap-existing", createComposite: true, wantApplied: true},
		{name: "does not create a composite when the fleet is at capacity", namespace: "gcp-cap-absent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := tt.namespace
			mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
			mustCreate(ctx, t, te.client, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
			gw := gcpLBGateway(ns, ns)
			gw.Spec.GCP.Replicas = 2
			gw.Spec.Forwards = []wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}
			mustCreate(ctx, t, te.client, gw)
			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)

			r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
				Config: reconcileConfig(), Recorder: &fakeEventRecorder{}}
			reconcileOnce(ctx, t, r, gw, "finalizer")
			if tt.createComposite {
				reconcileOnce(ctx, t, r, gw, "composite creation")
			}

			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)
			gw.Spec.GCP.Replicas = 6 // the default /29 holds 5
			gw.Spec.GCP.LoadBalancer.SessionAffinity = "CLIENT_IP"
			if err := te.client.Update(ctx, gw); err != nil {
				t.Fatalf("update gateway: %v", err)
			}
			reconcileOnce(ctx, t, r, gw, "over capacity")

			if !tt.wantApplied {
				assertXGatewayGCPNames(ctx, t, te.client, ns, []string{})
				return
			}
			assertXGatewayGCPNames(ctx, t, te.client, ns, []string{gw.Name})
			xg := newXGatewayGCP()
			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), xg)
			targetSize, _, err := unstructured.NestedInt64(xg.Object, "spec", "targetSize")
			if err != nil {
				t.Fatalf("read spec.targetSize: %v", err)
			}
			if targetSize != 2 {
				t.Errorf("spec.targetSize = %d, want the last accepted 2", targetSize)
			}
			assertNestedString(t, xg, "CLIENT_IP", "spec", "sessionAffinity")
			members, _, err := unstructured.NestedSlice(xg.Object, "spec", "members")
			if err != nil {
				t.Fatalf("read spec.members: %v", err)
			}
			if !reflect.DeepEqual(members, []any{}) {
				t.Errorf("spec.members = %#v, want the preserved empty roster", members)
			}
		})
	}
}

// TestReconcileBlankMIGNamePreservesRoster verifies dependency waiting retains the roster.
func TestReconcileBlankMIGNamePreservesRoster(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
		Config: discoveryTestConfig(), Recorder: &fakeEventRecorder{}}
	createCredentialsSecret(ctx, t, r, []byte("v1"))

	orig := newGCPDiscoveryClient
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	mockClient := gcpdiscoverymocks.NewMockClient(t)
	mockClient.EXPECT().
		List(mock.Anything, mock.Anything, mock.Anything, "edge-mig", mock.Anything, mock.Anything).
		Return(listedMemberSnapshot("vm-a", "203.0.113.10"), nil).Once()
	newGCPDiscoveryClient = func(context.Context, []byte) (gcpdiscovery.Client, error) { return mockClient, nil }

	const ns = "gcp-blank-mig"
	gw := lbDiscoveryGateway(ctx, t, te.client, ns)
	reconcileOnce(ctx, t, r, gw, "finalizer")
	reconcileOnce(ctx, t, r, gw, "composite creation")
	setXGatewayGCPMIGName(ctx, t, te.client, client.ObjectKeyFromObject(gw), "edge-mig")
	reconcileOnce(ctx, t, r, gw, "usable pass")

	wantMembers := compositeMembers(ctx, t, te.client, gw)
	wantSecrets := secretNames(ctx, t, te.client, ns)
	if len(wantMembers) != 1 {
		t.Fatalf("spec.members after the usable pass = %+v, want exactly one member", wantMembers)
	}

	setXGatewayGCPMIGName(ctx, t, te.client, client.ObjectKeyFromObject(gw), "")
	reconcileOnce(ctx, t, r, gw, "migName withdrawn")

	if got := compositeMembers(ctx, t, te.client, gw); !reflect.DeepEqual(got, wantMembers) {
		t.Errorf("spec.members with no published migName = %+v, want exactly %+v", got, wantMembers)
	}
	if got := secretNames(ctx, t, te.client, ns); !slices.Equal(got, wantSecrets) {
		t.Errorf("secrets in %s with no published migName = %v, want exactly %v", ns, got, wantSecrets)
	}
}

// secretNames is the sorted inventory of Secrets in a namespace: the Gateway's key Secrets plus
// one record Secret per roster member.
func secretNames(ctx context.Context, t *testing.T, cl client.Client, namespace string) []string {
	t.Helper()
	var secrets corev1.SecretList
	if err := cl.List(ctx, &secrets, client.InNamespace(namespace)); err != nil {
		t.Fatalf("list secrets in %s: %v", namespace, err)
	}
	names := make([]string, 0, len(secrets.Items))
	for _, s := range secrets.Items {
		names = append(names, s.Name)
	}
	slices.Sort(names)
	return names
}

// TestWarnSuppressionClearsOnRecovery verifies warning suppression resets after recovery.
func TestWarnSuppressionClearsOnRecovery(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)

	tests := []struct {
		name       string
		namespace  string
		build      func(ns string) *wgnetv1alpha1.Gateway
		breakSpec  func(gw *wgnetv1alpha1.Gateway)
		fixSpec    func(gw *wgnetv1alpha1.Gateway)
		wantReason string
	}{
		{
			name:       "emits the capacity warning again after recovery",
			namespace:  "warn-capacity",
			build:      func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			breakSpec:  func(gw *wgnetv1alpha1.Gateway) { gw.Spec.GCP.Replicas = 6 }, // the default /29 holds 5
			fixSpec:    func(gw *wgnetv1alpha1.Gateway) { gw.Spec.GCP.Replicas = 2 },
			wantReason: reasonInsufficientTunnelAddresses,
		},
		{
			name: "emits the tunnel address warning again after recovery",
			// A load-balanced Gateway's tunnel addresses are immutable, so this row is
			// single-Instance: only there can a pass correct them and break them again.
			namespace:  "warn-tunnel",
			build:      func(ns string) *wgnetv1alpha1.Gateway { return newGateway(ns, ns, nil, nil) },
			breakSpec:  func(gw *wgnetv1alpha1.Gateway) { gw.Spec.Wireguard.LinkAddress = "10.99.1.9" },
			fixSpec:    func(gw *wgnetv1alpha1.Gateway) { gw.Spec.Wireguard.LinkAddress = "10.99.0.2" },
			wantReason: reasonInvalidTunnelAddresses,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := tt.namespace
			mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
			mustCreate(ctx, t, te.client, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
			gw := tt.build(ns)
			gw.Spec.Forwards = []wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}
			mustCreate(ctx, t, te.client, gw)

			recorder := &fakeEventRecorder{}
			r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
				Config: reconcileConfig(), Recorder: recorder}
			responderPodName := "gateway-responder-warn-suppression-" + ns
			createResponderPod(ctx, t, te.client, ns, responderPodName, "node-a", "10.0.1.5", responderSelectorLabels(gw))
			t.Cleanup(func() {
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: responderPodName}}
				if err := te.client.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
					t.Logf("delete responder pod %s/%s: %v", ns, responderPodName, err)
				}
			})
			reconcileOnce(ctx, t, r, gw, "finalizer")
			for _, pass := range []struct {
				name   string
				mutate func(gw *wgnetv1alpha1.Gateway)
			}{{"broken", tt.breakSpec}, {"corrected", tt.fixSpec}, {"broken again", tt.breakSpec}} {
				mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)
				pass.mutate(gw)
				if err := te.client.Update(ctx, gw); err != nil {
					t.Fatalf("update gateway (%s): %v", pass.name, err)
				}
				reconcileOnce(ctx, t, r, gw, pass.name)
			}

			gotEvents := make([]string, 0, len(recorder.events))
			for _, ev := range recorder.events {
				gotEvents = append(gotEvents, ev.reason)
			}
			if want := []string{tt.wantReason, tt.wantReason}; !slices.Equal(gotEvents, want) {
				t.Errorf("event reasons = %v, want exactly %v", gotEvents, want)
			}
		})
	}
}
