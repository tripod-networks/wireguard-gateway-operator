package controller

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/stretchr/testify/mock"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
	gcpdiscoverymocks "github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery/mocks"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpmembers"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

func credentialsSecretKey() client.ObjectKey {
	return client.ObjectKey{Namespace: "crossplane-system", Name: "gcp-creds"}
}

// discoveryTestConfig is reconcileConfig extended with the GCP credential settings
// reconcileMembers needs; the discovery tests bind their own credentials Secret.
func discoveryTestConfig() Config {
	cfg := reconcileConfig()
	cfg.GCPCredentialsSecret = "crossplane-system/gcp-creds"
	cfg.GCPCredentialsKey = "credentials.json"
	return cfg
}

// testMemberKeypair generates real WireGuard key material for a member record: the record's
// public key is derived from its private key on every read.
func testMemberKeypair(t *testing.T) (privateKey, publicKey string) {
	t.Helper()
	priv, pub, err := wg.GenerateKeypair()
	if err != nil {
		t.Fatalf("wg.GenerateKeypair: %v", err)
	}
	return priv, pub
}

// mustEnsureKeySecrets writes the Gateway's key Secrets, which the reconcile does before any
// membership pass: a member's bundle payload carries the link public key they hold.
func mustEnsureKeySecrets(ctx context.Context, t *testing.T, r *GatewayReconciler, gw *wgnetv1alpha1.Gateway) {
	t.Helper()
	if err := r.ensureSecrets(ctx, gw); err != nil {
		t.Fatalf("ensure key secrets: %v", err)
	}
}

func createCredentialsSecret(ctx context.Context, t *testing.T, r *GatewayReconciler, bytes []byte) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "crossplane-system"}}
	if err := r.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create crossplane-system namespace: %v", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "crossplane-system", Name: "gcp-creds"},
		Data:       map[string][]byte{"credentials.json": bytes},
	}
	if err := r.Create(ctx, secret); err != nil {
		t.Fatalf("create gcp-creds secret: %v", err)
	}
}

// TestReconcileMembersSkipsDiscoveryWithoutMIGName covers first half: no Compute
// call is issued (the injected constructor is never invoked) while migName is unpublished.
func TestReconcileMembersSkipsDiscoveryWithoutMIGName(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: discoveryTestConfig()}
	calls := stubbedConstructor(t)

	const ns = "disc-no-mig"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	mustCreate(ctx, t, te.client, gw)
	mustEnsureKeySecrets(ctx, t, r, gw)

	result, discoveryFailed, _, err := r.reconcileMembers(ctx, gw, "", nil)
	if err != nil {
		t.Fatalf("reconcileMembers: %v", err)
	}
	if result != nil {
		t.Errorf("result = %+v, want nil while migName is unpublished", result)
	}
	if discoveryFailed {
		t.Errorf("discoveryFailed = true, want false: an unpublished migName is not a failure")
	}
	if *calls != 0 {
		t.Errorf("discovery client constructor calls = %d, want 0", *calls)
	}
}

// TestReconcileMembersListsOnceMIGNamePublished covers second half: listing runs
// once migName appears.
func TestReconcileMembersListsOnceMIGNamePublished(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: discoveryTestConfig()}
	createCredentialsSecret(ctx, t, r, []byte("v1"))

	orig := newGCPDiscoveryClient
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	mockClient := gcpdiscoverymocks.NewMockClient(t)
	mockClient.EXPECT().
		List(ctx, "test-project", "us-central1", "edge-mig", mock.Anything, mock.Anything).
		Return(gcpdiscovery.Snapshot{}, nil).Once()
	newGCPDiscoveryClient = func(_ context.Context, _ []byte) (gcpdiscovery.Client, error) {
		return mockClient, nil
	}

	const ns = "disc-with-mig"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	mustCreate(ctx, t, te.client, gw)
	mustEnsureKeySecrets(ctx, t, r, gw)

	result, discoveryFailed, _, err := r.reconcileMembers(ctx, gw, "edge-mig", nil)
	if err != nil {
		t.Fatalf("reconcileMembers: %v", err)
	}
	if discoveryFailed {
		t.Errorf("discoveryFailed = true, want false")
	}
	if result == nil {
		t.Fatal("result = nil, want a computed Result")
	}
}

// TestReconcileMembersListErrorReportsDiscoveryFailed covers: a listing error yields
// an unusable pass reported as discoveryFailed, never a partial Result.
func TestReconcileMembersListErrorReportsDiscoveryFailed(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: discoveryTestConfig()}
	createCredentialsSecret(ctx, t, r, []byte("v1"))

	orig := newGCPDiscoveryClient
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	mockClient := gcpdiscoverymocks.NewMockClient(t)
	mockClient.EXPECT().
		List(ctx, "test-project", "us-central1", "edge-mig", mock.Anything, mock.Anything).
		Return(gcpdiscovery.Snapshot{}, errors.New("listing failed mid-pagination")).Once()
	newGCPDiscoveryClient = func(_ context.Context, _ []byte) (gcpdiscovery.Client, error) {
		return mockClient, nil
	}

	const ns = "disc-list-error"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	mustCreate(ctx, t, te.client, gw)
	mustEnsureKeySecrets(ctx, t, r, gw)

	result, discoveryFailed, message, err := r.reconcileMembers(ctx, gw, "edge-mig", nil)
	if err != nil {
		t.Fatalf("reconcileMembers: %v", err)
	}
	if !discoveryFailed {
		t.Fatal("discoveryFailed = false, want true")
	}
	if message == "" {
		t.Error("discoveryMessage is empty, want it to name the listing failure")
	}
	if result == nil || !result.Unusable {
		t.Errorf("result = %+v, want Unusable true", result)
	}
}

// TestReconcileMembersRebuildsClientOnCredentialRotation covers: editing the live
// credentials Secret mid-test rebuilds the discovery client on the next pass.
func TestReconcileMembersRebuildsClientOnCredentialRotation(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: discoveryTestConfig()}
	createCredentialsSecret(ctx, t, r, []byte("v1"))
	calls := stubbedConstructor(t)

	const ns = "disc-rotation"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	mustCreate(ctx, t, te.client, gw)
	mustEnsureKeySecrets(ctx, t, r, gw)

	if _, _, _, err := r.reconcileMembers(ctx, gw, "edge-mig", nil); err != nil {
		t.Fatalf("reconcileMembers (first pass): %v", err)
	}
	if *calls != 1 {
		t.Fatalf("constructor calls after first pass = %d, want 1", *calls)
	}

	var secret corev1.Secret
	if err := te.client.Get(ctx, credentialsSecretKey(), &secret); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	secret.Data["credentials.json"] = []byte("v2")
	if err := te.client.Update(ctx, &secret); err != nil {
		t.Fatalf("rotate credentials secret: %v", err)
	}

	if _, _, _, err := r.reconcileMembers(ctx, gw, "edge-mig", nil); err != nil {
		t.Fatalf("reconcileMembers (second pass): %v", err)
	}
	if *calls != 2 {
		t.Errorf("constructor calls after rotation = %d, want 2", *calls)
	}
}

func TestReconcileMembersRefreshesRecordedNames(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	cfg := discoveryTestConfig()
	cfg.GCPAddressRefreshInterval = 10 * time.Minute
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: cfg, now: func() time.Time { return now }}
	createCredentialsSecret(ctx, t, r, []byte("v1"))

	const ns = "disc-refresh-names"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	mustCreate(ctx, t, te.client, gw)
	mustEnsureKeySecrets(ctx, t, r, gw)
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)
	deps := gcpmembers.NewKubernetesDeps(te.client, te.client, gw.UID, gw.Spec.GCP.ProjectID)
	priv, pub := testMemberKeypair(t)
	if err := deps.CreateRecord(ctx, ns, ns, gcpmembers.Record{Name: "vm-a", GatewayUID: gw.UID, Project: gw.Spec.GCP.ProjectID, Slot: 0, PrivateKey: priv, PublicKey: pub, TunnelAddress: "10.99.0.1", SubnetPrefix: 29}); err != nil {
		t.Fatalf("create member record: %v", err)
	}

	orig := newGCPDiscoveryClient
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	mockClient := gcpdiscoverymocks.NewMockClient(t)
	recorded := []gcpdiscovery.Recorded{{Name: "vm-a"}}
	mockClient.EXPECT().List(ctx, "test-project", "us-central1", "edge-mig", recorded, []string{"vm-a"}).Return(gcpdiscovery.Snapshot{}, nil).Once()
	mockClient.EXPECT().List(ctx, "test-project", "us-central1", "edge-mig", recorded, []string(nil)).Return(gcpdiscovery.Snapshot{}, nil).Once()
	newGCPDiscoveryClient = func(context.Context, []byte) (gcpdiscovery.Client, error) { return mockClient, nil }

	for _, pass := range []string{"first", "within interval"} {
		if _, failed, _, err := r.reconcileMembers(ctx, gw, "edge-mig", nil); err != nil || failed {
			t.Fatalf("reconcile members %s: failed=%t err=%v", pass, failed, err)
		}
	}
}

// lbDiscoveryGateway creates a load-balanced Gateway with one valid forward, the shape the
// full-Reconcile discovery cases need to get past provisioning.
func lbDiscoveryGateway(ctx context.Context, t *testing.T, cl client.Client, ns string) *wgnetv1alpha1.Gateway {
	t.Helper()
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
	gw := gcpLBGateway(ns, ns)
	gw.Spec.Forwards = []wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}
	mustCreate(ctx, t, cl, gw)
	return gw
}

func reconcileOnce(ctx context.Context, t *testing.T, r *GatewayReconciler, gw *wgnetv1alpha1.Gateway, pass string) {
	t.Helper()
	if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err != nil {
		t.Fatalf("reconcile (%s): %v", pass, err)
	}
}

func setXGatewayGCPMIGName(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, migName string) {
	t.Helper()
	xg := newXGatewayGCP()
	mustGet(ctx, t, cl, key, xg)
	if err := unstructured.SetNestedField(xg.Object, migName, "status", "migName"); err != nil {
		t.Fatalf("set status.migName: %v", err)
	}
	if err := cl.Status().Update(ctx, xg); err != nil {
		t.Fatalf("update xgatewaygcp status: %v", err)
	}
}

func linkPeers(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway) []link.Peer {
	t.Helper()
	var cm corev1.ConfigMap
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: gw.Namespace, Name: linkComponentName(gw)}, &cm)
	var rc link.RuntimeConfig
	if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
		t.Fatalf("decode link config: %v", err)
	}
	return rc.WireGuard.Peers
}

func compositeTargetSize(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway) int64 {
	t.Helper()
	xg := newXGatewayGCP()
	mustGet(ctx, t, cl, client.ObjectKeyFromObject(gw), xg)
	size, found, err := unstructured.NestedInt64(xg.Object, "spec", "targetSize")
	if err != nil || !found {
		t.Fatalf("read spec.targetSize: found=%v err=%v", found, err)
	}
	return size
}

func compositeMembers(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway) []any {
	t.Helper()
	xg := newXGatewayGCP()
	mustGet(ctx, t, cl, client.ObjectKeyFromObject(gw), xg)
	members, found, err := unstructured.NestedSlice(xg.Object, "spec", "members")
	if err != nil || !found {
		t.Fatalf("read spec.members: found=%v err=%v", found, err)
	}
	return members
}

func memberRecords(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway) []gcpmembers.Record {
	t.Helper()
	deps := gcpmembers.NewKubernetesDeps(cl, cl, gw.UID, gw.Spec.GCP.ProjectID)
	names, err := deps.ListRecordNames(ctx, gw.Namespace, gw.Name)
	if err != nil {
		t.Fatalf("list record names: %v", err)
	}
	records := make([]gcpmembers.Record, 0, len(names))
	for _, name := range names {
		rec, found, err := deps.GetRecord(ctx, gw.Namespace, gw.Name, name)
		if err != nil || !found {
			t.Fatalf("get record %q: found=%v err=%v", name, found, err)
		}
		rec.ResourceVersion = ""
		records = append(records, *rec)
	}
	return records
}

// listedMemberSnapshot is one present member with a detail read, the shape a first usable pass
// needs to produce a record, a peer and a roster entry.
func listedMemberSnapshot(name, externalAddress string) gcpdiscovery.Snapshot {
	return gcpdiscovery.Snapshot{
		Members: []gcpdiscovery.ListedMember{{
			Name: name, Action: gcpdiscovery.ActionNone, InstanceID: "1111",
			Verdict: gcpdiscovery.VerdictPresent, Zone: "us-central1-a", TemplateRevision: "rev-1",
		}},
		Details: map[string]gcpdiscovery.Detail{name: {
			Name: name, InstanceID: "1111", ExternalAddress: externalAddress,
			Reason: gcpdiscovery.DetailReasonNoRecordedAddress,
		}},
	}
}

// TestReconcileDiscoveryStartsOnMIGName covers through the real Reconcile: no List runs
// while the composite publishes no migName, and exactly one runs on the pass after it appears.
func TestReconcileDiscoveryStartsOnMIGName(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
		Config: discoveryTestConfig(), Recorder: &fakeEventRecorder{}}
	createCredentialsSecret(ctx, t, r, []byte("v1"))

	listCalls := 0
	orig := newGCPDiscoveryClient
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	mockClient := gcpdiscoverymocks.NewMockClient(t)
	mockClient.EXPECT().
		List(mock.Anything, mock.Anything, mock.Anything, "edge-mig", mock.Anything, mock.Anything).
		Run(func(context.Context, string, string, string, []gcpdiscovery.Recorded, []string) { listCalls++ }).
		Return(gcpdiscovery.Snapshot{}, nil)
	newGCPDiscoveryClient = func(context.Context, []byte) (gcpdiscovery.Client, error) { return mockClient, nil }

	gw := lbDiscoveryGateway(ctx, t, te.client, "disc-reconcile-mig")
	reconcileOnce(ctx, t, r, gw, "finalizer")
	reconcileOnce(ctx, t, r, gw, "composite creation")
	if listCalls != 0 {
		t.Fatalf("List calls before migName is published = %d, want 0", listCalls)
	}

	setXGatewayGCPMIGName(ctx, t, te.client, client.ObjectKeyFromObject(gw), "edge-mig")
	reconcileOnce(ctx, t, r, gw, "migName published")
	if listCalls != 1 {
		t.Errorf("List calls after migName is published = %d, want 1", listCalls)
	}
}

// TestReconcileListErrorPreservesMembership covers through the real Reconcile: a listing
// A refresh runs once the configured interval elapses.
func TestReconcileListErrorPreservesMembership(t *testing.T) {
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
	mockClient.EXPECT().
		List(mock.Anything, mock.Anything, mock.Anything, "edge-mig", mock.Anything, mock.Anything).
		Return(gcpdiscovery.Snapshot{}, errors.New("listing failed mid-pagination")).Once()
	newGCPDiscoveryClient = func(context.Context, []byte) (gcpdiscovery.Client, error) { return mockClient, nil }

	gw := lbDiscoveryGateway(ctx, t, te.client, "disc-reconcile-list-error")
	reconcileOnce(ctx, t, r, gw, "finalizer")
	reconcileOnce(ctx, t, r, gw, "composite creation")
	setXGatewayGCPMIGName(ctx, t, te.client, client.ObjectKeyFromObject(gw), "edge-mig")
	reconcileOnce(ctx, t, r, gw, "usable pass")

	wantPeers := linkPeers(ctx, t, te.client, gw)
	wantRecords := memberRecords(ctx, t, te.client, gw)
	wantTargetSize := compositeTargetSize(ctx, t, te.client, gw)
	wantMembers := compositeMembers(ctx, t, te.client, gw)
	if len(wantPeers) != 1 || len(wantRecords) != 1 || len(wantMembers) != 1 {
		t.Fatalf("after the usable pass: peers = %+v, records = %+v, members = %+v, want exactly one of each",
			wantPeers, wantRecords, wantMembers)
	}

	reconcileOnce(ctx, t, r, gw, "listing error")

	if got := linkPeers(ctx, t, te.client, gw); !reflect.DeepEqual(got, wantPeers) {
		t.Errorf("link peers after the listing error = %+v, want exactly %+v", got, wantPeers)
	}
	if got := memberRecords(ctx, t, te.client, gw); !reflect.DeepEqual(got, wantRecords) {
		t.Errorf("member records after the listing error = %+v, want exactly %+v", got, wantRecords)
	}
	if got := compositeTargetSize(ctx, t, te.client, gw); got != wantTargetSize {
		t.Errorf("spec.targetSize after the listing error = %d, want %d", got, wantTargetSize)
	}
	if got := compositeMembers(ctx, t, te.client, gw); !reflect.DeepEqual(got, wantMembers) {
		t.Errorf("spec.members after the listing error = %+v, want exactly %+v", got, wantMembers)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), &got)
	condition := findCondition(got.Status.Conditions, conditionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != reasonMemberDiscoveryFailed {
		t.Errorf("Ready condition = %+v, want False %q", condition, reasonMemberDiscoveryFailed)
	}
}

// TestReconcileRebuildsClientOnCredentialRotation covers through the real Reconcile: an
// edit to the live credentials Secret rebuilds the client, and the old one serves no further call.
func TestReconcileRebuildsClientOnCredentialRotation(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
		Config: discoveryTestConfig(), Recorder: &fakeEventRecorder{}}
	createCredentialsSecret(ctx, t, r, []byte("v1"))

	oldClient := gcpdiscoverymocks.NewMockClient(t)
	oldClient.EXPECT().
		List(mock.Anything, mock.Anything, mock.Anything, "edge-mig", mock.Anything, mock.Anything).
		Return(gcpdiscovery.Snapshot{}, nil).Once()
	newClient := gcpdiscoverymocks.NewMockClient(t)
	newClient.EXPECT().
		List(mock.Anything, mock.Anything, mock.Anything, "edge-mig", mock.Anything, mock.Anything).
		Return(gcpdiscovery.Snapshot{}, nil).Once()

	orig := newGCPDiscoveryClient
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	var built []string
	newGCPDiscoveryClient = func(_ context.Context, credentialJSON []byte) (gcpdiscovery.Client, error) {
		built = append(built, string(credentialJSON))
		if string(credentialJSON) == "v1" {
			return oldClient, nil
		}
		return newClient, nil
	}

	gw := lbDiscoveryGateway(ctx, t, te.client, "disc-reconcile-rotation")
	reconcileOnce(ctx, t, r, gw, "finalizer")
	reconcileOnce(ctx, t, r, gw, "composite creation")
	setXGatewayGCPMIGName(ctx, t, te.client, client.ObjectKeyFromObject(gw), "edge-mig")
	reconcileOnce(ctx, t, r, gw, "first listing")

	var secret corev1.Secret
	mustGet(ctx, t, te.client, credentialsSecretKey(), &secret)
	secret.Data["credentials.json"] = []byte("v2")
	if err := te.client.Update(ctx, &secret); err != nil {
		t.Fatalf("rotate credentials secret: %v", err)
	}

	reconcileOnce(ctx, t, r, gw, "listing after rotation")
	if want := []string{"v1", "v2"}; !slices.Equal(built, want) {
		t.Errorf("constructor credential bytes = %v, want exactly %v", built, want)
	}
}

// TestSteadyRequeue covers requeue bound: a load-balanced pass re-lists no sooner
// than GCPDiscoveryInterval, every other Gateway keeps the general RequeueInterval.
func TestSteadyRequeue(t *testing.T) {
	tests := []struct {
		name              string
		loadBalanced      bool
		requeueInterval   time.Duration
		discoveryInterval time.Duration
		want              time.Duration
	}{
		{"single_instance_keeps_the_general_interval", false, 30 * time.Second, 5 * time.Minute, 30 * time.Second},
		{"load_balanced_takes_the_discovery_floor", true, 30 * time.Second, 5 * time.Minute, 5 * time.Minute},
		{"load_balanced_keeps_a_slower_general_interval", true, 10 * time.Minute, 5 * time.Minute, 10 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GatewayReconciler{Config: Config{
				RequeueInterval:      tt.requeueInterval,
				GCPDiscoveryInterval: tt.discoveryInterval,
			}}
			if got := r.steadyRequeue(tt.loadBalanced); got != tt.want {
				t.Errorf("steadyRequeue(%v) = %s, want %s", tt.loadBalanced, got, tt.want)
			}
		})
	}
}

func TestDiscoveryRecorded(t *testing.T) {
	tests := []struct {
		name    string
		records []gcpmembers.Record
		want    []gcpdiscovery.Recorded
	}{
		{name: "record with address", records: []gcpmembers.Record{{Name: "vm-a", ExternalAddress: "203.0.113.1", InstanceID: "42"}}, want: []gcpdiscovery.Recorded{{Name: "vm-a", ExternalAddress: "203.0.113.1", InstanceID: "42"}}},
		{name: "record without address", records: []gcpmembers.Record{{Name: "vm-a", InstanceID: "42"}}, want: []gcpdiscovery.Recorded{{Name: "vm-a", InstanceID: "42"}}},
		{name: "no records", want: []gcpdiscovery.Recorded{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := discoveryRecorded(tt.records)
			if len(got) != len(tt.want) {
				t.Fatalf("records = %#v, want %#v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("records = %#v, want %#v", got, tt.want)
				}
			}
		})
	}
}

func TestGCPAddressRefreshDue(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		last *time.Time
		want bool
	}{
		{name: "no entry", want: true},
		{name: "below interval", last: new(now.Add(-9 * time.Minute)), want: false},
		{name: "at interval", last: new(now.Add(-10 * time.Minute)), want: true},
		{name: "above interval", last: new(now.Add(-11 * time.Minute)), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var refreshed sync.Map
			if tt.last != nil {
				refreshed.Store("ns/gw", *tt.last)
			}
			if got := gcpAddressRefreshDue(&refreshed, "ns/gw", now, 10*time.Minute); got != tt.want {
				t.Errorf("due = %t, want %t", got, tt.want)
			}
		})
	}
}
