package gcpmembers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// waitForRecordGone polls deps.GetRecord (a cached read) until it observes name absent, so a
// test's next step never races the informer cache's delivery of a delete it already issued.
func waitForRecordGone(ctx context.Context, t *testing.T, deps Deps, ns, gatewayName, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, found, err := deps.GetRecord(ctx, ns, gatewayName, name); err == nil && !found {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for record %q to be observed gone", name)
}

// waitForRecord polls the cached GetRecord until ready is true: a write reaches the API server
// before the informer cache, so a pass could otherwise read the state before its own update.
func waitForRecord(ctx context.Context, t *testing.T, deps Deps, ns, gatewayName, name string, ready func(Record) bool) Record {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last Record
	for time.Now().Before(deadline) {
		if rec, found, err := deps.GetRecord(ctx, ns, gatewayName, name); err == nil && found {
			last = *rec
			if ready(last) {
				return last
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for record %q to reach the expected state; last observed %+v", name, last)
	return Record{}
}

func createNamespace(ctx context.Context, t *testing.T, te *testEnv) string {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "gcpmembers-test-"}}
	if err := te.client.Create(ctx, ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	return ns.Name
}

// createSyncedComposite creates a stand-in XGatewayGCP composite and immediately reports it
// Synced=True with observedGeneration matching its own metadata.generation.
func createSyncedComposite(ctx context.Context, t *testing.T, te *testEnv, ns, name string) {
	t.Helper()
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(xGatewayGCPGVK)
	obj.SetNamespace(ns)
	obj.SetName(name)
	if err := unstructured.SetNestedField(obj.Object, map[string]any{}, "spec"); err != nil {
		t.Fatalf("set composite spec: %v", err)
	}
	if err := te.client.Create(ctx, obj); err != nil {
		t.Fatalf("create composite: %v", err)
	}
	setCompositeCondition(ctx, t, te, ns, name, "True", obj.GetGeneration())
}

func setCompositeCondition(ctx context.Context, t *testing.T, te *testEnv, ns, name, status string, observedGeneration int64) {
	t.Helper()
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(xGatewayGCPGVK)
	if err := te.uncached.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj); err != nil {
		t.Fatalf("read composite for status update: %v", err)
	}
	condition := map[string]any{
		"type":               "Synced",
		"status":             status,
		"observedGeneration": observedGeneration,
	}
	if err := unstructured.SetNestedSlice(obj.Object, []any{condition}, "status", "conditions"); err != nil {
		t.Fatalf("set composite status.conditions: %v", err)
	}
	if err := te.client.Status().Update(ctx, obj); err != nil {
		t.Fatalf("update composite status: %v", err)
	}
}

func clearCompositeConditions(ctx context.Context, t *testing.T, te *testEnv, ns, name string) {
	t.Helper()
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(xGatewayGCPGVK)
	if err := te.uncached.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj); err != nil {
		t.Fatalf("read composite for status update: %v", err)
	}
	if err := unstructured.SetNestedSlice(obj.Object, []any{}, "status", "conditions"); err != nil {
		t.Fatalf("clear composite status.conditions: %v", err)
	}
	if err := te.client.Status().Update(ctx, obj); err != nil {
		t.Fatalf("update composite status: %v", err)
	}
}

func createStandIn(ctx context.Context, t *testing.T, te *testEnv, gvk schema.GroupVersionKind, name string) {
	t.Helper()
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	obj.SetName(name)
	if err := unstructured.SetNestedField(obj.Object, map[string]any{}, "spec"); err != nil {
		t.Fatalf("set stand-in spec: %v", err)
	}
	if err := te.client.Create(ctx, obj); err != nil {
		t.Fatalf("create stand-in %s %q: %v", gvk.Kind, name, err)
	}
}

func deleteStandIn(ctx context.Context, t *testing.T, te *testEnv, gvk schema.GroupVersionKind, name string) {
	t.Helper()
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	obj.SetName(name)
	if err := te.client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("delete stand-in %s %q: %v", gvk.Kind, name, err)
	}
}

func TestRecordSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	ns := createNamespace(ctx, t, te)
	gatewayUID := types.UID("gw-uid-1")
	project := "proj-1"

	deps := NewKubernetesDeps(te.client, te.uncached, gatewayUID, project)
	priv, pub := testKeypair(t)
	rec := Record{
		Name:            "vm-a",
		Slot:            2,
		PrivateKey:      priv,
		PublicKey:       pub,
		TunnelAddress:   "10.99.0.3",
		SubnetPrefix:    29,
		PeerPublicKey:   testBundle.PeerPublicKey,
		PeerAllowedIPs:  testBundle.PeerAllowedIPs,
		ExternalAddress: "203.0.113.5",
		InstanceID:      "123456",
		GatewayUID:      gatewayUID,
		Project:         project,
	}
	if err := deps.CreateRecord(ctx, ns, "gw1", rec); err != nil {
		t.Fatalf("CreateRecord(...) returned unexpected error: %v", err)
	}

	// Discard in-memory state: build a brand new Deps instance sharing nothing but the
	// underlying Kubernetes client, then re-read.
	freshDeps := NewKubernetesDeps(te.client, te.uncached, gatewayUID, project)
	got, found, err := freshDeps.GetRecord(ctx, ns, "gw1", "vm-a")
	if err != nil {
		t.Fatalf("GetRecord(...) returned unexpected error: %v", err)
	}
	if !found {
		t.Fatalf("GetRecord(...) found = false, want true")
	}
	if got.Slot != rec.Slot || got.PrivateKey != rec.PrivateKey || got.PublicKey != rec.PublicKey ||
		got.TunnelAddress != rec.TunnelAddress || got.ExternalAddress != rec.ExternalAddress {
		t.Fatalf("GetRecord(...) = %+v, want Slot/PrivateKey/PublicKey/TunnelAddress/ExternalAddress matching %+v", got, rec)
	}
}

func TestDepartureHoldsSlot(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	ns := createNamespace(ctx, t, te)
	gatewayUID := types.UID("gw-uid-1")
	project := "proj-1"
	gatewayName := "gw1"

	deps := NewKubernetesDeps(te.client, te.uncached, gatewayUID, project)
	createSyncedComposite(ctx, t, te, ns, gatewayName)

	names, err := NameResourceNames(string(gatewayUID), project, "vm-a")
	if err != nil {
		t.Fatalf("NameResourceNames(...) returned unexpected error: %v", err)
	}
	createStandIn(ctx, t, te, secretManagerSecretGVK, names.CloudSecretName)

	priv, pub := testKeypair(t)
	rec := Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0, PrivateKey: priv, PublicKey: pub, TunnelAddress: testGatewayAddress, SubnetPrefix: 29, GatewayUID: gatewayUID, Project: project}
	if err := deps.CreateRecord(ctx, ns, gatewayName, rec); err != nil {
		t.Fatalf("CreateRecord(...) returned unexpected error: %v", err)
	}

	// Wait out the cache between passes: a tight loop can read the prior pass's state and
	// under-count the debounce on a slow runner. Production passes are requeue-spaced.
	absent := &gcpdiscovery.Snapshot{}
	var got Record
	for i := range 3 {
		if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
			t.Fatalf("Reconcile(...) pass %d returned unexpected error: %v", i, err)
		}
		wantCount := i + 1
		got = waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(r Record) bool { return r.DepartureCount == wantCount })
	}
	if got.Slot != 0 || got.DepartureCount != 3 || !got.PendingConfirmation {
		t.Fatalf("GetRecord(...) = %+v, want Slot 0, DepartureCount 3 and PendingConfirmation true", got)
	}

	// A blocking managed resource still exists: confirmation must not release the record.
	result, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle)
	if err != nil {
		t.Fatalf("Reconcile(...) returned unexpected error: %v", err)
	}
	m, ok := findMember(result.Members, "vm-a")
	if !ok || m.State != wgnetv1alpha1.GatewayGCPMemberDeparted || m.Message == "" || m.Zone != testZone || m.Revision != testRevision {
		t.Fatalf("Result.Members[\"vm-a\"] = %+v, ok=%v, want State Departed with a non-empty Message, Zone %s, Revision %s", m, ok, testZone, testRevision)
	}
	if _, found, err := deps.GetRecord(ctx, ns, gatewayName, "vm-a"); err != nil || !found {
		t.Fatalf("GetRecord(...) found=%v, err=%v; want the record still held while confirmation is blocked", found, err)
	}

	// Clear the blocker: the next pass confirms and releases.
	deleteStandIn(ctx, t, te, secretManagerSecretGVK, names.CloudSecretName)
	if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
		t.Fatalf("Reconcile(...) returned unexpected error: %v", err)
	}
	waitForRecordGone(ctx, t, deps, ns, gatewayName, "vm-a")
}

func TestNameReuseResumesLiveRecord(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	ns := createNamespace(ctx, t, te)
	gatewayUID := types.UID("gw-uid-1")
	project := "proj-1"
	gatewayName := "gw1"

	deps := NewKubernetesDeps(te.client, te.uncached, gatewayUID, project)
	createSyncedComposite(ctx, t, te, ns, gatewayName)

	priv, pub := testKeypair(t)
	rec := Record{Name: "vm-a", Slot: 0, PrivateKey: priv, PublicKey: pub, TunnelAddress: testGatewayAddress, SubnetPrefix: 29, GatewayUID: gatewayUID, Project: project}
	if err := deps.CreateRecord(ctx, ns, gatewayName, rec); err != nil {
		t.Fatalf("CreateRecord(...) returned unexpected error: %v", err)
	}

	absent := &gcpdiscovery.Snapshot{}
	present := &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{presentMember("vm-a", "1")}}

	// Wait out the cache between passes: Reconcile's own label update reads through the
	// cache, and a stale read here races its own prior write, not just the test's.
	for i := range 3 {
		if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
			t.Fatalf("Reconcile(...) pass %d returned unexpected error: %v", i, err)
		}
		waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(r Record) bool { return r.DepartureCount == i+1 })
	}

	// Reappears before the removal pass's confirmation ever ran: resumes the same key.
	if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, present, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
		t.Fatalf("Reconcile(...) returned unexpected error: %v", err)
	}
	resumed := waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(r Record) bool { return !r.PendingConfirmation })
	if resumed.PrivateKey != priv || resumed.PublicKey != pub || resumed.Slot != 0 || resumed.PendingConfirmation {
		t.Fatalf("GetRecord(...) = %+v, want the original key/slot resumed and PendingConfirmation false", resumed)
	}

	// Depart again, this time let confirmation and release complete.
	for i := range 3 {
		if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
			t.Fatalf("Reconcile(...) pass %d returned unexpected error: %v", i, err)
		}
		waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(r Record) bool { return r.DepartureCount == i+1 })
	}
	if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
		t.Fatalf("Reconcile(...) returned unexpected error: %v", err)
	}
	waitForRecordGone(ctx, t, deps, ns, gatewayName, "vm-a")

	// Reappears after the record is truly gone: a fresh allocation, a new key. DepartureCount
	// 0 rules out a cache entry still trailing the delete.
	if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, present, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
		t.Fatalf("Reconcile(...) returned unexpected error: %v", err)
	}
	fresh := waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(r Record) bool {
		return r.DepartureCount == 0 && !r.PendingConfirmation
	})
	if fresh.PrivateKey == priv || fresh.PublicKey == pub {
		t.Fatalf("GetRecord(...) = %+v, want a new key distinct from the original one", fresh)
	}
}

// countingReader wraps a client.Reader, counting Get calls by GroupVersionKind so a test can
// assert the exact interaction shape.
type countingReader struct {
	client.Reader
	counts map[schema.GroupVersionKind]int
}

func (r *countingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		r.counts[u.GroupVersionKind()]++
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

// staleReader always reports NotFound, simulating an informer cache that has not yet
// observed a just-created object ( "stale cached data" fixture).
type staleReader struct{}

func (staleReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	gvk := schema.GroupVersionKind{}
	if u, ok := obj.(*unstructured.Unstructured); ok {
		gvk = u.GroupVersionKind()
	}
	return apierrors.NewNotFound(schema.GroupResource{Group: gvk.Group, Resource: gvk.Kind}, key.Name)
}

func (staleReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return nil
}

func TestUncachedConfirmationReads(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	ns := createNamespace(ctx, t, te)
	gatewayUID := types.UID("gw-uid-1")
	project := "proj-1"
	gatewayName := "gw1"

	createSyncedComposite(ctx, t, te, ns, gatewayName)
	names, err := NameResourceNames(string(gatewayUID), project, "vm-a")
	if err != nil {
		t.Fatalf("NameResourceNames(...) returned unexpected error: %v", err)
	}
	createStandIn(ctx, t, te, secretManagerSecretGVK, names.CloudSecretName)

	// A stale reader never observes the just-created object: it would wrongly confirm the
	// resource absent.
	staleDeps := NewKubernetesDeps(te.client, staleReader{}, gatewayUID, project)
	absentAccordingToStale, _, err := staleDeps.ConfirmManagedResourcesAbsent(ctx, names)
	if err != nil {
		t.Fatalf("ConfirmManagedResourcesAbsent(...) with a stale reader returned unexpected error: %v", err)
	}
	if !absentAccordingToStale {
		t.Fatalf("ConfirmManagedResourcesAbsent(...) with a stale reader reported present, want the stub to always report NotFound")
	}

	// The real, genuinely uncached path correctly sees the object and every Get it issues.
	counting := &countingReader{Reader: te.uncached, counts: map[schema.GroupVersionKind]int{}}
	realDeps := NewKubernetesDeps(te.client, counting, gatewayUID, project)
	absent, reason, err := realDeps.ConfirmManagedResourcesAbsent(ctx, names)
	if err != nil {
		t.Fatalf("ConfirmManagedResourcesAbsent(...) returned unexpected error: %v", err)
	}
	if absent || reason == "" {
		t.Fatalf("ConfirmManagedResourcesAbsent(...) = (%v, %q), want (false, a non-empty reason): the stand-in Secret still exists", absent, reason)
	}
	for _, gvk := range []schema.GroupVersionKind{secretManagerSecretGVK, secretManagerSecretVersionGVK, secretManagerSecretIAMMemberGVK} {
		if counting.counts[gvk] != 1 {
			t.Fatalf("Get(%s) called %d times, want exactly 1", gvk, counting.counts[gvk])
		}
	}

	compositeCounting := &countingReader{Reader: te.uncached, counts: map[schema.GroupVersionKind]int{}}
	compositeDeps := NewKubernetesDeps(te.client, compositeCounting, gatewayUID, project)
	deleteStandIn(ctx, t, te, secretManagerSecretGVK, names.CloudSecretName)
	if _, _, err := compositeDeps.ConfirmManagedResourcesAbsent(ctx, names); err != nil {
		t.Fatalf("ConfirmManagedResourcesAbsent(...) returned unexpected error: %v", err)
	}
	if _, _, err := compositeDeps.CompositeSynced(ctx, ns, gatewayName); err != nil {
		t.Fatalf("CompositeSynced(...) returned unexpected error: %v", err)
	}
	if compositeCounting.counts[xGatewayGCPGVK] != 1 {
		t.Fatalf("Get(%s) called %d times, want exactly 1", xGatewayGCPGVK, compositeCounting.counts[xGatewayGCPGVK])
	}
}

func TestRecordDeletionPreconditions(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	ns := createNamespace(ctx, t, te)
	gatewayUID := types.UID("gw-uid-1")
	project := "proj-1"
	gatewayName := "gw1"

	deps := NewKubernetesDeps(te.client, te.uncached, gatewayUID, project)
	priv, pub := testKeypair(t)
	rec := Record{Name: "vm-a", Slot: 0, PrivateKey: priv, PublicKey: pub, TunnelAddress: testGatewayAddress, SubnetPrefix: 29, GatewayUID: gatewayUID, Project: project}
	if err := deps.CreateRecord(ctx, ns, gatewayName, rec); err != nil {
		t.Fatalf("CreateRecord(...) returned unexpected error: %v", err)
	}
	got := waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(Record) bool { return true })

	if err := deps.DeleteRecord(ctx, ns, gatewayName, "vm-a", got.UID, "stale-resource-version"); err == nil {
		t.Fatalf("DeleteRecord(...) with a stale resourceVersion precondition = nil error, want an error")
	}
	if _, found, err := deps.GetRecord(ctx, ns, gatewayName, "vm-a"); err != nil || !found {
		t.Fatalf("GetRecord(...) found=%v, err=%v; want the record untouched by the failed delete", found, err)
	}

	if err := deps.DeleteRecord(ctx, ns, gatewayName, "vm-a", got.UID, got.ResourceVersion); err != nil {
		t.Fatalf("DeleteRecord(...) with correct preconditions returned unexpected error: %v", err)
	}
	waitForRecordGone(ctx, t, deps, ns, gatewayName, "vm-a")

	// The freed slot goes to a distinct key.
	names := listedSnapshot("vm-b", "9")
	if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, names, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
		t.Fatalf("Reconcile(...) returned unexpected error: %v", err)
	}
	next := waitForRecord(ctx, t, deps, ns, gatewayName, "vm-b", func(r Record) bool { return r.Slot == 0 })
	if next.Slot != 0 || next.PrivateKey == priv {
		t.Fatalf("GetRecord(...) = %+v, want Slot 0 with a key distinct from the original one", next)
	}
}

func listedSnapshot(name, instanceID string) *gcpdiscovery.Snapshot {
	return &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{presentMember(name, instanceID)}}
}

func TestCollapsedConfirmationGating(t *testing.T) {
	ctx := context.Background()
	gatewayUID := types.UID("gw-uid-1")
	project := "proj-1"
	gatewayName := "gw1"
	absent := &gcpdiscovery.Snapshot{}

	setup := func(t *testing.T) (Deps, *testEnv, string) {
		te := setupEnvtest(t)
		ns := createNamespace(ctx, t, te)
		deps := NewKubernetesDeps(te.client, te.uncached, gatewayUID, project)
		priv, pub := testKeypair(t)
		rec := Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0, PrivateKey: priv, PublicKey: pub, TunnelAddress: testGatewayAddress, SubnetPrefix: 29, GatewayUID: gatewayUID, Project: project}
		if err := deps.CreateRecord(ctx, ns, gatewayName, rec); err != nil {
			t.Fatalf("CreateRecord(...) returned unexpected error: %v", err)
		}
		// Wait out the cache between passes: Reconcile's own label update reads through the
		// cache, and a stale read here races its own prior write, not just the test's.
		for i := range 3 {
			if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
				t.Fatalf("Reconcile(...) pass %d returned unexpected error: %v", i, err)
			}
			waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(r Record) bool { return r.DepartureCount == i+1 })
		}
		return deps, te, ns
	}

	assertStillBlocked := func(t *testing.T, deps Deps, ns string) {
		t.Helper()
		result, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle)
		if err != nil {
			t.Fatalf("Reconcile(...) returned unexpected error: %v", err)
		}
		m, ok := findMember(result.Members, "vm-a")
		if !ok || m.State != wgnetv1alpha1.GatewayGCPMemberDeparted || m.Zone != testZone || m.Revision != testRevision {
			t.Fatalf("Result.Members[\"vm-a\"] = %+v, ok=%v, want State Departed, Zone %s, Revision %s", m, ok, testZone, testRevision)
		}
		if _, found, err := deps.GetRecord(ctx, ns, gatewayName, "vm-a"); err != nil || !found {
			t.Fatalf("GetRecord(...) found=%v, err=%v; want the record still held", found, err)
		}
	}

	t.Run("stale_observed_generation_blocks", func(t *testing.T) {
		deps, te, ns := setup(t)
		createSyncedComposite(ctx, t, te, ns, gatewayName)
		setCompositeCondition(ctx, t, te, ns, gatewayName, "True", 999)
		assertStillBlocked(t, deps, ns)
	})

	t.Run("synced_false_blocks", func(t *testing.T) {
		deps, te, ns := setup(t)
		createSyncedComposite(ctx, t, te, ns, gatewayName)
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(xGatewayGCPGVK)
		if err := te.uncached.Get(ctx, client.ObjectKey{Namespace: ns, Name: gatewayName}, obj); err != nil {
			t.Fatalf("read composite: %v", err)
		}
		setCompositeCondition(ctx, t, te, ns, gatewayName, "False", obj.GetGeneration())
		assertStillBlocked(t, deps, ns)
	})

	t.Run("missing_condition_blocks", func(t *testing.T) {
		deps, te, ns := setup(t)
		createSyncedComposite(ctx, t, te, ns, gatewayName)
		clearCompositeConditions(ctx, t, te, ns, gatewayName)
		assertStillBlocked(t, deps, ns)
	})

	t.Run("resource_still_present_blocks", func(t *testing.T) {
		deps, te, ns := setup(t)
		createSyncedComposite(ctx, t, te, ns, gatewayName)
		names, err := NameResourceNames(string(gatewayUID), project, "vm-a")
		if err != nil {
			t.Fatalf("NameResourceNames(...) returned unexpected error: %v", err)
		}
		createStandIn(ctx, t, te, secretManagerSecretGVK, names.CloudSecretName)
		assertStillBlocked(t, deps, ns)
	})
}

func TestDebounceAcrossUsableAndUnusablePasses(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	ns := createNamespace(ctx, t, te)
	gatewayUID := types.UID("gw-uid-1")
	project := "proj-1"
	gatewayName := "gw1"

	deps := NewKubernetesDeps(te.client, te.uncached, gatewayUID, project)
	priv, pub := testKeypair(t)
	rec := Record{Name: "vm-a", Slot: 0, PrivateKey: priv, PublicKey: pub, TunnelAddress: testGatewayAddress, SubnetPrefix: 29, GatewayUID: gatewayUID, Project: project}
	if err := deps.CreateRecord(ctx, ns, gatewayName, rec); err != nil {
		t.Fatalf("CreateRecord(...) returned unexpected error: %v", err)
	}

	absent := &gcpdiscovery.Snapshot{}
	if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
		t.Fatalf("Reconcile(...) (absent) returned unexpected error: %v", err)
	}
	got := waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(r Record) bool { return r.DepartureCount == 1 })
	if got.DepartureCount != 1 {
		t.Fatalf("GetRecord(...).DepartureCount = %d, want 1 after one absent pass", got.DepartureCount)
	}

	// An unusable pass in between neither advances nor resets the count, and issues no
	// write, so the wait above already establishes the state this read observes.
	if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, nil, 1, 1, nil, testGatewayAddress, 1, testBundle); err != nil {
		t.Fatalf("Reconcile(...) (unusable) returned unexpected error: %v", err)
	}
	stillOne, _, err := deps.GetRecord(ctx, ns, gatewayName, "vm-a")
	if err != nil {
		t.Fatalf("GetRecord(...) returned unexpected error: %v", err)
	}
	if stillOne.DepartureCount != 1 {
		t.Fatalf("GetRecord(...).DepartureCount = %d, want still 1 after an unusable pass", stillOne.DepartureCount)
	}

	if _, err := Reconcile(ctx, deps, string(gatewayUID), ns, gatewayName, project, absent, 1, 1, nil, testGatewayAddress, 0, testBundle); err != nil {
		t.Fatalf("Reconcile(...) (absent) returned unexpected error: %v", err)
	}
	got = waitForRecord(ctx, t, deps, ns, gatewayName, "vm-a", func(r Record) bool { return r.DepartureCount == 2 })
	if got.DepartureCount != 2 {
		t.Fatalf("GetRecord(...).DepartureCount = %d, want 2 after a second absent pass", got.DepartureCount)
	}
}
