package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stretchr/testify/mock"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
	gcpdiscoverymocks "github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery/mocks"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpmembers"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// TestReadyPrecedence exercises table: one case per readyPrecedence signal, each
// in isolation, plus each clearing to the next reason once its own cause clears.
func TestReadyPrecedence(t *testing.T) {
	invalidFwd := &invalidForward{reason: reasonServiceNotFound, message: "1 forward(s) invalid: backend not found"}

	tests := []struct {
		name        string
		in          readySignals
		wantReason  string
		wantMessage string
		wantReady   bool
	}{
		{
			name:        "invalid tunnel addresses first",
			in:          readySignals{InvalidTunnelAddresses: true, InvalidTunnelMessage: "bad subnet", InvalidForward: invalidFwd, LinkFaultReason: "SomeFault"},
			wantReason:  reasonInvalidTunnelAddresses,
			wantMessage: "bad subnet",
		},
		{
			name:        "invalid forward, no tunnel issue",
			in:          readySignals{InvalidForward: invalidFwd, LinkFaultReason: "SomeFault"},
			wantReason:  reasonServiceNotFound,
			wantMessage: "1 forward(s) invalid: backend not found",
		},
		{
			name:        "link fault, no invalid forward",
			in:          readySignals{LinkFaultReason: "LinkDown", LinkFaultMessage: "down"},
			wantReason:  "LinkDown",
			wantMessage: "down",
		},
		{
			name:        "insufficient capacity, load balanced",
			in:          readySignals{LoadBalanced: true, InsufficientCapacity: true, CapacityMessage: "over capacity"},
			wantReason:  reasonInsufficientTunnelAddresses,
			wantMessage: "over capacity",
		},
		{
			name:        "insufficient capacity ignored when not load balanced",
			in:          readySignals{LoadBalanced: false, InsufficientCapacity: true, CapacityMessage: "over capacity"},
			wantReason:  reasonProvisioning,
			wantMessage: "waiting for gateway address and active link tunnel",
		},
		{
			name:        "discovery failed",
			in:          readySignals{DiscoveryFailed: true, DiscoveryMessage: "list error"},
			wantReason:  reasonMemberDiscoveryFailed,
			wantMessage: "list error",
		},
		{
			name:        "members not ready with a rendered peer and no live session",
			in:          readySignals{LoadBalanced: true, PeerCount: 1, MembersNotReady: true},
			wantReason:  reasonMembersNotReady,
			wantMessage: "no fleet member has a live wireguard session",
		},
		{
			name:        "members not ready with no rendered peer, even with a live session and an address",
			in:          readySignals{LoadBalanced: true, PeerCount: 0, ProvisionAddress: "203.0.113.5"},
			wantReason:  reasonMembersNotReady,
			wantMessage: "no fleet member observed yet",
		},
		{
			name:        "members not ready ignored when not load balanced",
			in:          readySignals{LoadBalanced: false, PeerCount: 0, MembersNotReady: true},
			wantReason:  reasonProvisioning,
			wantMessage: "waiting for gateway address and active link tunnel",
		},
		{
			name:        "ready once every earlier step clears",
			in:          readySignals{LoadBalanced: true, PeerCount: 1, ProvisionAddress: "203.0.113.5"},
			wantReason:  reasonReady,
			wantMessage: "gateway address provisioned and active link tunnel up",
			wantReady:   true,
		},
		{
			name:        "provisioning when nothing else applies and no address yet",
			in:          readySignals{},
			wantReason:  reasonProvisioning,
			wantMessage: "waiting for gateway address and active link tunnel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, message, ready := readyPrecedence(tt.in)
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
			if message != tt.wantMessage {
				t.Errorf("message = %q, want %q", message, tt.wantMessage)
			}
			if ready != tt.wantReady {
				t.Errorf("ready = %v, want %v", ready, tt.wantReady)
			}
		})
	}
}

// TestMirrorStatusMembersShape covers: status.gcp.members mirrors Result.Members
// verbatim, including a capacity-blocked Pending member.
func TestMirrorStatusMembersShape(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: reconcileConfig()}

	const ns = "status-members-shape"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	mustCreate(ctx, t, te.client, gw)

	wantMembers := []wgnetv1alpha1.GatewayGCPMemberStatus{
		{Name: "gw-a", State: wgnetv1alpha1.GatewayGCPMemberActive, Slot: 0, TunnelAddress: "10.99.0.1"},
		{Name: "gw-b", State: wgnetv1alpha1.GatewayGCPMemberPending},
	}
	result := &gcpmembers.Result{Members: wantMembers, TargetSize: 2}

	if err := r.mirrorStatusWithForwards(ctx, gw, "", "", linkStatus{}, readySignals{LoadBalanced: true}, result, nil); err != nil {
		t.Fatalf("mirrorStatusWithForwards: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: ns}, &got)
	if len(got.Status.GCP.Members) != len(wantMembers) {
		t.Fatalf("status.gcp.members = %+v, want %+v", got.Status.GCP.Members, wantMembers)
	}
	for i := range wantMembers {
		if got.Status.GCP.Members[i] != wantMembers[i] {
			t.Errorf("status.gcp.members[%d] = %+v, want %+v", i, got.Status.GCP.Members[i], wantMembers[i])
		}
	}
}

// TestMirrorStatusUnusablePassPreservesMembers verifies unusable passes retain members.
func TestMirrorStatusUnusablePassPreservesMembers(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: reconcileConfig()}

	const ns = "status-unusable-preserves"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	mustCreate(ctx, t, te.client, gw)

	settled := []wgnetv1alpha1.GatewayGCPMemberStatus{
		{Name: "gw-a", State: wgnetv1alpha1.GatewayGCPMemberActive, TunnelAddress: "10.99.0.1"},
	}
	if err := r.mirrorStatusWithForwards(ctx, gw, "", "", linkStatus{}, readySignals{LoadBalanced: true},
		&gcpmembers.Result{Members: settled}, nil); err != nil {
		t.Fatalf("mirrorStatusWithForwards (settle): %v", err)
	}

	// An unusable pass: Result carries no Members, only Unusable true.
	if err := r.mirrorStatusWithForwards(ctx, gw, "", "", linkStatus{},
		readySignals{LoadBalanced: true, DiscoveryFailed: true, DiscoveryMessage: "unusable"},
		&gcpmembers.Result{Unusable: true}, nil); err != nil {
		t.Fatalf("mirrorStatusWithForwards (unusable): %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: ns}, &got)
	if len(got.Status.GCP.Members) != 1 || got.Status.GCP.Members[0] != settled[0] {
		t.Errorf("status.gcp.members = %+v, want unchanged %+v", got.Status.GCP.Members, settled)
	}
	cond := findCondition(got.Status.Conditions, conditionReady)
	if cond == nil || cond.Reason != reasonMemberDiscoveryFailed {
		t.Errorf("Ready reason = %v, want %q", cond, reasonMemberDiscoveryFailed)
	}
}

// findCondition returns the condition of type t, or nil.
func findCondition(conditions []metav1.Condition, t string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == t {
			return &conditions[i]
		}
	}
	return nil
}

func TestMirrorStatusMembersReadiness(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)

	tests := []struct {
		name        string
		active      bool
		members     []wgnetv1alpha1.GatewayGCPMemberStatus
		wantReason  string
		wantMessage string
	}{
		{
			name:   "one live member",
			active: true,
			members: []wgnetv1alpha1.GatewayGCPMemberStatus{
				{Name: "vm-a", State: wgnetv1alpha1.GatewayGCPMemberActive},
				{Name: "vm-b", State: wgnetv1alpha1.GatewayGCPMemberPending},
			},
			wantReason:  reasonProvisioning,
			wantMessage: "waiting for gateway address and active link tunnel",
		},
		{
			name: "no live member",
			members: []wgnetv1alpha1.GatewayGCPMemberStatus{
				{Name: "vm-a", State: wgnetv1alpha1.GatewayGCPMemberPending},
				{Name: "vm-b", State: wgnetv1alpha1.GatewayGCPMemberPending},
			},
			wantReason:  reasonMembersNotReady,
			wantMessage: "no fleet member has a live wireguard session",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := "status-members-ready-" + string(rune('a'+i))
			mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
			gw := gcpLBGateway(ns, ns)
			mustCreate(ctx, t, te.client, gw)
			r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: reconcileConfig()}

			signals := readySignals{LoadBalanced: true, PeerCount: len(tt.members), MembersNotReady: !tt.active}
			if err := r.mirrorStatusWithForwards(ctx, gw, "", "", linkStatus{Active: tt.active}, signals,
				&gcpmembers.Result{Members: tt.members}, nil); err != nil {
				t.Fatalf("mirror status: %v", err)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), &got)
			condition := findCondition(got.Status.Conditions, conditionReady)
			if condition == nil || condition.Reason != tt.wantReason || condition.Message != tt.wantMessage {
				t.Errorf("Ready condition = %+v, want reason %q and message %q", condition, tt.wantReason, tt.wantMessage)
			}
			if !tt.active {
				if err := r.mirrorStatusWithForwards(ctx, gw, "", "", linkStatus{Active: true},
					readySignals{LoadBalanced: true, PeerCount: len(tt.members)},
					&gcpmembers.Result{Members: tt.members}, nil); err != nil {
					t.Fatalf("mirror cleared member readiness: %v", err)
				}
				mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), &got)
				condition = findCondition(got.Status.Conditions, conditionReady)
				if condition == nil || condition.Reason != reasonProvisioning || condition.Message != "waiting for gateway address and active link tunnel" {
					t.Errorf("cleared Ready condition = %+v, want reason %q and the provisioning message", condition, reasonProvisioning)
				}
			}
		})
	}
}

// secretManagerSecretGVK is the managed-resource kind gcpmembers confirms absent before it
// releases a record; internal/gcpmembers keeps its own unexported copy.
var secretManagerSecretGVK = schema.GroupVersionKind{Group: "secretmanager.gcp.m.upbound.io", Version: "v1beta1", Kind: "Secret"}

func createSecretManagerStandIn(ctx context.Context, t *testing.T, cl client.Client, name string) {
	t.Helper()
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(secretManagerSecretGVK)
	obj.SetName(name)
	if err := unstructured.SetNestedMap(obj.Object, map[string]any{}, "spec"); err != nil {
		t.Fatalf("set stand-in spec: %v", err)
	}
	if err := cl.Create(ctx, obj); err != nil {
		t.Fatalf("create Secret Manager stand-in %q: %v", name, err)
	}
}

// TestReconcileMembersBlockedCleanupSurfacing covers: a blocked member reports Departed
// naming the blocker and warns once, leaving the Ready reason and the link's fault annotation be.
func TestReconcileMembersBlockedCleanupSurfacing(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	recorder := &fakeEventRecorder{}
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
		Config: discoveryTestConfig(), Recorder: recorder}
	createCredentialsSecret(ctx, t, r, []byte("v1"))

	const ns = "status-blocked-cleanup"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	gw.Spec.GCP.Replicas = 1
	mustCreate(ctx, t, te.client, gw)
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)

	deps := gcpmembers.NewKubernetesDeps(te.client, te.client, gw.UID, gw.Spec.GCP.ProjectID)
	priv, pub := testMemberKeypair(t)
	if err := deps.CreateRecord(ctx, ns, ns, gcpmembers.Record{
		Name: "vm-a", Zone: "us-central1-a", Revision: "rev-1", Slot: 0,
		PrivateKey: priv, PublicKey: pub, TunnelAddress: "10.99.0.1", SubnetPrefix: 29,
		GatewayUID: gw.UID, Project: gw.Spec.GCP.ProjectID,
	}); err != nil {
		t.Fatalf("create member record: %v", err)
	}
	mustEnsureKeySecrets(ctx, t, r, gw)
	names, err := gcpmembers.NameResourceNames(string(gw.UID), gw.Spec.GCP.ProjectID, "vm-a")
	if err != nil {
		t.Fatalf("derive managed resource names: %v", err)
	}
	createSecretManagerStandIn(ctx, t, te.client, names.CloudSecretName)

	const faultMessage = "apply failed on node-a"
	upsertLeaseHolder(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: linkComponentName(gw)}, ns+"-link-0",
		map[string]string{link.LeaseFaultAnnotation: link.FaultApplyFailed, link.LeaseFaultMessageAnnotation: faultMessage})

	orig := newGCPDiscoveryClient
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	mockClient := gcpdiscoverymocks.NewMockClient(t)
	mockClient.EXPECT().
		List(ctx, gw.Spec.GCP.ProjectID, gw.Spec.GCP.Region, "edge-mig", mock.Anything, mock.Anything).
		Return(gcpdiscovery.Snapshot{}, nil)
	newGCPDiscoveryClient = func(context.Context, []byte) (gcpdiscovery.Client, error) { return mockClient, nil }

	eligible, ok, reason := tunnelAddresses(effectiveWGSubnet(gw), effectiveWGGatewayAddress(gw), effectiveWGLinkAddress(gw))
	if !ok {
		t.Fatalf("tunnel addresses rejected: %s", reason)
	}

	// Three absent passes exhaust the departure debounce; the two after it are the blocked
	// confirmation attempts asks to see warned exactly once.
	var result *gcpmembers.Result
	for pass := 1; pass <= 5; pass++ {
		res, discoveryFailed, message, rerr := r.reconcileMembers(ctx, gw, "edge-mig", eligible)
		if rerr != nil {
			t.Fatalf("reconcile members pass %d: %v", pass, rerr)
		}
		if discoveryFailed {
			t.Fatalf("reconcile members pass %d: discoveryFailed with %q, want a usable pass", pass, message)
		}
		result = res
	}

	if len(result.Members) != 1 {
		t.Fatalf("Result.Members = %+v, want exactly the blocked member", result.Members)
	}
	blocked := result.Members[0]
	if blocked.Name != "vm-a" || blocked.State != wgnetv1alpha1.GatewayGCPMemberDeparted ||
		!strings.Contains(blocked.Message, names.CloudSecretName) {
		t.Errorf("Result.Members[0] = %+v, want vm-a Departed with a message naming %q", blocked, names.CloudSecretName)
	}

	wantEvents := []recordedEvent{{
		eventtype: corev1.EventTypeWarning,
		reason:    reasonMemberCleanupBlocked,
		action:    actionReconcile,
		note:      fmt.Sprintf("member %q has departed but its cleanup cannot complete: %s", blocked.Name, blocked.Message),
	}}
	if len(recorder.events) != len(wantEvents) {
		t.Fatalf("events = %+v, want exactly %+v", recorder.events, wantEvents)
	}
	for i, want := range wantEvents {
		got := recorder.events[i]
		if got.eventtype != want.eventtype || got.reason != want.reason || got.action != want.action || got.note != want.note {
			t.Errorf("events[%d] = %+v, want %+v", i, got, want)
		}
	}

	ls, err := r.linkStatusOf(ctx, gw)
	if err != nil {
		t.Fatalf("link status: %v", err)
	}
	signals := readySignals{
		LoadBalanced:     true,
		LinkFaultReason:  ls.FaultReason,
		LinkFaultMessage: ls.FaultMessage,
		MembersNotReady:  !ls.Active,
	}
	if err := r.mirrorStatusWithForwards(ctx, gw, "", "", ls, signals, result, nil); err != nil {
		t.Fatalf("mirror status: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), &got)
	if len(got.Status.GCP.Members) != 1 || got.Status.GCP.Members[0] != blocked {
		t.Errorf("status.gcp.members = %+v, want exactly %+v", got.Status.GCP.Members, blocked)
	}
	condition := findCondition(got.Status.Conditions, conditionReady)
	if condition == nil || condition.Reason != link.FaultApplyFailed || condition.Message != faultMessage {
		t.Errorf("Ready condition = %+v, want the link fault reason %q and message %q",
			condition, link.FaultApplyFailed, faultMessage)
	}

	var lease coordinationv1.Lease
	mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: linkComponentName(gw)}, &lease)
	wantAnnotations := map[string]string{
		link.LeaseFaultAnnotation:        link.FaultApplyFailed,
		link.LeaseFaultMessageAnnotation: faultMessage,
	}
	if !maps.Equal(lease.Annotations, wantAnnotations) {
		t.Errorf("link lease annotations = %v, want exactly %v", lease.Annotations, wantAnnotations)
	}
}

// TestReconcileMembersBlockedCleanupSurvivesUnusablePass verifies cleanup status retention.
func TestReconcileMembersBlockedCleanupSurvivesUnusablePass(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	recorder := &fakeEventRecorder{}
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
		Config: discoveryTestConfig(), Recorder: recorder}
	createCredentialsSecret(ctx, t, r, []byte("v1"))

	const ns = "status-blocked-cleanup-unusable"
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	gw := gcpLBGateway(ns, ns)
	gw.Spec.GCP.Replicas = 1
	mustCreate(ctx, t, te.client, gw)
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)

	deps := gcpmembers.NewKubernetesDeps(te.client, te.client, gw.UID, gw.Spec.GCP.ProjectID)
	priv, pub := testMemberKeypair(t)
	if err := deps.CreateRecord(ctx, ns, ns, gcpmembers.Record{
		Name: "vm-a", Zone: "us-central1-a", Revision: "rev-1", Slot: 0,
		PrivateKey: priv, PublicKey: pub, TunnelAddress: "10.99.0.1", SubnetPrefix: 29,
		GatewayUID: gw.UID, Project: gw.Spec.GCP.ProjectID,
	}); err != nil {
		t.Fatalf("create member record: %v", err)
	}
	mustEnsureKeySecrets(ctx, t, r, gw)
	names, err := gcpmembers.NameResourceNames(string(gw.UID), gw.Spec.GCP.ProjectID, "vm-a")
	if err != nil {
		t.Fatalf("derive managed resource names: %v", err)
	}
	createSecretManagerStandIn(ctx, t, te.client, names.CloudSecretName)

	listFails := false
	orig := newGCPDiscoveryClient
	t.Cleanup(func() { newGCPDiscoveryClient = orig })
	mockClient := gcpdiscoverymocks.NewMockClient(t)
	mockClient.EXPECT().
		List(ctx, gw.Spec.GCP.ProjectID, gw.Spec.GCP.Region, "edge-mig", mock.Anything, mock.Anything).
		RunAndReturn(func(context.Context, string, string, string, []gcpdiscovery.Recorded, []string) (gcpdiscovery.Snapshot, error) {
			if listFails {
				return gcpdiscovery.Snapshot{}, errors.New("listing failed mid-pagination")
			}
			return gcpdiscovery.Snapshot{}, nil
		})
	newGCPDiscoveryClient = func(context.Context, []byte) (gcpdiscovery.Client, error) { return mockClient, nil }

	eligible, ok, reason := tunnelAddresses(effectiveWGSubnet(gw), effectiveWGGatewayAddress(gw), effectiveWGLinkAddress(gw))
	if !ok {
		t.Fatalf("tunnel addresses rejected: %s", reason)
	}
	pass := func(t *testing.T, label string, wantFailed bool) *gcpmembers.Result {
		t.Helper()
		res, discoveryFailed, message, rerr := r.reconcileMembers(ctx, gw, "edge-mig", eligible)
		if rerr != nil {
			t.Fatalf("reconcile members (%s): %v", label, rerr)
		}
		if discoveryFailed != wantFailed {
			t.Fatalf("reconcile members (%s): discoveryFailed = %v with %q, want %v", label, discoveryFailed, message, wantFailed)
		}
		return res
	}

	// Three absent passes exhaust the departure debounce; the fourth is the blocked confirmation.
	for i := 1; i <= 4; i++ {
		pass(t, fmt.Sprintf("usable %d", i), false)
	}
	listFails = true
	pass(t, "unusable", true)
	listFails = false
	result := pass(t, "blocked again", false)

	if len(result.Members) != 1 || result.Members[0].State != wgnetv1alpha1.GatewayGCPMemberDeparted ||
		!strings.Contains(result.Members[0].Message, names.CloudSecretName) {
		t.Fatalf("Result.Members = %+v, want exactly vm-a Departed naming %q", result.Members, names.CloudSecretName)
	}
	wantEvents := []recordedEvent{{
		regarding: gw,
		eventtype: corev1.EventTypeWarning,
		reason:    reasonMemberCleanupBlocked,
		action:    actionReconcile,
		note: fmt.Sprintf("member %q has departed but its cleanup cannot complete: %s",
			result.Members[0].Name, result.Members[0].Message),
	}}
	if len(recorder.events) != len(wantEvents) {
		t.Fatalf("events = %+v, want exactly %+v", recorder.events, wantEvents)
	}
	for i, want := range wantEvents {
		if recorder.events[i] != want {
			t.Errorf("events[%d] = %+v, want %+v", i, recorder.events[i], want)
		}
	}
}
