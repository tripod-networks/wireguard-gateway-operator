package controller

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// gcpLBGateway builds a load-balanced Gateway fixture: replicas 2, two zones inside region,
// loadBalancer set. Tests mutate a copy's fields to exercise one admission rule at a time.
func gcpLBGateway(name, namespace string) *wgnetv1alpha1.Gateway {
	gw := newGateway(name, namespace, nil, nil)
	gw.Spec.GCP.Replicas = 2
	gw.Spec.GCP.Zones = []string{"us-central1-a", "us-central1-b"}
	gw.Spec.GCP.LoadBalancer = &wgnetv1alpha1.GatewayGCPLoadBalancerSpec{SessionAffinity: "NONE"}
	return gw
}

// TestGatewayGCPZonesReplicasAdmission covers: spec.gcp.zones and spec.gcp.replicas
// CEL rules, both with and without spec.gcp.loadBalancer.
func TestGatewayGCPZonesReplicasAdmission(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const wantZonesInRegion = "spec.gcp.zones entries must be inside spec.gcp.region"
	const wantReplicasOne = "without spec.gcp.loadBalancer, replicas must be 1 and zones"

	tests := []struct {
		name  string
		build func(ns string) *wgnetv1alpha1.Gateway
		// mutate, when set, sends the Gateway as unstructured so a field the typed object would
		// omit at its zero value reaches the apiserver as an explicit key.
		mutate      func(t *testing.T, u *unstructured.Unstructured)
		accept      bool
		wantMessage string
	}{
		{
			name: "zones cross region rejected",
			build: func(ns string) *wgnetv1alpha1.Gateway {
				gw := gcpLBGateway(ns, ns)
				gw.Spec.GCP.Zones = []string{"us-central1-a", "us-east1-b"}
				return gw
			},
			wantMessage: wantZonesInRegion,
		},
		{
			name: "zones empty entry rejected",
			build: func(ns string) *wgnetv1alpha1.Gateway {
				gw := gcpLBGateway(ns, ns)
				gw.Spec.GCP.Zones = []string{"us-central1-a", ""}
				return gw
			},
			wantMessage: "spec.gcp.zones",
		},
		{
			name:  "replicas below minimum rejected",
			build: func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			mutate: func(t *testing.T, u *unstructured.Unstructured) {
				t.Helper()
				if err := unstructured.SetNestedField(u.Object, int64(0), "spec", "gcp", "replicas"); err != nil {
					t.Fatalf("set spec.gcp.replicas: %v", err)
				}
			},
			wantMessage: "spec.gcp.replicas",
		},
		{
			name: "redundant zones zone accepted without load balancer",
			build: func(ns string) *wgnetv1alpha1.Gateway {
				gw := newGateway(ns, ns, nil, nil)
				gw.Spec.GCP.Zone = "us-central1-a"
				gw.Spec.GCP.Zones = []string{"us-central1-a"}
				return gw
			},
			accept: true,
		},
		{
			name: "replicas over 1 rejected without load balancer",
			build: func(ns string) *wgnetv1alpha1.Gateway {
				gw := newGateway(ns, ns, nil, nil)
				gw.Spec.GCP.Replicas = 2
				return gw
			},
			wantMessage: wantReplicasOne,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("zones-replicas-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			var obj client.Object = tt.build(ns)
			if tt.mutate != nil {
				obj = asUnstructuredGateway(t, obj, tt.mutate)
			}
			assertAdmission(ctx, t, cl, obj, cl.Create(ctx, obj), tt.accept, tt.wantMessage)
		})
	}
}

// TestGatewayGCPNameLengthAdmission covers: the metadata.name bound of a load-balanced Gateway.
func TestGatewayGCPNameLengthAdmission(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const wantNameBound = "a load-balanced Gateway name is at most 37 characters"
	const wantGeneralNameBound = "metadata.name must be a DNS-1035 label of at most 53 characters"

	tests := []struct {
		name        string
		build       func(ns string) *wgnetv1alpha1.Gateway
		accept      bool
		wantMessage string
	}{
		{
			name:        "38 character name rejected with load balancer",
			build:       func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(strings.Repeat("a", 38), ns) },
			wantMessage: wantNameBound,
		},
		{
			name:   "37 character name accepted with load balancer",
			build:  func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(strings.Repeat("a", 37), ns) },
			accept: true,
		},
		{
			name:   "38 character name accepted without load balancer",
			build:  func(ns string) *wgnetv1alpha1.Gateway { return newGateway(strings.Repeat("a", 38), ns, nil, nil) },
			accept: true,
		},
		{
			name:   "53 character name accepted without load balancer",
			build:  func(ns string) *wgnetv1alpha1.Gateway { return newGateway("gw-"+strings.Repeat("a", 50), ns, nil, nil) },
			accept: true,
		},
		{
			name:        "54 character name rejected without load balancer",
			build:       func(ns string) *wgnetv1alpha1.Gateway { return newGateway("gw-"+strings.Repeat("a", 51), ns, nil, nil) },
			wantMessage: wantGeneralNameBound,
		},
		{
			name:        "name starting with a digit rejected",
			build:       func(ns string) *wgnetv1alpha1.Gateway { return newGateway("1gw", ns, nil, nil) },
			wantMessage: wantGeneralNameBound,
		},
		{
			name:        "dotted name rejected",
			build:       func(ns string) *wgnetv1alpha1.Gateway { return newGateway("gw.one", ns, nil, nil) },
			wantMessage: wantGeneralNameBound,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("name-length-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			obj := tt.build(ns)
			assertAdmission(ctx, t, cl, obj, cl.Create(ctx, obj), tt.accept, tt.wantMessage)
		})
	}
}

func asUnstructuredGateway(t *testing.T, gw client.Object, mutate func(t *testing.T, u *unstructured.Unstructured)) *unstructured.Unstructured {
	t.Helper()
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(gw)
	if err != nil {
		t.Fatalf("convert Gateway to unstructured: %v", err)
	}
	u := &unstructured.Unstructured{Object: raw}
	u.SetGroupVersionKind(wgnetv1alpha1.GroupVersion.WithKind("Gateway"))
	mutate(t, u)
	return u
}

// TestGatewayGCPLoadBalancerUpdateAdmission covers: the immutability CEL rules that
// bind on UPDATE only (oldSelf-reading rules never guard CREATE).
func TestGatewayGCPLoadBalancerUpdateAdmission(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tests := []struct {
		name        string
		base        func(ns string) *wgnetv1alpha1.Gateway
		update      func(gw *wgnetv1alpha1.Gateway)
		accept      bool
		wantMessage string
	}{
		{
			name: "load balancer added on update rejected",
			base: func(ns string) *wgnetv1alpha1.Gateway { return newGateway(ns, ns, nil, nil) },
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.GCP.LoadBalancer = &wgnetv1alpha1.GatewayGCPLoadBalancerSpec{SessionAffinity: "NONE"}
			},
			wantMessage: "spec.gcp.loadBalancer presence is immutable",
		},
		{
			name: "load balancer removed on update rejected",
			base: func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.GCP.LoadBalancer = nil
				gw.Spec.GCP.Replicas = 1
			},
			wantMessage: "spec.gcp.loadBalancer presence is immutable",
		},
		{
			name: "zone set changed on update rejected",
			base: func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.GCP.Zones = []string{"us-central1-a", "us-central1-c"}
			},
			wantMessage: "a load-balanced Gateway's effective zone set is immutable",
		},
		{
			name: "zones zone respelling accepted on update",
			base: func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.GCP.Zones = []string{"us-central1-b", "us-central1-a"}
			},
			accept: true,
		},
		{
			name: "replicas and session affinity mutable",
			base: func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.GCP.Replicas = 5
				gw.Spec.GCP.LoadBalancer.SessionAffinity = "CLIENT_IP"
			},
			accept: true,
		},
		{
			name: "disk size changed on single instance rejected",
			base: func(ns string) *wgnetv1alpha1.Gateway {
				gw := newGateway(ns, ns, nil, nil)
				gw.Spec.GCP.DiskSizeGB = 20
				return gw
			},
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.GCP.DiskSizeGB = 21
			},
			wantMessage: "spec.gcp.diskSizeGB is immutable on a single-instance Gateway",
		},
		{
			name: "disk size changed on load balanced accepted",
			base: func(ns string) *wgnetv1alpha1.Gateway {
				gw := gcpLBGateway(ns, ns)
				gw.Spec.GCP.DiskSizeGB = 20
				return gw
			},
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.GCP.DiskSizeGB = 21
			},
			accept: true,
		},
		{
			name: "tunnel parameters immutable on load balanced",
			base: func(ns string) *wgnetv1alpha1.Gateway { return gcpLBGateway(ns, ns) },
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.Wireguard.Subnet = "10.99.0.0/28"
			},
			wantMessage: "spec.wireguard.subnet, gatewayAddress and linkAddress are immutable",
		},
		{
			name: "tunnel parameters mutable without load balancer",
			base: func(ns string) *wgnetv1alpha1.Gateway { return newGateway(ns, ns, nil, nil) },
			update: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.Wireguard.Subnet = "10.99.0.0/28"
				gw.Spec.Wireguard.GatewayAddress = "10.99.0.1"
				gw.Spec.Wireguard.LinkAddress = "10.99.0.2"
			},
			accept: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("lb-update-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

			gw := tt.base(ns)
			if err := cl.Create(ctx, gw); err != nil {
				t.Fatalf("create base Gateway: %v", err)
			}

			var cur wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: ns}, &cur)
			tt.update(&cur)
			err := cl.Update(ctx, &cur)
			assertAdmission(ctx, t, cl, &cur, err, tt.accept, tt.wantMessage)
		})
	}
}

// TestGatewayForwardHealthPortAdmission covers: the Cluster-mode TCP/27000 forward CEL
// rule and its UDP/other-policy escapes.
func TestGatewayForwardHealthPortAdmission(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tests := []struct {
		name        string
		forward     wgnetv1alpha1.Forward
		policy      wgnetv1alpha1.TrafficPolicy
		healthPort  int32
		accept      bool
		wantMessage string
	}{
		{
			name:        "cluster forward 27000 TCP rejected at admission",
			forward:     wgnetv1alpha1.Forward{Port: 27000, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			policy:      wgnetv1alpha1.TrafficPolicyCluster,
			wantMessage: "a TCP forward on spec.link.healthPort (27000 when unset) is rejected under trafficPolicy Cluster",
		},
		{
			name:    "same port udp accepted",
			forward: wgnetv1alpha1.Forward{Port: 27000, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "web"},
			policy:  wgnetv1alpha1.TrafficPolicyCluster,
			accept:  true,
		},
		{
			name:    "same port other policy accepted",
			forward: wgnetv1alpha1.Forward{Port: 27000, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			policy:  wgnetv1alpha1.TrafficPolicyLocal,
			accept:  true,
		},
		{
			name:        "cluster custom health port forward on it rejected",
			forward:     wgnetv1alpha1.Forward{Port: 8181, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			policy:      wgnetv1alpha1.TrafficPolicyCluster,
			healthPort:  8181,
			wantMessage: "a TCP forward on spec.link.healthPort (27000 when unset) is rejected under trafficPolicy Cluster",
		},
		{
			name:       "cluster custom health port forward on default port accepted",
			forward:    wgnetv1alpha1.Forward{Port: 27000, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			policy:     wgnetv1alpha1.TrafficPolicyCluster,
			healthPort: 8181,
			accept:     true,
		},
		{
			name:        "local healthPort set rejected",
			forward:     wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			policy:      wgnetv1alpha1.TrafficPolicyLocal,
			healthPort:  8181,
			wantMessage: "spec.link.healthPort applies only to trafficPolicy Cluster; a Local Gateway's health port is 27000 plus its link id",
		},
		{
			name:        "healthPort out of range rejected by schema",
			forward:     wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			policy:      wgnetv1alpha1.TrafficPolicyCluster,
			healthPort:  70000,
			wantMessage: "spec.link.healthPort",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("health-port-admission-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

			gw := newGateway(ns, ns, []wgnetv1alpha1.Forward{tt.forward}, nil)
			gw.Spec.TrafficPolicy = tt.policy
			gw.Spec.Link.HealthPort = tt.healthPort
			assertAdmission(ctx, t, cl, gw, cl.Create(ctx, gw), tt.accept, tt.wantMessage)
		})
	}
}

// TestGatewayResponderAdmission covers: spec.responder.replicas is Cluster-only (the CEL rule
// added alongside spec.link's), and spec.responder.port is bounded by the schema.
func TestGatewayResponderAdmission(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tests := []struct {
		name        string
		policy      wgnetv1alpha1.TrafficPolicy
		responder   wgnetv1alpha1.GatewayResponderSpec
		accept      bool
		wantMessage string
	}{
		{
			name:        "local with replicas set rejected",
			policy:      wgnetv1alpha1.TrafficPolicyLocal,
			responder:   wgnetv1alpha1.GatewayResponderSpec{Replicas: 2},
			wantMessage: "spec.responder.replicas applies only to trafficPolicy Cluster; Local runs one responder per node",
		},
		{
			name:        "port out of range rejected by schema",
			policy:      wgnetv1alpha1.TrafficPolicyCluster,
			responder:   wgnetv1alpha1.GatewayResponderSpec{Port: 70000},
			wantMessage: "spec.responder.port",
		},
		{
			name:      "cluster with replicas accepted",
			policy:    wgnetv1alpha1.TrafficPolicyCluster,
			responder: wgnetv1alpha1.GatewayResponderSpec{Replicas: 3},
			accept:    true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("responder-admission-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

			gw := newGateway(ns, ns, nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			gw.Spec.Responder = tt.responder
			assertAdmission(ctx, t, cl, gw, cl.Create(ctx, gw), tt.accept, tt.wantMessage)
		})
	}
}

// reservedLinkID is the link id the reserved-health-port row pins into status, so its forward
// port is the 27000+id health port without depending on what the allocator would pick.
const reservedLinkID = 7

func TestReconcileGCPAdmission(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	tests := []struct {
		name    string
		gateway func(string) *wgnetv1alpha1.Gateway
		// prepare runs between the Gateway's creation and the first reconcile, for the
		// backends and status a row needs the reconciler to observe.
		prepare     func(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway)
		wantReason  string
		wantMessage string
		wantEvents  []string
	}{
		{
			name: "tunnel address outside subnet reports invalid",
			gateway: func(ns string) *wgnetv1alpha1.Gateway {
				gw := gcpLBGateway(ns, ns)
				gw.Spec.Wireguard.GatewayAddress = "10.99.1.1"
				return gw
			},
			wantReason:  reasonInvalidTunnelAddresses,
			wantMessage: "10.99.1.1",
			wantEvents:  []string{reasonInvalidTunnelAddresses},
		},
		{
			name: "local forward 27000 plus ID reported reserved health port",
			gateway: func(ns string) *wgnetv1alpha1.Gateway {
				gw := newGateway(ns, ns, []wgnetv1alpha1.Forward{
					{Port: int32(link.NewGatewayIdentity(reservedLinkID).HealthPort), Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
				}, nil)
				gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
				return gw
			},
			prepare: func(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway) {
				t.Helper()
				mustCreate(ctx, t, cl, portedClusterIPService(gw.Namespace, "web",
					int32(link.NewGatewayIdentity(reservedLinkID).HealthPort), corev1.ProtocolTCP))
				gw.Status.Link.ID = reservedLinkID
				if err := cl.Status().Update(ctx, gw); err != nil {
					t.Fatalf("set status.link.id: %v", err)
				}
			},
			wantReason:  reasonReservedHealthPort,
			wantMessage: fmt.Sprintf("%d", link.NewGatewayIdentity(reservedLinkID).HealthPort),
			wantEvents:  []string{reasonReservedHealthPort},
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("gcp-reconcile-admission-%d", i)
			mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
			gw := tt.gateway(ns)
			mustCreate(ctx, t, te.client, gw)
			if tt.prepare != nil {
				tt.prepare(ctx, t, te.client, gw)
			}
			recorder := &fakeEventRecorder{}
			r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme, Config: reconcileConfig(), Recorder: recorder}
			for range []int{0, 1} {
				if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err != nil {
					t.Fatalf("reconcile: %v", err)
				}
			}
			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), &got)
			condition := findCondition(got.Status.Conditions, conditionReady)
			if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != tt.wantReason || !strings.Contains(condition.Message, tt.wantMessage) {
				t.Errorf("Ready condition = %+v, want False %q mentioning %q", condition, tt.wantReason, tt.wantMessage)
			}
			gotEvents := make([]string, 0, len(recorder.events))
			for _, ev := range recorder.events {
				gotEvents = append(gotEvents, ev.reason)
			}
			if !slices.Equal(gotEvents, tt.wantEvents) {
				t.Errorf("event reasons = %v, want exactly %v", gotEvents, tt.wantEvents)
			}
		})
	}
}

// TestReconcileReservedHealthPortWarnSuppression covers Warning: the rejected forward
// warns once while it stays rejected, and again once a corrected forward is broken anew.
func TestReconcileReservedHealthPortWarnSuppression(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)

	const ns = "reserved-health-port-warn"
	healthPort := int32(link.NewGatewayIdentity(reservedLinkID).HealthPort)
	mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, te.client, portedClusterIPService(ns, "health", healthPort, corev1.ProtocolTCP))
	mustCreate(ctx, t, te.client, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

	collides := wgnetv1alpha1.Forward{Port: healthPort, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "health"}
	corrected := wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
	gw := newGateway(ns, ns, []wgnetv1alpha1.Forward{collides}, nil)
	gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	mustCreate(ctx, t, te.client, gw)
	mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)
	gw.Status.Link.ID = reservedLinkID
	if err := te.client.Status().Update(ctx, gw); err != nil {
		t.Fatalf("set status.link.id: %v", err)
	}

	recorder := &fakeEventRecorder{}
	r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
		Config: reconcileConfig(), Recorder: recorder}
	reconcileOnce(ctx, t, r, gw, "finalizer")
	for _, pass := range []struct {
		name    string
		forward wgnetv1alpha1.Forward
	}{{"rejected", collides}, {"rejected again", collides}, {"corrected", corrected}, {"rejected anew", collides}} {
		mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)
		gw.Spec.Forwards = []wgnetv1alpha1.Forward{pass.forward}
		if err := te.client.Update(ctx, gw); err != nil {
			t.Fatalf("update gateway (%s): %v", pass.name, err)
		}
		reconcileOnce(ctx, t, r, gw, pass.name)
	}

	gotEvents := make([]string, 0, len(recorder.events))
	for _, ev := range recorder.events {
		gotEvents = append(gotEvents, ev.reason)
	}
	want := []string{reasonReservedHealthPort, reasonReservedHealthPort}
	if !slices.Equal(gotEvents, want) {
		t.Errorf("event reasons = %v, want exactly %v", gotEvents, want)
	}
}

// TestReconcileReservedHealthPortProvisionsNothing verifies the reserved-port gate.
func TestReconcileReservedHealthPortProvisionsNothing(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	healthPort := int32(link.NewGatewayIdentity(reservedLinkID).HealthPort)

	tests := []struct {
		name        string
		forward     wgnetv1alpha1.Forward
		wantReason  string
		wantMessage string
		wantEvents  []string
	}{
		{
			name:       "the only forward takes the reserved health port",
			forward:    wgnetv1alpha1.Forward{Port: healthPort, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			wantReason: reasonReservedHealthPort,
			wantMessage: fmt.Sprintf("1 forward(s) invalid: forward TCP port %d collides with this gateway's own health port",
				healthPort),
			wantEvents: []string{reasonReservedHealthPort},
		},
		{
			name:       "the only forward names a port the backend does not publish",
			forward:    wgnetv1alpha1.Forward{Port: 8443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			wantReason: reasonTargetPortNotListening,
			wantMessage: fmt.Sprintf("1 forward(s) invalid: forward backend Service %q in namespace %q does not publish TCP port 8443",
				"web", "reserved-port-gate-1"),
			wantEvents: nil,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("reserved-port-gate-%d", i)
			mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
			mustCreate(ctx, t, te.client, portedClusterIPService(ns, "web", healthPort, corev1.ProtocolTCP))

			gw := newGateway(ns, ns, []wgnetv1alpha1.Forward{tt.forward}, nil)
			gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
			mustCreate(ctx, t, te.client, gw)
			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)
			// The reserved port is 27000+id, so the id is pinned rather than left to the
			// allocator: both rows then report the same link id too.
			gw.Status.Link.ID = reservedLinkID
			if err := te.client.Status().Update(ctx, gw); err != nil {
				t.Fatalf("set status.link.id: %v", err)
			}

			recorder := &fakeEventRecorder{}
			r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
				Config: reconcileConfig(), Recorder: recorder}
			for _, pass := range []string{"finalizer", "validation", "validation repeat"} {
				reconcileOnce(ctx, t, r, gw, pass)
			}

			gotEvents := make([]string, 0, len(recorder.events))
			for _, ev := range recorder.events {
				gotEvents = append(gotEvents, ev.reason)
			}
			if !slices.Equal(gotEvents, tt.wantEvents) {
				t.Errorf("event reasons = %v, want exactly %v", gotEvents, tt.wantEvents)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), &got)
			want := wgnetv1alpha1.GatewayStatus{
				Link: wgnetv1alpha1.GatewayLinkStatus{ID: reservedLinkID},
				Conditions: []metav1.Condition{{
					Type: conditionReady, Status: metav1.ConditionFalse, ObservedGeneration: got.Generation,
					Reason: tt.wantReason, Message: tt.wantMessage,
				}},
			}
			if diff := gatewayStatusWithoutTimestamps(got.Status); !reflect.DeepEqual(diff, want) {
				t.Errorf("status = %+v, want exactly %+v", diff, want)
			}

			// The namespace holds exactly its backend Service and the Gateway: the gate
			// precedes every write, whichever validation rejected the forward.
			assertNamespaceInventory(ctx, t, te.client, ns, []string{"Gateway/" + ns, "Service/web"})
		})
	}
}

// gatewayStatusWithoutTimestamps clears the condition timestamps the API server stamps, so a
// row can compare the whole status by value.
func gatewayStatusWithoutTimestamps(status wgnetv1alpha1.GatewayStatus) wgnetv1alpha1.GatewayStatus {
	conditions := make([]metav1.Condition, 0, len(status.Conditions))
	for _, cond := range status.Conditions {
		cond.LastTransitionTime = metav1.Time{}
		conditions = append(conditions, cond)
	}
	status.Conditions = conditions
	return status
}

// assertNamespaceInventory compares a namespace as a whole: every namespaced kind a Gateway's
// reconcile can write, plus the Gateways themselves, as sorted "Kind/name" entries.
func assertNamespaceInventory(ctx context.Context, t *testing.T, cl client.Client, namespace string, want []string) {
	t.Helper()
	lists := []struct {
		kind string
		list client.ObjectList
	}{
		{"Gateway", &wgnetv1alpha1.GatewayList{}},
		{"Secret", &corev1.SecretList{}},
		{"ConfigMap", &corev1.ConfigMapList{}},
		{"Service", &corev1.ServiceList{}},
		{"Deployment", &appsv1.DeploymentList{}},
		{"DaemonSet", &appsv1.DaemonSetList{}},
		{"NetworkPolicy", &networkingv1.NetworkPolicyList{}},
		{"Role", &rbacv1.RoleList{}},
		{"RoleBinding", &rbacv1.RoleBindingList{}},
		{"PodDisruptionBudget", &policyv1.PodDisruptionBudgetList{}},
		{"Lease", &coordinationv1.LeaseList{}},
		{XGatewayGCPGVK.Kind, unstructuredListOf(XGatewayGCPGVK.GroupVersion().WithKind(XGatewayGCPGVK.Kind + "List"))},
		{dnsEndpointKind, unstructuredListOf(schema.GroupVersion{Group: "externaldns.k8s.io", Version: "v1alpha1"}.WithKind(dnsEndpointKind + "List"))},
	}

	got := make([]string, 0, len(want))
	for _, entry := range lists {
		if err := cl.List(ctx, entry.list, client.InNamespace(namespace)); err != nil {
			t.Fatalf("list %ss in %s: %v", entry.kind, namespace, err)
		}
		items, err := apimeta.ExtractList(entry.list)
		if err != nil {
			t.Fatalf("extract %s list: %v", entry.kind, err)
		}
		for _, item := range items {
			obj, ok := item.(client.Object)
			if !ok {
				t.Fatalf("%s list item %T is not a client.Object", entry.kind, item)
			}
			got = append(got, entry.kind+"/"+obj.GetName())
		}
	}
	slices.Sort(got)
	wantSorted := slices.Sorted(slices.Values(want))
	if !slices.Equal(got, wantSorted) {
		t.Errorf("objects in %s = %v, want exactly %v", namespace, got, wantSorted)
	}
}

func unstructuredListOf(gvk schema.GroupVersionKind) *unstructured.UnstructuredList {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gvk)
	return list
}
