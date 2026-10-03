package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// reconcileConfig is the operator config the controller tests reconcile with. PodNamespace is
// "default": every envtest control plane provisions it, so the shared network applies cleanly.
func reconcileConfig() Config {
	return Config{
		LinkImage:           "registry.example.com/gateway-link:test",
		LinkImagePullPolicy: "IfNotPresent",
		UserData:            "#ignition\n",
		SharedNetworkName:   "wgnet-test",
		PodNamespace:        "default",
		// Zero requeue keeps the test from depending on wall-clock requeue timing;
		// the test re-invokes Reconcile explicitly.
		RequeueInterval: 0,
		ResponderImage:  "registry.example.com/gateway-responder:test",
	}
}

// countingKeyGen returns a deterministic KeyGenerator and a pointer to its call
// count, so a test can assert key material is generated exactly once.
func countingKeyGen() (KeyGenerator, *int) {
	calls := 0
	gen := func() (string, string, error) {
		calls++
		return fmt.Sprintf("priv-%d", calls), fmt.Sprintf("pub-%d", calls), nil
	}
	return gen, &calls
}

// drainReconcile invokes Reconcile a few times so the finalizer-add pass and the ensure/mirror
// passes all run. Reconcile is idempotent, so the fixed iteration count is safe.
func drainReconcile(ctx context.Context, t *testing.T, r *GatewayReconciler, key client.ObjectKey) {
	t.Helper()
	req := ctrl.Request{NamespacedName: key}
	for range 3 {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
}

func sampleGateway(name, namespace string) *wgnetv1alpha1.Gateway {
	return newGateway(name, namespace,
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		},
		[]string{"edge.example.com"},
	)
}

// reconcileFixture starts envtest with the wg-system namespace and a sample Gateway. SSA, which
// the fake client cannot model, is why these tests need a real control plane.
func reconcileFixture(ctx context.Context, t *testing.T) (*testEnv, *GatewayReconciler, *wgnetv1alpha1.Gateway, client.ObjectKey, *int) {
	t.Helper()
	te := setupEnvtestRBAC(t)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wg-system"}}
	if err := te.client.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace: %v", err)
	}

	// Classification requires each backend to exist with a ClusterIP publishing the forward's
	// port before provisioning, so the lifecycle path must create them with matching ports.
	for _, svc := range []*corev1.Service{
		portedClusterIPService("wg-system", "web", 443, corev1.ProtocolTCP),
		portedClusterIPService("wg-system", "vpn", 1194, corev1.ProtocolUDP),
	} {
		if err := te.client.Create(ctx, svc); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create service %s: %v", svc.Name, err)
		}
	}

	gw := sampleGateway("edge", "wg-system")
	if err := te.client.Create(ctx, gw); err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	gen, calls := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
	return te, r, gw, client.ObjectKeyFromObject(gw), calls
}

// TestReconcileLifecycle runs against a real API server, required because the reconciler applies
// its children with server-side apply.
func TestReconcileLifecycle(t *testing.T) {
	ctx := context.Background()
	te, r, gw, key, calls := reconcileFixture(ctx, t)
	cl := te.client

	drainReconcile(ctx, t, r, key)

	t.Run("finalizer added", func(t *testing.T) {
		var got wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &got)
		if !controllerutil.ContainsFinalizer(&got, gatewayFinalizer) {
			t.Errorf("finalizer %q not present: %v", gatewayFinalizer, got.Finalizers)
		}
	})

	t.Run("secrets created once and owner-ref'd", func(t *testing.T) {
		var bundle corev1.Secret
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-bundle"}, &bundle)
		if got := string(bundle.Data[wg.BundleKey]); got != "priv-1\npub-2\n" {
			t.Errorf("bundle = %q, want priv-1\\npub-2\\n", got)
		}
		assertOwnedByGateway(t, &bundle, gw)

		var linkSec corev1.Secret
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &linkSec)
		if got := string(linkSec.Data[wg.LinkPrivateKey]); got != "priv-2" {
			t.Errorf("link private = %q, want priv-2", got)
		}
		if got := string(linkSec.Data[wg.LinkPeerPublicKey]); got != "pub-1" {
			t.Errorf("link peer public = %q, want pub-1", got)
		}
		assertOwnedByGateway(t, &linkSec, gw)

		// A second reconcile must not regenerate keys.
		drainReconcile(ctx, t, r, key)
		if *calls != 2 {
			t.Errorf("keygen calls = %d, want 2 (generate once)", *calls)
		}
	})

	t.Run("xgatewaygcp created and owner-ref'd", func(t *testing.T) {
		xg := newXGatewayGCP()
		mustGet(ctx, t, cl, key, xg)
		assertNestedString(t, xg, "us-central1", "spec", "region")
		assertOwnedByGatewayUnstructured(t, xg, gw)
	})

	t.Run("link children created and owner-ref'd", func(t *testing.T) {
		var dep appsv1.Deployment
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &dep)
		assertOwnedByGateway(t, &dep, gw)

		var cm corev1.ConfigMap
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &cm)
		assertOwnedByGateway(t, &cm, gw)

		var np networkingv1.NetworkPolicy
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &np)
		assertOwnedByGateway(t, &np, gw)

		// The link runs leader election, so the operator creates its dedicated
		// ServiceAccount, Role, and RoleBinding, each owner-ref'd to the Gateway.
		var sa corev1.ServiceAccount
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &sa)
		assertOwnedByGateway(t, &sa, gw)

		var role rbacv1.Role
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &role)
		assertOwnedByGateway(t, &role, gw)

		var rb rbacv1.RoleBinding
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &rb)
		assertOwnedByGateway(t, &rb, gw)
	})

	t.Run("status mirrored and endpoint rendered after composite reports address", func(t *testing.T) {
		setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.9", "sa@example.iam.gserviceaccount.com", "")
		setLinkLeaseActive(ctx, t, cl, key, "edge-link-0", true, "node-a")
		drainReconcile(ctx, t, r, key)

		var got wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &got)
		if got.Status.Address != "203.0.113.9" {
			t.Errorf("status.address = %q, want 203.0.113.9", got.Status.Address)
		}
		if got.Status.ServiceAccountEmail != "sa@example.iam.gserviceaccount.com" {
			t.Errorf("status.serviceAccountEmail = %q, want sa@...", got.Status.ServiceAccountEmail)
		}
		if c := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady); c == nil || c.Status != metav1.ConditionTrue {
			t.Errorf("Ready condition = %+v, want True", c)
		}

		// Once the composite reports an address, the reconciler renders it as the
		// link's WireGuard peer endpoint so the link reloads in place.
		var cm corev1.ConfigMap
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: "wg-system", Name: "edge-link"}, &cm)
		var rc link.RuntimeConfig
		decodeJSON(t, cm.Data[linkConfigKey], &rc)
		if len(rc.WireGuard.Peers) != 1 {
			t.Fatalf("link configmap peers = %d, want 1", len(rc.WireGuard.Peers))
		}
		if want := "203.0.113.9:51820"; rc.WireGuard.Peers[0].Endpoint != want {
			t.Errorf("link configmap peer.endpoint = %q, want %q", rc.WireGuard.Peers[0].Endpoint, want)
		}
	})

	t.Run("dns endpoint created once address known", func(t *testing.T) {
		ep := &unstructured.Unstructured{}
		ep.SetGroupVersionKind(buildDNSEndpoint(gw, "x").GroupVersionKind())
		mustGet(ctx, t, cl, key, ep)
		endpoints, found, err := unstructured.NestedSlice(ep.Object, "spec", "endpoints")
		if err != nil || !found || len(endpoints) != 1 {
			t.Errorf("dns endpoints = %v (found=%v err=%v), want one", endpoints, found, err)
		}
		assertOwnedByGatewayUnstructured(t, ep, gw)
	})

	t.Run("delete removes xgatewaygcp and releases finalizer", func(t *testing.T) {
		var live wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &live)
		if err := cl.Delete(ctx, &live); err != nil {
			t.Fatalf("delete gateway: %v", err)
		}

		eventually(ctx, t, "gateway finalizer release after drain", func() bool {
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("reconcile delete: %v", err)
			}
			var after wgnetv1alpha1.Gateway
			return apierrors.IsNotFound(cl.Get(ctx, key, &after))
		})

		xg := newXGatewayGCP()
		if err := cl.Get(ctx, key, xg); !apierrors.IsNotFound(err) {
			t.Errorf("xgatewaygcp get after gateway purge = %v, want NotFound", err)
		}

		// edge is the only Gateway, so its teardown is the last delete: the refcount
		// path must have deleted the shared network too.
		if err := cl.Get(ctx, sharedNetworkKey(r), newXGatewayNetwork()); !apierrors.IsNotFound(err) {
			t.Errorf("shared network get after last gateway purge = %v, want NotFound", err)
		}
	})
}

// TestReconcileIdempotent asserts a converged Gateway is not rewritten (resourceVersion stays
// stable), guarding against a status-write loop in the provisioning and ready states.
func TestReconcileIdempotent(t *testing.T) {
	tests := []struct {
		name    string
		address string
		saEmail string
	}{
		{
			name: "provisioning, no composite address yet",
		},
		{
			name:    "ready, composite reports address",
			address: "203.0.113.9",
			saEmail: "sa@example.iam.gserviceaccount.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			te, r, _, key, _ := reconcileFixture(ctx, t)
			cl := te.client

			drainReconcile(ctx, t, r, key)
			if tc.address != "" {
				setXGatewayGCPStatus(ctx, t, cl, key, tc.address, tc.saEmail, "")
				setLinkLeaseActive(ctx, t, cl, key, key.Name+"-link-0", true, "node-a")
				drainReconcile(ctx, t, r, key)
			}

			var converged wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &converged)
			if converged.Status.Address != tc.address {
				t.Fatalf("status.address = %q, want %q", converged.Status.Address, tc.address)
			}

			rvBefore := converged.ResourceVersion
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("redundant reconcile: %v", err)
			}

			var after wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &after)
			if after.ResourceVersion != rvBefore {
				t.Errorf("gateway resourceVersion changed on redundant reconcile: %s -> %s (status write loop)",
					rvBefore, after.ResourceVersion)
			}
			if after.Status.Address != tc.address {
				t.Errorf("status.address drifted to %q, want %q", after.Status.Address, tc.address)
			}
			wantReady := metav1.ConditionFalse
			if tc.address != "" {
				wantReady = metav1.ConditionTrue
			}
			if c := apimeta.FindStatusCondition(after.Status.Conditions, conditionReady); c == nil || c.Status != wantReady {
				t.Errorf("Ready condition = %+v, want %s", c, wantReady)
			}
		})
	}
}

// sharedNetworkKey is the key of the singleton shared network r ensures, derived from its config
// so it cannot drift from what the reconciler applies.
func sharedNetworkKey(r *GatewayReconciler) client.ObjectKey {
	return client.ObjectKey{Name: r.Config.SharedNetworkName, Namespace: r.Config.PodNamespace}
}

// reconcileUntilGone drives Reconcile until the Gateway at key is purged. The refcount teardown
// spans several reconciles, where a fixed iteration count would be brittle.
func reconcileUntilGone(ctx context.Context, t *testing.T, r *GatewayReconciler, cl client.Client, key client.ObjectKey) {
	t.Helper()
	eventually(ctx, t, "gateway "+key.String()+" purged after delete", func() bool {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile delete %s: %v", key, err)
		}
		return apierrors.IsNotFound(cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}))
	})
}

// TestReconcileSharedNetworkRefcount asserts the shared network survives deleting the first of
// two Gateways sharing it and is torn down only by the last delete.
func TestReconcileSharedNetworkRefcount(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	const ns = "wg-system"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "vpn", 1194, corev1.ProtocolUDP))

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

	gw1 := sampleGateway("gw-one", ns)
	gw2 := sampleGateway("gw-two", ns)
	mustCreate(ctx, t, cl, gw1)
	mustCreate(ctx, t, cl, gw2)
	key1 := client.ObjectKeyFromObject(gw1)
	key2 := client.ObjectKeyFromObject(gw2)

	drainReconcile(ctx, t, r, key1)
	drainReconcile(ctx, t, r, key2)

	// Both Gateways converged, so the singleton shared network exists exactly once.
	if err := cl.Get(ctx, sharedNetworkKey(r), newXGatewayNetwork()); err != nil {
		t.Fatalf("shared network get after both gateways provisioned = %v, want present", err)
	}

	// Deleting the first of two Gateways is not the last delete: the network must
	// survive and gw-one must be fully purged.
	mustDeleteGateway(ctx, t, cl, key1)
	reconcileUntilGone(ctx, t, r, cl, key1)
	if err := cl.Get(ctx, sharedNetworkKey(r), newXGatewayNetwork()); err != nil {
		t.Errorf("shared network get after first of two gateways deleted = %v, want still present", err)
	}

	// Deleting the second Gateway is the last delete: the refcount path must tear
	// the shared network down and only then release gw-two's finalizer.
	mustDeleteGateway(ctx, t, cl, key2)
	reconcileUntilGone(ctx, t, r, cl, key2)
	if err := cl.Get(ctx, sharedNetworkKey(r), newXGatewayNetwork()); !apierrors.IsNotFound(err) {
		t.Errorf("shared network get after last gateway deleted = %v, want NotFound", err)
	}
}

// mustDeleteGateway re-reads the live Gateway at key and deletes it, so the delete
// carries the server's current resourceVersion rather than a stale fixture copy.
func mustDeleteGateway(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) {
	t.Helper()
	var live wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &live)
	if err := cl.Delete(ctx, &live); err != nil {
		t.Fatalf("delete gateway %s: %v", key, err)
	}
}

// newGatewayCELFixture builds a Gateway with the given forwards and an explicit listen port. A
// zero wgPort is left unset so the CRD default applies.
func newGatewayCELFixture(name, namespace string, wgPort int32, forwards []wgnetv1alpha1.Forward) *wgnetv1alpha1.Gateway {
	gw := newGateway(name, namespace, forwards, nil)
	gw.Spec.Wireguard.ListenPort = wgPort
	return gw
}

// newGatewayNoWireguard builds a Gateway as unstructured with spec.wireguard absent. A typed
// fixture cannot express this: omitempty does not drop a non-pointer struct.
func newGatewayNoWireguard(name, namespace string, forwards []wgnetv1alpha1.Forward) *unstructured.Unstructured {
	rawForwards := make([]any, 0, len(forwards))
	for _, f := range forwards {
		rawForwards = append(rawForwards, map[string]any{
			"port":     int64(f.Port),
			"protocol": string(f.Protocol),
			"service":  f.Service,
		})
	}

	spec := map[string]any{
		"gcp": map[string]any{
			"projectID": "test-project",
			"region":    "us-central1",
			"zone":      "us-central1-a",
		},
	}
	if len(rawForwards) > 0 {
		spec["forwards"] = rawForwards
	}

	gw := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	gw.SetGroupVersionKind(wgnetv1alpha1.GroupVersion.WithKind("Gateway"))
	gw.SetName(name)
	gw.SetNamespace(namespace)
	return gw
}

// TestGatewayCELValidation exercises the spec-level CEL rules at admission: per-(port,protocol)
// uniqueness and the bar on a UDP forward over the WireGuard listen port.
func TestGatewayCELValidation(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tcp := wgnetv1alpha1.ProtocolTCP
	udp := wgnetv1alpha1.ProtocolUDP

	tests := []struct {
		name string
		// omitWireguard runs the rules against the CRD-defaulted block; otherwise wgPort
		// sets the listen port explicitly (zero leaves it unset for the default).
		omitWireguard bool
		wgPort        int32
		forwards      []wgnetv1alpha1.Forward
		trafficPolicy wgnetv1alpha1.TrafficPolicy
		linkReplicas  int32
		accept        bool
		// wantMessage, when set, must appear in the rejection error.
		wantMessage string
	}{
		{
			name:   "duplicate port and protocol rejected",
			wgPort: 0,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: tcp, Service: "a"},
				{Port: 443, Protocol: tcp, Service: "b"},
			},
			accept: false,
		},
		{
			name:   "same port differing protocol accepted",
			wgPort: 0,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: tcp, Service: "a"},
				{Port: 443, Protocol: udp, Service: "b"},
			},
			accept: true,
		},
		{
			name:   "udp forward on defaulted wireguard port rejected",
			wgPort: 0,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51820, Protocol: udp, Service: "a"},
			},
			accept: false,
		},
		{
			name:          "udp forward on omitted wireguard port rejected",
			omitWireguard: true,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51820, Protocol: udp, Service: "a"},
			},
			accept: false,
		},
		{
			name:   "udp forward on explicit wireguard port rejected",
			wgPort: 51821,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51821, Protocol: udp, Service: "a"},
			},
			accept: false,
		},
		{
			name:   "udp forward on default port accepted when wireguard port moved",
			wgPort: 51821,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51820, Protocol: udp, Service: "a"},
			},
			accept: true,
		},
		{
			name:   "tcp forward on wireguard port accepted",
			wgPort: 51820,
			forwards: []wgnetv1alpha1.Forward{
				{Port: 51820, Protocol: tcp, Service: "a"},
			},
			accept: true,
		},
		{
			name:          "local with multiple link replicas rejected",
			trafficPolicy: wgnetv1alpha1.TrafficPolicyLocal,
			linkReplicas:  2,
			accept:        false,
			wantMessage:   "spec.link.replicas applies only to trafficPolicy Cluster",
		},
		{
			name:          "local with no link block accepted",
			trafficPolicy: wgnetv1alpha1.TrafficPolicyLocal,
			accept:        true,
		},
		{
			name:          "cluster with multiple link replicas accepted",
			trafficPolicy: wgnetv1alpha1.TrafficPolicyCluster,
			linkReplicas:  2,
			accept:        true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("cel-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

			var gw client.Object
			if tt.omitWireguard {
				gw = newGatewayNoWireguard(ns, ns, tt.forwards)
			} else {
				typed := newGatewayCELFixture(ns, ns, tt.wgPort, tt.forwards)
				typed.Spec.TrafficPolicy = tt.trafficPolicy
				typed.Spec.Link.Replicas = tt.linkReplicas
				gw = typed
			}
			assertAdmission(ctx, t, cl, gw, cl.Create(ctx, gw), tt.accept, tt.wantMessage)
		})
	}
}

// TestGatewayWireguardDefaulting verifies spec.wireguard is optional: a Gateway omitting the
// block is admitted and reads back with every sub-field carrying its CRD default.
func TestGatewayWireguardDefaulting(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const ns = "wg-default"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

	gw := newGatewayNoWireguard(ns, ns, nil)
	if err := cl.Create(ctx, gw); err != nil {
		t.Fatalf("create Gateway with omitted spec.wireguard: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: ns}, &got)

	wantWG := wgnetv1alpha1.GatewayWireguardSpec{
		ListenPort:        51820,
		Subnet:            "10.99.0.0/29",
		GatewayAddress:    "10.99.0.1",
		LinkAddress:       "10.99.0.2",
		Keepalive:         25,
		MTU:               1380,
		ReconcileInterval: "10s",
	}
	if got.Spec.Wireguard != wantWG {
		t.Errorf("defaulted spec.wireguard = %+v, want %+v", got.Spec.Wireguard, wantWG)
	}
}

// portedClusterIPService builds a ClusterIP Service in ns publishing port/proto; envtest assigns
// spec.clusterIP on create, so classification sees a routable VIP.
func portedClusterIPService(ns, name string, port int32, proto corev1.Protocol) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{Port: port, Protocol: proto}},
		},
	}
}

// TestReconcileNetworkPolicyAllowsRemappedBackendPort pins port resolution through a real apply:
// egress must open the pod port kube-proxy DNATs to, and a named targetPort a protocol-only rule.
func TestReconcileNetworkPolicyAllowsRemappedBackendPort(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name       string
		namespace  string
		targetPort intstr.IntOrString
		// wantPorts are the numeric TCP ports the applied policy must open to
		// 0.0.0.0/0.
		wantPorts []int32
		// wantProtocolOnly expects a port-less (whole-protocol) egress rule instead,
		// the shape an unresolved backend port renders.
		wantProtocolOnly bool
	}{
		{
			name:       "numeric target port opens both the service port and the pod port",
			namespace:  "np-remap",
			targetPort: intstr.FromInt32(10443),
			wantPorts:  []int32{443, 10443},
		},
		{
			name:             "named target port leaves a protocol-only rule",
			namespace:        "np-named",
			targetPort:       intstr.FromString("https"),
			wantProtocolOnly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustCreate(ctx, t, cl, namespaceWithLabels(tt.namespace, nil))

			svc := portedClusterIPService(tt.namespace, "web", 443, corev1.ProtocolTCP)
			svc.Spec.Ports[0].Name = "https"
			svc.Spec.Ports[0].TargetPort = tt.targetPort
			mustCreate(ctx, t, cl, svc)

			gw := newGateway("edge", tt.namespace, []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			mustCreate(ctx, t, cl, gw)

			gen, _ := countingKeyGen()
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
			drainReconcile(ctx, t, r, client.ObjectKeyFromObject(gw))

			var np networkingv1.NetworkPolicy
			mustGet(ctx, t, cl, client.ObjectKey{Namespace: tt.namespace, Name: "edge-link"}, &np)

			for _, port := range tt.wantPorts {
				if !hasOpenEgressPort(np.Spec.Egress, corev1.ProtocolTCP, port) {
					t.Errorf("applied networkpolicy missing egress to TCP %d: %+v", port, np.Spec.Egress)
				}
			}
			if tt.wantProtocolOnly {
				if !hasProtocolOnlyEgress(np.Spec.Egress, corev1.ProtocolTCP) {
					t.Errorf("applied networkpolicy has no protocol-only TCP egress rule: %+v", np.Spec.Egress)
				}
				if hasOpenEgressPort(np.Spec.Egress, corev1.ProtocolTCP, 443) {
					t.Errorf("applied networkpolicy pins TCP 443 for an unresolved backend port: %+v", np.Spec.Egress)
				}
			}
		})
	}
}

// TestGatewayReadyProvisioningMessage exercises the operator-side fold: the composite's
// status.message is appended to the Provisioning Ready message, truncated like a link fault.
func TestGatewayReadyProvisioningMessage(t *testing.T) {
	const baseMsg = "waiting for gateway address and active link tunnel"
	longM := strings.Repeat("m", 5000)
	wantTruncated := baseMsg + ": " + longM[:maxFaultMessageBytes-len(faultMessageTruncationMarker)] + faultMessageTruncationMarker

	tests := []struct {
		name        string
		address     string
		saEmail     string
		message     string
		wantMessage string
	}{
		{name: "address empty, message empty", wantMessage: baseMsg},
		{name: "address empty, message set", message: "address not found", wantMessage: baseMsg + ": address not found"},
		{name: "address set, message empty", address: "203.0.113.60", wantMessage: baseMsg},
		{name: "address set, message set", address: "203.0.113.60", message: "bind failed", wantMessage: baseMsg + ": bind failed"},
		{name: "message over budget is truncated with the prefix kept", message: longM, wantMessage: wantTruncated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			te, r, _, key, _ := reconcileFixture(ctx, t)
			cl := te.client

			drainReconcile(ctx, t, r, key)
			setXGatewayGCPStatus(ctx, t, cl, key, tt.address, tt.saEmail, tt.message)
			drainReconcile(ctx, t, r, key)

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			c := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if c == nil {
				t.Fatalf("Ready condition absent")
			}
			if c.Status != metav1.ConditionFalse || c.Reason != reasonProvisioning {
				t.Fatalf("Ready = %s/%s, want False/Provisioning", c.Status, c.Reason)
			}
			if c.Message != tt.wantMessage {
				t.Errorf("Ready message = %q, want %q", c.Message, tt.wantMessage)
			}
		})
	}
}

func namespaceWithLabels(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// mustCreate creates obj, tolerating an already-exists result so a shared envtest
// control plane can be reused across rows.
func mustCreate(ctx context.Context, t *testing.T, cl client.Client, obj client.Object) {
	t.Helper()
	if err := cl.Create(ctx, obj); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create %T %s/%s: %v", obj, obj.GetNamespace(), obj.GetName(), err)
	}
}

func mustGet(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, obj client.Object) {
	t.Helper()
	if err := cl.Get(ctx, key, obj); err != nil {
		t.Fatalf("get %s %s: %v", obj.GetObjectKind().GroupVersionKind().Kind, key, err)
	}
}

// Simulates Crossplane's status write; an empty message leaves status.message unset, matching a
// composite that never wrote it.
func setXGatewayGCPStatus(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, address, saEmail, message string) {
	t.Helper()
	xg := newXGatewayGCP()
	mustGet(ctx, t, cl, key, xg)
	if err := unstructured.SetNestedField(xg.Object, address, "status", "address"); err != nil {
		t.Fatalf("set status.address: %v", err)
	}
	if err := unstructured.SetNestedField(xg.Object, saEmail, "status", "serviceAccountEmail"); err != nil {
		t.Fatalf("set status.serviceAccountEmail: %v", err)
	}
	if message != "" {
		if err := unstructured.SetNestedField(xg.Object, message, "status", "message"); err != nil {
			t.Fatalf("set status.message: %v", err)
		}
	}
	if err := cl.Status().Update(ctx, xg); err != nil {
		t.Fatalf("update xgatewaygcp status: %v", err)
	}
}

// Envtest lacks scheduler/kubelet updates, so this sets PodReady and simulates the holder's
// tunnel-ready Lease annotation when ready.
func setLinkLeaseActive(ctx context.Context, t *testing.T, cl client.Client, gwKey client.ObjectKey, podName string, ready bool, nodeName string) {
	t.Helper()
	leaseName := linkComponentName(&wgnetv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: gwKey.Name, Namespace: gwKey.Namespace},
	})

	var annotations map[string]string
	if ready {
		annotations = map[string]string{link.LeaseTunnelReadyAnnotation: "true"}
	}
	upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: gwKey.Namespace, Name: leaseName}, podName, annotations)
	upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: gwKey.Namespace, Name: podName}, ready, nodeName)
}

// setLinkLeaseFault stamps the link-fault annotations onto the Gateway's link Lease. An empty
// reason clears them, which is how the holder signals it has finished programming.
func setLinkLeaseFault(ctx context.Context, t *testing.T, cl client.Client, gwKey client.ObjectKey, reason, message string) {
	t.Helper()
	leaseKey := client.ObjectKey{Namespace: gwKey.Namespace, Name: gwKey.Name + "-link"}

	var lease coordinationv1.Lease
	if err := cl.Get(ctx, leaseKey, &lease); err != nil {
		t.Fatalf("get link lease %s: %v", leaseKey, err)
	}
	if lease.Annotations == nil {
		lease.Annotations = map[string]string{}
	}
	if reason == "" {
		delete(lease.Annotations, link.LeaseFaultAnnotation)
		delete(lease.Annotations, link.LeaseFaultMessageAnnotation)
	} else {
		lease.Annotations[link.LeaseFaultAnnotation] = reason
		lease.Annotations[link.LeaseFaultMessageAnnotation] = message
	}
	if err := cl.Update(ctx, &lease); err != nil {
		t.Fatalf("update link lease %s annotations: %v", leaseKey, err)
	}
}

// upsertLeaseHolder ensures a Lease at key exists with HolderIdentity set to holder, creating
// it on first call and patching the holder thereafter.
func upsertLeaseHolder(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, holder string, annotations map[string]string) {
	t.Helper()
	var lease coordinationv1.Lease
	err := cl.Get(ctx, key, &lease)
	switch {
	case apierrors.IsNotFound(err):
		lease = coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, Annotations: annotations},
			Spec:       coordinationv1.LeaseSpec{HolderIdentity: &holder},
		}
		if err := cl.Create(ctx, &lease); err != nil {
			t.Fatalf("create link lease %s: %v", key, err)
		}
	case err != nil:
		t.Fatalf("get link lease %s: %v", key, err)
	default:
		lease.Spec.HolderIdentity = &holder
		lease.Annotations = annotations
		if err := cl.Update(ctx, &lease); err != nil {
			t.Fatalf("update link lease %s holder: %v", key, err)
		}
	}
}

// upsertPodReady ensures a minimal pod at key has its PodReady condition set to ready, writing
// the status subresource directly since envtest has no kubelet. Idempotent across flips.
func upsertPodReady(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, ready bool, nodeName string) {
	t.Helper()
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}

	var pod corev1.Pod
	if err := cl.Get(ctx, key, &pod); err != nil {
		if !apierrors.IsNotFound(err) {
			t.Fatalf("get link holder pod %s: %v", key, err)
		}
		pod = corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Spec: corev1.PodSpec{
				NodeName:   nodeName,
				Containers: []corev1.Container{{Name: "link", Image: "registry.example.com/gateway-link:test"}},
			},
		}
		if err := cl.Create(ctx, &pod); err != nil {
			t.Fatalf("create link holder pod %s: %v", key, err)
		}
	}

	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}
	if err := cl.Status().Update(ctx, &pod); err != nil {
		t.Fatalf("update link holder pod %s status: %v", key, err)
	}
}

func assertOwnedByGateway(t *testing.T, obj metav1.Object, gw *wgnetv1alpha1.Gateway) {
	t.Helper()
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Kind == "Gateway" && ref.Name == gw.Name && ref.Controller != nil && *ref.Controller {
			return
		}
	}
	t.Errorf("object %s/%s missing controller owner-ref to Gateway %s; refs=%v",
		obj.GetNamespace(), obj.GetName(), gw.Name, obj.GetOwnerReferences())
}

func assertOwnedByGatewayUnstructured(t *testing.T, u *unstructured.Unstructured, gw *wgnetv1alpha1.Gateway) {
	t.Helper()
	assertOwnedByGateway(t, u, gw)
}

type recordedEvent struct {
	regarding runtime.Object
	eventtype string
	reason    string
	action    string
	note      string
}

// fakeEventRecorder records every Eventf call. The interface has a single method, so a generated
// mock would add nothing over capturing the args directly.
type fakeEventRecorder struct {
	events []recordedEvent
}

func (f *fakeEventRecorder) Eventf(regarding runtime.Object, _ runtime.Object, eventtype, reason, action, note string, args ...any) {
	f.events = append(f.events, recordedEvent{
		regarding: regarding,
		eventtype: eventtype,
		reason:    reason,
		action:    action,
		note:      fmt.Sprintf(note, args...),
	})
}

// TestReconcilerFailEmitsEvent covers the reconcile-failure path: fail emits a Warning event
// when a recorder is wired, and does not panic when the recorder is nil.
func TestReconcilerFailEmitsEvent(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wg-system"}}
	mustCreate(ctx, t, cl, ns)

	tests := []struct {
		name         string
		gateway      string
		withRecorder bool
		wantEvents   int
	}{
		{name: "records warning event when recorder wired", gateway: "fail-recorded", withRecorder: true, wantEvents: 1},
		{name: "no panic when recorder nil", gateway: "fail-nil-recorder", withRecorder: false, wantEvents: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway(tt.gateway, "wg-system", nil, nil)
			mustCreate(ctx, t, cl, gw)

			rec := &fakeEventRecorder{}
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig()})
			if tt.withRecorder {
				r.Recorder = rec
			}

			cause := fmt.Errorf("boom")
			_, err := r.fail(ctx, gw, "ensure xgatewaygcp", cause)
			if err == nil {
				t.Fatalf("fail returned nil error; want the wrapped cause surfaced")
			}
			if !errors.Is(err, cause) {
				t.Errorf("fail error = %v; want it to wrap %v", err, cause)
			}

			if len(rec.events) != tt.wantEvents {
				t.Fatalf("recorded %d events; want %d", len(rec.events), tt.wantEvents)
			}
			if tt.wantEvents == 0 {
				return
			}

			ev := rec.events[0]
			if ev.eventtype != corev1.EventTypeWarning {
				t.Errorf("event type = %q; want %q", ev.eventtype, corev1.EventTypeWarning)
			}
			if ev.reason != reasonReconcileFailed {
				t.Errorf("event reason = %q; want %q", ev.reason, reasonReconcileFailed)
			}
			if ev.action != actionReconcile {
				t.Errorf("event action = %q; want %q", ev.action, actionReconcile)
			}
			if evGW, ok := ev.regarding.(*wgnetv1alpha1.Gateway); !ok || evGW.Name != tt.gateway {
				t.Errorf("event regarding = %#v; want Gateway %q", ev.regarding, tt.gateway)
			}
			if !strings.Contains(ev.note, "ensure xgatewaygcp") || !strings.Contains(ev.note, "boom") {
				t.Errorf("event note = %q; want it to describe the wrapped failure", ev.note)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, client.ObjectKeyFromObject(gw), &got)
			cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonReconcileFailed {
				t.Errorf("Ready condition = %#v; want False/%s", cond, reasonReconcileFailed)
			}
		})
	}
}

// TestLinkActiveReadyGate covers the active-tunnel gate: readiness follows the lease holder pod,
// so a Ready idle standby must not mask a holder that is not Ready.
func TestLinkActiveReadyGate(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name string
		// arrange sets state after provisioning and address assignment; holderName may identify the
		// row's Lease holder pod.
		arrange   func(t *testing.T, ns, holderName string)
		wantReady metav1.ConditionStatus
		// wantRequeueAfter is the requeue the row's reconcile pass must return; zero when the
		// holder pod is left not Ready, since reconcileConfig sets a zero steady-state poll.
		wantRequeueAfter time.Duration
	}{
		{
			name: "holder pod ready, tunnel up",
			arrange: func(t *testing.T, ns, holderName string) {
				setLinkLeaseActive(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw"}, holderName, true, "node-a")
			},
			wantReady: metav1.ConditionTrue,
		},
		{
			name: "holder pod not ready masks a ready standby",
			arrange: func(t *testing.T, ns, holderName string) {
				// The Ready standby is not the lease holder. The holder gates the tunnel,
				// and it is not Ready, so the Gateway must be Ready=False.
				upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link-standby"}, true, "node-b")
				setLinkLeaseActive(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw"}, holderName, false, "node-a")
			},
			wantReady: metav1.ConditionFalse,
		},
		{
			name: "lease absent, no active tunnel",
			arrange: func(_ *testing.T, _, _ string) {
				// No lease and no holder pod: linkStatusOf must read NotFound and report
				// the tunnel as not active without erroring.
			},
			wantReady: metav1.ConditionFalse,
		},
		{
			name: "lease present but holder pod absent",
			arrange: func(t *testing.T, ns, holderName string) {
				// The lease names a missing holder pod, the failover window between the old
				// holder releasing and the new one publishing. linkStatusOf must tolerate it.
				upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link"}, holderName, nil)
			},
			wantReady: metav1.ConditionFalse,
		},
		{
			name: "holder pod ready, tunnel annotation absent",
			arrange: func(t *testing.T, ns, holderName string) {
				// The kubelet probe latched PodReady before the holder's first Lease write:
				// the Gateway must stay Ready=False and poll again inside the requeue floor.
				upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link"}, holderName, nil)
				upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: holderName}, true, "node-a")
			},
			wantReady:        metav1.ConditionFalse,
			wantRequeueAfter: tunnelReadyPollInterval,
		},
		{
			name: "holder pod ready, tunnel annotation false",
			arrange: func(t *testing.T, ns, holderName string) {
				upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link"}, holderName,
					map[string]string{link.LeaseTunnelReadyAnnotation: "false"})
				upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: holderName}, true, "node-a")
			},
			wantReady:        metav1.ConditionFalse,
			wantRequeueAfter: tunnelReadyPollInterval,
		},
		{
			name: "tunnel annotation true but holder pod not ready",
			arrange: func(t *testing.T, ns, holderName string) {
				upsertLeaseHolder(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link"}, holderName,
					map[string]string{link.LeaseTunnelReadyAnnotation: "true"})
				upsertPodReady(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: holderName}, false, "node-a")
			},
			wantReady: metav1.ConditionFalse,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("la-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

			gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			mustCreate(ctx, t, cl, gw)
			key := client.ObjectKeyFromObject(gw)

			gen, _ := countingKeyGen()
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

			// Provision the Gateway, then give the composite an address so the address
			// gate is satisfied and the Ready outcome turns solely on the active tunnel.
			drainReconcile(ctx, t, r, key)
			setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.30", "sa@example.iam.gserviceaccount.com", "")

			tt.arrange(t, ns, "gw-link-0")

			// Every tunnel-gate case is a non-error outcome, so a failure here means
			// linkStatusOf surfaced a NotFound as an error.
			res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
			if err != nil {
				t.Fatalf("reconcile after arranging tunnel state: %v", err)
			}
			if res.RequeueAfter != tt.wantRequeueAfter {
				t.Errorf("RequeueAfter = %v, want %v", res.RequeueAfter, tt.wantRequeueAfter)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if cond == nil {
				t.Fatalf("Ready condition absent")
			}
			if cond.Status != tt.wantReady {
				t.Errorf("Ready status = %s, want %s (reason %q, message %q)",
					cond.Status, tt.wantReady, cond.Reason, cond.Message)
			}
			if tt.wantReady == metav1.ConditionTrue && cond.Reason != reasonReady {
				t.Errorf("Ready reason = %q, want %q", cond.Reason, reasonReady)
			}
		})
	}
}

// startManager runs a manager on the envtest config with the GatewayReconciler registered, so
// the Service and Namespace watches are live. It is stopped via t.Cleanup.
func startManager(ctx context.Context, t *testing.T, te *testEnv) client.Client {
	t.Helper()

	mgr, err := ctrl.NewManager(te.operatorCfg, ctrl.Options{
		Scheme: te.scheme,
		// Disable the metrics listener so parallel managers in one test binary do
		// not contend for a port.
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Every manager registers a controller named "gateway"; skip the process-global
		// uniqueness check so more than one startManager test can run in one binary.
		Controller: config.Controller{SkipNameValidation: new(true)},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	gen, _ := countingKeyGen()
	r := &GatewayReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Config:      reconcileConfig(),
		GenerateKey: gen,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("setup reconciler with manager: %v", err)
	}

	mgrCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := mgr.Start(mgrCtx); err != nil {
			// A cancel-driven shutdown returns nil, so a non-nil error here is real and
			// worth surfacing without racing the test goroutine's t.Fatalf.
			t.Errorf("manager start: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	if !mgr.GetCache().WaitForCacheSync(mgrCtx) {
		t.Fatal("manager cache failed to sync")
	}
	return mgr.GetClient()
}

// pollUntil polls cond until true or timeout elapses, failing with msg. The manager-backed
// transition tests need a longer deadline than the package eventually helper.
func pollUntil(ctx context.Context, t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: context done: %v", msg, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %s", msg)
}

// transitionTimeout bounds each manager-backed transition wait, generous because it
// covers a watch event firing, a reconcile running, and the dependent status patches.
const transitionTimeout = 30 * time.Second

// waitForReconcileQuiescence waits until key's resourceVersion holds steady for several checks,
// evidence the self-triggering burst of reconciles a Gateway creation sets off has settled.
func waitForReconcileQuiescence(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) {
	t.Helper()
	const stableChecksNeeded = 5
	const checkInterval = 200 * time.Millisecond

	var lastRV string
	stableChecks := 0
	deadline := time.Now().Add(transitionTimeout)
	for time.Now().Before(deadline) {
		var gw wgnetv1alpha1.Gateway
		if err := cl.Get(ctx, key, &gw); err == nil {
			if gw.ResourceVersion == lastRV {
				stableChecks++
				if stableChecks >= stableChecksNeeded {
					return
				}
			} else {
				lastRV = gw.ResourceVersion
				stableChecks = 0
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for gateway %s reconcile quiescence: context done: %v", key, ctx.Err())
		case <-time.After(checkInterval):
		}
	}
	t.Fatalf("timed out waiting for gateway %s reconcile to settle", key)
}

// gatewayReadyReason fetches the Gateway at key with cl and returns its Ready
// condition status and reason, or empty strings if the condition is absent.
func gatewayReadyReason(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) (metav1.ConditionStatus, string) {
	t.Helper()
	var gw wgnetv1alpha1.Gateway
	if err := cl.Get(ctx, key, &gw); err != nil {
		t.Fatalf("get gateway %s: %v", key, err)
	}
	cond := apimeta.FindStatusCondition(gw.Status.Conditions, conditionReady)
	if cond == nil {
		return "", ""
	}
	return cond.Status, cond.Reason
}

// driveProvisionedReady supplies the readiness preconditions envtest cannot: it patches the
// composite address and makes the link lease hold a Ready pod so the watches flip Ready.
func driveProvisionedReady(ctx context.Context, t *testing.T, direct client.Client, key client.ObjectKey) {
	t.Helper()

	pollUntil(ctx, t, transitionTimeout, "composite created for "+key.String(), func() bool {
		return !apierrors.IsNotFound(direct.Get(ctx, key, newXGatewayGCP()))
	})

	depKey := client.ObjectKey{Namespace: key.Namespace, Name: key.Name + "-link"}
	pollUntil(ctx, t, transitionTimeout, "link deployment created for "+key.String(), func() bool {
		return !apierrors.IsNotFound(direct.Get(ctx, depKey, &appsv1.Deployment{}))
	})

	// The lease and pod are not watched, so writing the watched composite status last lets its
	// reconcile observe the address and the active tunnel together and flip Ready=True.
	setLinkLeaseActive(ctx, t, direct, key, key.Name+"-link-0", true, "node-a")
	setXGatewayGCPStatus(ctx, t, direct, key, "203.0.113.20", "sa@example.iam.gserviceaccount.com", "")
}

// TestForwardValidationTransitions runs a real manager so the Service and Namespace watches
// enqueue, then drives backend changes and asserts reconvergence without a manual reconcile.
func TestForwardValidationTransitions(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	direct := te.client
	startManager(ctx, t, te)

	t.Run("service created after gateway", func(t *testing.T) {
		const ns = "tr-svc-create"
		mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))

		gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		// No backend Service yet: the operator must not provision, and Ready=False
		// carries ServiceNotFound.
		pollUntil(ctx, t, transitionTimeout, "ServiceNotFound before backend exists", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonServiceNotFound
		})
		if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: bundleSecretName(gw)}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Fatalf("bundle Secret get = %v, want NotFound (no valid forward, not provisioned)", err)
		}

		// Creating the backend Service must trigger the Service watch, re-classify
		// the forward as valid, and provision it.
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
		pollUntil(ctx, t, transitionTimeout, "forward present after service created", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1 && rc.Forwards[0].Service == "web."+ns+".svc.cluster.local"
		})

		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True after backend created", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue && reason == reasonReady
		})
	})

	t.Run("service deleted removes only that forward", func(t *testing.T) {
		const ns = "tr-svc-delete"
		mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "api", 7443, corev1.ProtocolTCP))

		gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			{Port: 7443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "api"},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		// Both forwards valid: the link config carries both and the Gateway is Ready.
		pollUntil(ctx, t, transitionTimeout, "both forwards present", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 2
		})
		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True with both forwards", func() bool {
			status, _ := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue
		})

		// Deleting the "web" backend must drop only its forward; "api" stays, the
		// Gateway keeps its VM, and Ready=False carries the ServiceNotFound reason.
		if err := direct.Delete(ctx, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP)); err != nil {
			t.Fatalf("delete web service: %v", err)
		}
		pollUntil(ctx, t, transitionTimeout, "only api forward remains after web deleted", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1 && rc.Forwards[0].Service == "api."+ns+".svc.cluster.local"
		})
		pollUntil(ctx, t, transitionTimeout, "Ready=False/ServiceNotFound after web deleted", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonServiceNotFound
		})
		// The Gateway stays provisioned: deleting one backend does not tear the VM
		// down.
		if err := direct.Get(ctx, key, newXGatewayGCP()); err != nil {
			t.Fatalf("composite get after one backend deleted = %v, want still present", err)
		}
	})

	t.Run("consent label toggles cross-namespace forward", func(t *testing.T) {
		const gwNS = "tr-consent"
		target := gwNS + "-target"
		mustCreate(ctx, t, direct, namespaceWithLabels(gwNS, nil))
		mustCreate(ctx, t, direct, namespaceWithLabels(target, nil))
		mustCreate(ctx, t, direct, portedClusterIPService(target, "web", 443, corev1.ProtocolTCP))

		gw := newGateway("gw", gwNS, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", Namespace: target},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		// Unlabelled target: the cross-namespace forward is denied and, as the only
		// forward, the Gateway does not provision.
		pollUntil(ctx, t, transitionTimeout, "CrossNamespaceForwardDenied while unlabelled", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonCrossNamespaceForwardDenied
		})

		// Adding the consent label must trigger the Namespace watch and let the
		// forward through.
		setNamespaceLabel(ctx, t, direct, target, crossNamespaceIngressLabel, crossNamespaceIngressValue)
		pollUntil(ctx, t, transitionTimeout, "cross-ns forward present after label added", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: gwNS, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1 && rc.Forwards[0].Service == "web."+target+".svc.cluster.local"
		})
		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True after consent label added", func() bool {
			status, _ := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue
		})

		// Removing the label must re-deny the forward; the Gateway keeps its VM
		// (now provisioned) and reports Ready=False with the denial reason.
		removeNamespaceLabel(ctx, t, direct, target, crossNamespaceIngressLabel)
		pollUntil(ctx, t, transitionTimeout, "Ready=False/denied after label removed", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonCrossNamespaceForwardDenied
		})
		pollUntil(ctx, t, transitionTimeout, "no forwards after label removed", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: gwNS, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 0
		})
	})

	t.Run("target port appearing admits the forward", func(t *testing.T) {
		const ns = "tr-targetport"
		mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))
		// The Service exists but publishes the wrong port, so the forward's target
		// port (443) is not listening.
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 80, corev1.ProtocolTCP))

		gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		pollUntil(ctx, t, transitionTimeout, "TargetPortNotListening before port published", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonTargetPortNotListening
		})
		if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: bundleSecretName(gw)}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Fatalf("bundle Secret get = %v, want NotFound (target port not listening, not provisioned)", err)
		}

		// Publishing port 443 on the Service must trigger the Service watch and admit
		// the forward.
		addServicePort(ctx, t, direct, ns, "web", 443, corev1.ProtocolTCP)
		pollUntil(ctx, t, transitionTimeout, "forward present after target port published", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1
		})
		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True after target port published", func() bool {
			status, _ := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue
		})
	})

	t.Run("target port disappearing revokes the forward", func(t *testing.T) {
		const ns = "tr-targetport-revoke"
		mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))
		// The Service publishes an unrelated port too, so removing 443 leaves it present:
		// the revocation reason must be TargetPortNotListening, not ServiceNotFound.
		mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))
		addServicePort(ctx, t, direct, ns, "web", 9000, corev1.ProtocolTCP)

		gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
		}, nil)
		mustCreate(ctx, t, direct, gw)
		key := client.ObjectKeyFromObject(gw)

		// Target port published: the forward is valid, provisions, and reaches Ready.
		pollUntil(ctx, t, transitionTimeout, "forward present while target port published", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 1
		})
		driveProvisionedReady(ctx, t, direct, key)
		pollUntil(ctx, t, transitionTimeout, "Ready=True with target port published", func() bool {
			status, _ := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionTrue
		})

		// Removing the target port must trigger the Service watch and revoke the forward:
		// Ready=False/TargetPortNotListening, the link config empties, the Gateway keeps its VM.
		removeServicePort(ctx, t, direct, ns, "web", 443, corev1.ProtocolTCP)
		pollUntil(ctx, t, transitionTimeout, "Ready=False/TargetPortNotListening after target port removed", func() bool {
			status, reason := gatewayReadyReason(ctx, t, direct, key)
			return status == metav1.ConditionFalse && reason == reasonTargetPortNotListening
		})
		pollUntil(ctx, t, transitionTimeout, "no forwards after target port removed", func() bool {
			var cm corev1.ConfigMap
			if err := direct.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm); err != nil {
				return false
			}
			var rc link.RuntimeConfig
			if err := jsonUnmarshalString(cm.Data[linkConfigKey], &rc); err != nil {
				return false
			}
			return len(rc.Forwards) == 0
		})
		if err := direct.Get(ctx, key, newXGatewayGCP()); err != nil {
			t.Fatalf("composite get after target port removed = %v, want still present", err)
		}
	})
}

// TestResponderServiceWatchCorrectsDrift pins that an out-of-band Service edit self-heals via
// the Owns watch alone (RequeueInterval is zero here): apiserver never bumps a Service generation.
func TestResponderServiceWatchCorrectsDrift(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	direct := te.client
	startManager(ctx, t, te)

	const ns = "responder-service-drift"
	mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

	gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
	}, nil)
	mustCreate(ctx, t, direct, gw)
	key := client.ObjectKeyFromObject(gw)

	// Wait for the post-finalizer requeue and its self-triggered cascade to run their course
	// before mutating, so the only reconcile left that can correct the drift is the Service watch.
	waitForReconcileQuiescence(ctx, t, direct, key)

	svcKey := client.ObjectKey{Namespace: ns, Name: "gw-responder"}
	var svc corev1.Service
	pollUntil(ctx, t, transitionTimeout, "responder service created for "+key.String(), func() bool {
		return direct.Get(ctx, svcKey, &svc) == nil && svc.Labels["app.kubernetes.io/component"] != ""
	})

	svc.Labels["app.kubernetes.io/component"] = "drifted"
	if err := direct.Update(ctx, &svc); err != nil {
		t.Fatalf("drift responder service label: %v", err)
	}
	// Confirm the write actually landed on the server before polling for its correction:
	// otherwise a stale first poll read could observe the pre-drift value and pass by luck.
	var confirmed corev1.Service
	pollUntil(ctx, t, transitionTimeout, "drift observed on the server before polling for its correction", func() bool {
		return direct.Get(ctx, svcKey, &confirmed) == nil && confirmed.Labels["app.kubernetes.io/component"] == "drifted"
	})

	pollUntil(ctx, t, transitionTimeout, "responder service label restored after drift", func() bool {
		var got corev1.Service
		if err := direct.Get(ctx, svcKey, &got); err != nil {
			return false
		}
		return got.Labels["app.kubernetes.io/component"] == componentResponder
	})
}

// TestLinkWorkloadStatusEventTriggersReconcile pins that a Local Gateway's link DaemonSet status
// update alone drives status.link.activeNode, since link pods carry no watch of their own.
func TestLinkWorkloadStatusEventTriggersReconcile(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	direct := te.client
	startManager(ctx, t, te)

	const ns = "link-workload-status-event"
	mustCreate(ctx, t, direct, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, direct, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

	gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
	}, nil)
	gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	mustCreate(ctx, t, direct, gw)
	key := client.ObjectKeyFromObject(gw)

	workloadKey := client.ObjectKey{Namespace: ns, Name: linkComponentName(gw)}
	var ds appsv1.DaemonSet
	pollUntil(ctx, t, transitionTimeout, "link daemonset created for "+key.String(), func() bool {
		return direct.Get(ctx, workloadKey, &ds) == nil
	})

	// Wait for the post-finalizer requeue's cascade to settle before creating the holder pod,
	// so the DaemonSet status update below is the only trigger left to see it become ready.
	waitForReconcileQuiescence(ctx, t, direct, key)

	podName := linkComponentName(gw) + "-0"
	createLinkPod(ctx, t, direct, gw, podName, "node-a")
	var pod corev1.Pod
	mustGet(ctx, t, direct, client.ObjectKey{Namespace: ns, Name: podName}, &pod)
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := direct.Status().Update(ctx, &pod); err != nil {
		t.Fatalf("mark link pod ready: %v", err)
	}
	upsertLeaseHolder(ctx, t, direct, workloadKey, podName, nil)

	mustGet(ctx, t, direct, workloadKey, &ds)
	ds.Status.DesiredNumberScheduled = 1
	ds.Status.NumberReady = 1
	if err := direct.Status().Update(ctx, &ds); err != nil {
		t.Fatalf("update link daemonset status: %v", err)
	}

	eventually(ctx, t, "status.link.activeNode reflects the ready holder pod", func() bool {
		var got wgnetv1alpha1.Gateway
		if err := direct.Get(ctx, key, &got); err != nil {
			return false
		}
		return got.Status.Link.ActiveNode == "node-a"
	})
}

// jsonUnmarshalString unmarshals raw into v, returning the error so a poll predicate can treat
// a not-yet-written ConfigMap as "keep waiting" rather than failing the test.
func jsonUnmarshalString(raw string, v any) error {
	return json.Unmarshal([]byte(raw), v)
}

// setNamespaceLabel sets label=value on the named namespace via a read-modify-
// write with the direct client, so the operator's Namespace watch fires.
func setNamespaceLabel(ctx context.Context, t *testing.T, cl client.Client, name, label, value string) {
	t.Helper()
	var ns corev1.Namespace
	mustGet(ctx, t, cl, client.ObjectKey{Name: name}, &ns)
	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	ns.Labels[label] = value
	if err := cl.Update(ctx, &ns); err != nil {
		t.Fatalf("set namespace %s label %s: %v", name, label, err)
	}
}

// removeNamespaceLabel deletes label from the named namespace via a read-modify-
// write with the direct client, so the operator's Namespace watch fires.
func removeNamespaceLabel(ctx context.Context, t *testing.T, cl client.Client, name, label string) {
	t.Helper()
	var ns corev1.Namespace
	mustGet(ctx, t, cl, client.ObjectKey{Name: name}, &ns)
	delete(ns.Labels, label)
	if err := cl.Update(ctx, &ns); err != nil {
		t.Fatalf("remove namespace %s label %s: %v", name, label, err)
	}
}

// addServicePort appends a published port/proto to the named Service, so the Service watch
// fires. It names every port first: a multi-port Service requires named ports.
func addServicePort(ctx context.Context, t *testing.T, cl client.Client, ns, name string, port int32, proto corev1.Protocol) {
	t.Helper()
	var svc corev1.Service
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: name}, &svc)
	svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: port, Protocol: proto})
	for i := range svc.Spec.Ports {
		svc.Spec.Ports[i].Name = fmt.Sprintf("p%d", svc.Spec.Ports[i].Port)
	}
	if err := cl.Update(ctx, &svc); err != nil {
		t.Fatalf("add port %d to service %s/%s: %v", port, ns, name, err)
	}
}

// removeServicePort drops the matching port from the named Service, so the Service watch fires.
// It renames the survivors to keep the named-port invariant, and fails if no port matched.
func removeServicePort(ctx context.Context, t *testing.T, cl client.Client, ns, name string, port int32, proto corev1.Protocol) {
	t.Helper()
	var svc corev1.Service
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: name}, &svc)
	kept := make([]corev1.ServicePort, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		if p.Port == port && p.Protocol == proto {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == len(svc.Spec.Ports) {
		t.Fatalf("remove port %d/%s from service %s/%s: no matching port", port, proto, ns, name)
	}
	for i := range kept {
		kept[i].Name = fmt.Sprintf("p%d", kept[i].Port)
	}
	svc.Spec.Ports = kept
	if err := cl.Update(ctx, &svc); err != nil {
		t.Fatalf("remove port %d from service %s/%s: %v", port, ns, name, err)
	}
}

// TestGatewayTrafficPolicyDefaulting verifies spec.trafficPolicy is optional and reads back as
// Cluster, so an object created before the field existed keeps its data path.
func TestGatewayTrafficPolicyDefaulting(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	const ns = "tp-default"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

	gw := newGatewayNoWireguard(ns, ns, nil)
	if err := cl.Create(ctx, gw); err != nil {
		t.Fatalf("create Gateway with omitted spec.trafficPolicy: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: ns}, &got)
	if got.Spec.TrafficPolicy != wgnetv1alpha1.TrafficPolicyCluster {
		t.Errorf("defaulted spec.trafficPolicy = %q, want %q", got.Spec.TrafficPolicy, wgnetv1alpha1.TrafficPolicyCluster)
	}
}

// TestGatewayTrafficPolicyImmutable pins the transition rule: the VM's ruleset is baked at boot,
// so a live mode change is rejected at admission in either direction.
func TestGatewayTrafficPolicyImmutable(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)
	cl := te.client

	tests := []struct {
		name string
		// omitOnCreate builds the Gateway through the unstructured path with no
		// trafficPolicy at all, so the update runs against the CRD-defaulted value.
		omitOnCreate bool
		create       wgnetv1alpha1.TrafficPolicy
		update       wgnetv1alpha1.TrafficPolicy
	}{
		{name: "local to cluster rejected", create: wgnetv1alpha1.TrafficPolicyLocal, update: wgnetv1alpha1.TrafficPolicyCluster},
		{name: "cluster to local rejected", create: wgnetv1alpha1.TrafficPolicyCluster, update: wgnetv1alpha1.TrafficPolicyLocal},
		{name: "defaulted cluster to local rejected", omitOnCreate: true, update: wgnetv1alpha1.TrafficPolicyLocal},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("tp-imm-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))

			if tt.omitOnCreate {
				mustCreate(ctx, t, cl, newGatewayNoWireguard(ns, ns, nil))
			} else {
				gw := newGateway(ns, ns, nil, nil)
				gw.Spec.TrafficPolicy = tt.create
				mustCreate(ctx, t, cl, gw)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: ns}, &got)
			if tt.omitOnCreate && got.Spec.TrafficPolicy != wgnetv1alpha1.TrafficPolicyCluster {
				t.Fatalf("defaulted spec.trafficPolicy = %q, want Cluster", got.Spec.TrafficPolicy)
			}

			got.Spec.TrafficPolicy = tt.update
			assertAdmission(ctx, t, cl, &got, cl.Update(ctx, &got), false, "spec.trafficPolicy is immutable")
		})
	}
}

// localGatewayFixture creates a namespace, a backend Service and a Local Gateway in it,
// returning a reconciler authorized as the operator and the Gateway's key.
func localGatewayFixture(ctx context.Context, t *testing.T, te *testEnv, ns string) (*GatewayReconciler, client.ObjectKey) {
	t.Helper()
	return linkGatewayFixture(ctx, t, te, ns, wgnetv1alpha1.TrafficPolicyLocal)
}

// linkGatewayFixture creates ns, the backend Service its single forward targets, and a Gateway
// on the given traffic policy, returning a reconciler wired to the operator identity.
func linkGatewayFixture(ctx context.Context, t *testing.T, te *testEnv, ns string, policy wgnetv1alpha1.TrafficPolicy) (*GatewayReconciler, client.ObjectKey) {
	t.Helper()
	cl := te.client
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

	gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
	}, nil)
	gw.Spec.TrafficPolicy = policy
	mustCreate(ctx, t, cl, gw)

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
	return r, client.ObjectKeyFromObject(gw)
}

// createLinkPod creates a Running pod carrying gw's link selector labels and nodeName, standing
// in for a Local Gateway's DaemonSet pod, which envtest's absent kubelet never schedules.
func createLinkPod(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway, name, nodeName string) {
	t.Helper()
	createLinkPodWithPhase(ctx, t, cl, gw, name, nodeName, corev1.PodRunning)
}

// createLinkPodWithPhase is createLinkPod with an explicit phase, letting a test create a link
// pod responderMissingNodes' phase filter must skip.
func createLinkPodWithPhase(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway, name, nodeName string, phase corev1.PodPhase) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: name, Labels: linkSelectorLabels(gw)},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{{Name: "link", Image: "registry.example.com/gateway-link:test"}},
		},
	}
	if err := cl.Create(ctx, pod); err != nil {
		t.Fatalf("create link pod %s/%s: %v", gw.Namespace, name, err)
	}
	pod.Status.Phase = phase
	if err := cl.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update link pod %s/%s status: %v", gw.Namespace, name, err)
	}
}

// createResponderPod creates a Running, Ready responder pod with a pod IP, in namespace, on
// nodeName, carrying labels (typically responderSelectorLabels(gw)).
func createResponderPod(ctx context.Context, t *testing.T, cl client.Client, namespace, name, nodeName, podIP string, labels map[string]string) {
	t.Helper()
	createResponderPodWithReady(ctx, t, cl, namespace, name, nodeName, podIP, labels, true)
}

// createResponderPodWithReady is createResponderPod with an explicit PodReady status, letting a
// test create a Running-but-not-Ready responder pod.
func createResponderPodWithReady(ctx context.Context, t *testing.T, cl client.Client, namespace, name, nodeName, podIP string, labels map[string]string, ready bool) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{{Name: "responder", Image: "registry.example.com/responder:test"}},
		},
	}
	if err := cl.Create(ctx, pod); err != nil {
		t.Fatalf("create responder pod %s/%s: %v", namespace, name, err)
	}
	readyStatus := corev1.ConditionFalse
	if ready {
		readyStatus = corev1.ConditionTrue
	}
	pod.Status.Phase = corev1.PodRunning
	pod.Status.PodIP = podIP
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: readyStatus}}
	if err := cl.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update responder pod %s/%s status: %v", namespace, name, err)
	}
}

// TestLinkReadyReasonPrecedence pins the Ready-reason ordering: an invalid forward over a link
// fault over Ready and Provisioning, with an unrecognised fault value ignored, never copied.
func TestLinkReadyReasonPrecedence(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name string
		// breakForward deletes the backend Service so classification rejects the only
		// forward, which must outrank any published fault.
		breakForward bool
		// holderReady drives the Lease holder pod's readiness gate.
		holderReady bool
		faultReason string
		// compositeMessage is the composite's status.message, which only the Provisioning
		// arm folds in; a fault or an invalid forward must win the arm and drop it.
		compositeMessage string
		wantStatus       metav1.ConditionStatus
		wantReason       string
		// wantMessage, when non-nil, asserts the whole Ready message for a row's namespace.
		wantMessage func(ns string) string
	}{
		{
			name:             "no fault and a ready holder is Ready",
			holderReady:      true,
			compositeMessage: "address: cannot find address prod-edge",
			wantStatus:       metav1.ConditionTrue,
			wantReason:       reasonReady,
			wantMessage: func(string) string {
				return "gateway address provisioned and active link tunnel up"
			},
		},
		{
			name:        "fault outranks Ready",
			holderReady: true,
			faultReason: link.FaultRPFilterStrict,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  link.FaultRPFilterStrict,
		},
		{
			name:        "fault outranks Provisioning",
			holderReady: false,
			faultReason: link.FaultNoLocalEndpoint,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  link.FaultNoLocalEndpoint,
		},
		{
			name:         "invalid forward outranks a fault",
			breakForward: true,
			holderReady:  true,
			faultReason:  link.FaultApplyFailed,
			wantStatus:   metav1.ConditionFalse,
			wantReason:   reasonServiceNotFound,
		},
		{
			name:             "fault outranks a composite message",
			holderReady:      true,
			faultReason:      link.FaultNoLocalEndpoint,
			compositeMessage: "instance: quota exceeded",
			wantStatus:       metav1.ConditionFalse,
			wantReason:       link.FaultNoLocalEndpoint,
			wantMessage: func(string) string {
				return "link on node-a reported " + link.FaultNoLocalEndpoint
			},
		},
		{
			name:             "invalid forward outranks a composite message",
			breakForward:     true,
			holderReady:      true,
			faultReason:      link.FaultApplyFailed,
			compositeMessage: "instance: quota exceeded",
			wantStatus:       metav1.ConditionFalse,
			wantReason:       reasonServiceNotFound,
			wantMessage: func(ns string) string {
				return fmt.Sprintf("1 forward(s) invalid: forward backend Service %q in namespace %q not found yet", "web", ns)
			},
		},
		{
			name:        "unrecognised fault value is ignored",
			holderReady: true,
			faultReason: "SomethingElse",
			wantStatus:  metav1.ConditionTrue,
			wantReason:  reasonReady,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("fault-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			svc := portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP)
			mustCreate(ctx, t, cl, svc)

			gw := newGateway("gw", ns, []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			mustCreate(ctx, t, cl, gw)
			key := client.ObjectKeyFromObject(gw)

			gen, _ := countingKeyGen()
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

			drainReconcile(ctx, t, r, key)
			setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.40", "sa@example.iam.gserviceaccount.com", tt.compositeMessage)
			setLinkLeaseActive(ctx, t, cl, key, "gw-link-0", tt.holderReady, "node-a")
			setLinkLeaseFault(ctx, t, cl, key, tt.faultReason, "link on node-a reported "+tt.faultReason)

			if tt.breakForward {
				if err := cl.Delete(ctx, svc); err != nil {
					t.Fatalf("delete backend service: %v", err)
				}
			}

			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if cond == nil {
				t.Fatal("Ready condition absent")
			}
			if cond.Status != tt.wantStatus || cond.Reason != tt.wantReason {
				t.Fatalf("Ready = %s/%s, want %s/%s (message %q)",
					cond.Status, cond.Reason, tt.wantStatus, tt.wantReason, cond.Message)
			}
			if tt.wantMessage != nil {
				if want := tt.wantMessage(ns); cond.Message != want {
					t.Errorf("Ready message = %q, want %q", cond.Message, want)
				}
			}

			if tt.wantReason != link.FaultRPFilterStrict {
				return
			}
			// Clearing the annotation is how the holder signals it finished programming;
			// the Gateway must return to Ready without any other input changing.
			setLinkLeaseFault(ctx, t, cl, key, "", "")
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatalf("reconcile after clearing the fault: %v", err)
			}
			mustGet(ctx, t, cl, key, &got)
			cond = apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
			if cond.Status != metav1.ConditionTrue || cond.Reason != reasonReady {
				t.Errorf("Ready after clearing the fault = %s/%s, want True/%s", cond.Status, cond.Reason, reasonReady)
			}
		})
	}
}

// TestLinkStatusHeldThroughAllForwardsInvalid pins that the all-invalid early return leaves
// status.link.activeNode alone: the link still holds its Lease and serves the last config.
func TestLinkStatusHeldThroughAllForwardsInvalid(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	mustCreate(ctx, t, cl, namespaceWithLabels("held-link", nil))

	gw := newGateway("gw", "held-link", []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "absent"},
	}, nil)
	mustCreate(ctx, t, cl, gw)
	key := client.ObjectKeyFromObject(gw)

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

	drainReconcile(ctx, t, r, key)
	setLinkLeaseActive(ctx, t, cl, key, "gw-link-0", true, "node-a")

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile with every forward invalid: %v", err)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ActiveNode != "node-a" {
		t.Errorf("status.link.activeNode = %q, want node-a: the holder still serves", got.Status.Link.ActiveNode)
	}
	if c := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady); c == nil || c.Reason != reasonServiceNotFound {
		t.Errorf("Ready condition = %+v, want False/%s", c, reasonServiceNotFound)
	}
}

// TestTruncateFaultMessage pins the condition-message budget: an oversized fault message is cut
// to a length the API accepts, on a rune boundary, and marked truncated.
func TestTruncateFaultMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want func(t *testing.T, got string)
	}{
		{
			name: "short message is unchanged",
			msg:  "rp_filter is strict on node-a",
			want: func(t *testing.T, got string) {
				t.Helper()
				if got != "rp_filter is strict on node-a" {
					t.Errorf("message = %q, want it unchanged", got)
				}
			},
		},
		{
			name: "empty message is unchanged",
			msg:  "",
			want: func(t *testing.T, got string) {
				t.Helper()
				if got != "" {
					t.Errorf("message = %q, want empty", got)
				}
			},
		},
		{
			name: "message at the budget is unchanged",
			msg:  strings.Repeat("a", maxFaultMessageBytes),
			want: func(t *testing.T, got string) {
				t.Helper()
				if len(got) != maxFaultMessageBytes {
					t.Errorf("length = %d, want %d", len(got), maxFaultMessageBytes)
				}
				if strings.HasSuffix(got, faultMessageTruncationMarker) {
					t.Error("message at the budget was marked truncated")
				}
			},
		},
		{
			name: "oversized message is cut and marked",
			msg:  strings.Repeat("b", 40000),
			want: func(t *testing.T, got string) {
				t.Helper()
				if len(got) != maxFaultMessageBytes {
					t.Errorf("length = %d, want %d", len(got), maxFaultMessageBytes)
				}
				if !strings.HasSuffix(got, faultMessageTruncationMarker) {
					t.Errorf("message = %q, want the truncation marker", got[len(got)-40:])
				}
			},
		},
		{
			name: "invalid byte before the cut does not shrink it",
			msg:  "\xff" + strings.Repeat("c", 40000),
			want: func(t *testing.T, got string) {
				t.Helper()
				if len(got) != maxFaultMessageBytes {
					t.Errorf("length = %d, want %d", len(got), maxFaultMessageBytes)
				}
				if !strings.HasSuffix(got, faultMessageTruncationMarker) {
					t.Error("oversized message was not marked truncated")
				}
			},
		},
		{
			name: "multibyte message stays valid UTF-8",
			msg:  strings.Repeat("é", 40000),
			want: func(t *testing.T, got string) {
				t.Helper()
				if !utf8.ValidString(got) {
					t.Error("truncated message is not valid UTF-8")
				}
				if len(got) > maxFaultMessageBytes {
					t.Errorf("length = %d, want at most %d", len(got), maxFaultMessageBytes)
				}
				if !strings.HasSuffix(got, faultMessageTruncationMarker) {
					t.Error("oversized multibyte message was not marked truncated")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, truncateFaultMessage(tt.msg))
		})
	}
}

// linkTeardownTimeout bounds each teardown wait: several reconciles, each doing a
// handful of API round trips.
const linkTeardownTimeout = 30 * time.Second

// TestReleaseFinalizerReapsLinkLease asserts the delete path holds the finalizer until the link
// pods are gone, then reaps the Lease nothing owner-refs and a live elector would re-create.
func TestReleaseFinalizerReapsLinkLease(t *testing.T) {
	tests := []struct {
		name     string
		policy   wgnetv1alpha1.TrafficPolicy
		workload func() client.Object
		// stuck deletes the hand-made pod up front and leaves a finalizer on it, so it
		// stays Terminating the way a pod on a partitioned node does.
		stuck bool
	}{
		{
			name:     "cluster mode deletes the link deployment",
			policy:   wgnetv1alpha1.TrafficPolicyCluster,
			workload: func() client.Object { return &appsv1.Deployment{} },
		},
		{
			name:     "local mode deletes the link daemonset",
			policy:   wgnetv1alpha1.TrafficPolicyLocal,
			workload: func() client.Object { return &appsv1.DaemonSet{} },
		},
		{
			name:     "pod stuck terminating past its grace period stops holding the delete",
			policy:   wgnetv1alpha1.TrafficPolicyCluster,
			workload: func() client.Object { return &appsv1.Deployment{} },
			stuck:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			te := setupEnvtestRBAC(t)
			cl := te.client

			r, key := linkGatewayFixture(ctx, t, te, "lease-reap", tc.policy)
			drainReconcile(ctx, t, r, key)

			var gw wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &gw)
			linkKey := client.ObjectKey{Namespace: key.Namespace, Name: linkComponentName(&gw)}
			if err := cl.Get(ctx, linkKey, tc.workload()); err != nil {
				t.Fatalf("get link workload %s before delete: %v", linkKey, err)
			}

			podKey := client.ObjectKey{Namespace: key.Namespace, Name: linkComponentName(&gw) + "-0"}
			pod := linkElectorPod(&gw, podKey.Name)
			if tc.stuck {
				pod.Finalizers = []string{stuckPodFinalizer}
				pod.Spec.TerminationGracePeriodSeconds = new(int64(1))
			}
			mustCreate(ctx, t, cl, pod)
			mustCreate(ctx, t, cl, &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Namespace: linkKey.Namespace, Name: linkKey.Name},
				Spec:       coordinationv1.LeaseSpec{HolderIdentity: new(podKey.Name)},
			})

			if tc.stuck {
				withLinkTeardownSlack(t, time.Second)
				if err := cl.Delete(ctx, pod); err != nil {
					t.Fatalf("delete link holder pod %s: %v", podKey, err)
				}
				t.Cleanup(func() { removePodFinalizer(context.Background(), t, cl, podKey) })
			}

			mustDeleteGateway(ctx, t, cl, key)

			if tc.stuck {
				pollUntil(ctx, t, linkTeardownTimeout, "gateway purged past the stuck pod", func() bool {
					if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
						t.Fatalf("reconcile delete past stuck pod: %v", err)
					}
					return apierrors.IsNotFound(cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}))
				})
				if err := cl.Get(ctx, linkKey, &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
					t.Errorf("get link lease after purge past stuck pod = %v, want NotFound", err)
				}
				return
			}

			pollUntil(ctx, t, linkTeardownTimeout, "link workload deleted while the holder pod lives", func() bool {
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
					t.Fatalf("reconcile delete: %v", err)
				}
				return apierrors.IsNotFound(cl.Get(ctx, linkKey, tc.workload()))
			})

			// The elector pod still runs, so the finalizer must hold and the Lease
			// must survive: deleting it now would let the elector re-create it.
			if err := cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}); err != nil {
				t.Fatalf("get gateway while holder pod lives = %v, want still present", err)
			}
			if err := cl.Get(ctx, linkKey, &coordinationv1.Lease{}); err != nil {
				t.Fatalf("get link lease while holder pod lives = %v, want still present", err)
			}

			var waiting wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &waiting)
			cond := apimeta.FindStatusCondition(waiting.Status.Conditions, conditionReady)
			switch {
			case cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonTerminating:
				t.Errorf("Ready condition while waiting on link pods = %+v, want False/%s", cond, reasonTerminating)
			case cond.Message != "waiting for link pods to exit: "+podKey.Name:
				t.Errorf("Ready message while waiting on link pods = %q, want %q",
					cond.Message, "waiting for link pods to exit: "+podKey.Name)
			}

			if err := cl.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: podKey.Namespace, Name: podKey.Name}}); err != nil {
				t.Fatalf("delete link holder pod %s: %v", podKey, err)
			}

			pollUntil(ctx, t, linkTeardownTimeout, "gateway purged once the holder pod is gone", func() bool {
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
					t.Fatalf("reconcile delete after pod removal: %v", err)
				}
				return apierrors.IsNotFound(cl.Get(ctx, key, &wgnetv1alpha1.Gateway{}))
			})

			if err := cl.Get(ctx, linkKey, &coordinationv1.Lease{}); !apierrors.IsNotFound(err) {
				t.Errorf("get link lease after gateway purge = %v, want NotFound", err)
			}
		})
	}
}

// linkElectorPod builds a minimal pod carrying the link selector labels, standing in
// for a running elector: envtest has no workload controller to create one.
func linkElectorPod(gw *wgnetv1alpha1.Gateway, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gw.Namespace,
			Name:      name,
			Labels:    linkSelectorLabels(gw),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "link", Image: "registry.example.com/gateway-link:test"}},
		},
	}
}

// TestDropWarnSuppression covers the deletion-time clearing: every suppression entry the deleted
// Gateway owns goes, including the tunnel-address one, and another Gateway's entry stays.
func TestDropWarnSuppression(t *testing.T) {
	gw := &wgnetv1alpha1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "gw", UID: "uid-1"}}
	other := &wgnetv1alpha1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "other", UID: "uid-2"}}
	otherKey := invalidTunnelWarnKeyPrefix + unresolvedWarnKey(other)
	allWarned := func(gws ...*wgnetv1alpha1.Gateway) map[string]string {
		seeded := map[string]string{}
		for _, g := range gws {
			for _, k := range allWarnSuppressionKeys(g) {
				seeded[k] = "warned"
			}
		}
		return seeded
	}

	tests := []struct {
		name string
		seed map[string]string
		want map[string]string
	}{
		{
			name: "every key of the deleted gateway",
			seed: map[string]string{
				unresolvedWarnKey(gw):                               "backends",
				blockedCleanupWarnKeyPrefix + unresolvedWarnKey(gw): "cleanup",
				invalidTunnelWarnKeyPrefix + unresolvedWarnKey(gw):  "tunnel",
				otherKey: "tunnel",
			},
			want: map[string]string{otherKey: "tunnel"},
		},
		{
			name: "over-capacity gateway beside a co-resident one",
			seed: allWarned(gw, other),
			want: allWarned(other),
		},
		{
			name: "nothing suppressed",
			seed: map[string]string{},
			want: map[string]string{},
		},
		{
			name: "only another gateway suppressed",
			seed: map[string]string{otherKey: "tunnel"},
			want: map[string]string{otherKey: "tunnel"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GatewayReconciler{}
			for k, v := range tt.seed {
				r.unresolvedWarned.Store(k, v)
			}

			r.dropWarnSuppression(gw)

			got := map[string]string{}
			r.unresolvedWarned.Range(func(k, v any) bool {
				key, ok := k.(string)
				if !ok {
					t.Fatalf("suppression key %#v is not a string", k)
				}
				value, ok := v.(string)
				if !ok {
					t.Fatalf("suppression entry %q holds %#v, want a string", key, v)
				}
				got[key] = value
				return true
			})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("suppression entries = %v, want exactly %v", got, tt.want)
			}
		})
	}
}

// allWarnSuppressionKeys lists every suppression entry one Gateway can own.
func allWarnSuppressionKeys(gw *wgnetv1alpha1.Gateway) []string {
	key := unresolvedWarnKey(gw)
	return []string{
		key,
		blockedCleanupWarnKeyPrefix + key,
		invalidTunnelWarnKeyPrefix + key,
		capacityWarnKeyPrefix + key,
	}
}

// stuckPodFinalizer keeps a hand-made link pod in Terminating, standing in for a pod on
// a node the kubelet no longer reports from.
const stuckPodFinalizer = "wgnet.dev/test-hold-pod"

// withLinkTeardownSlack shortens the teardown slack for one test and restores it after,
// so a row can reach the stuck-pod branch without waiting out the production padding.
func withLinkTeardownSlack(t *testing.T, slack time.Duration) {
	t.Helper()
	previous := linkTeardownSlack
	linkTeardownSlack = slack
	t.Cleanup(func() { linkTeardownSlack = previous })
}

// removePodFinalizer clears the test finalizer so the pod can be collected, tolerating a
// pod already gone.
func removePodFinalizer(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) {
	t.Helper()
	var pod corev1.Pod
	if err := cl.Get(ctx, key, &pod); err != nil {
		if !apierrors.IsNotFound(err) {
			t.Errorf("get pod %s for finalizer removal: %v", key, err)
		}
		return
	}
	pod.Finalizers = nil
	if err := cl.Update(ctx, &pod); err != nil && !apierrors.IsNotFound(err) {
		t.Errorf("remove finalizer from pod %s: %v", key, err)
	}
}

// testConfig is the operator-level config the builder tests fold into Gateways.
func testConfig() Config {
	return Config{
		LinkImage:           "registry.example.com/gateway-link:test",
		LinkImagePullPolicy: "IfNotPresent",
		UserData:            "#ignition\n",
		EnableOSLogin:       true,
		RequeueInterval:     0,
		SharedNetworkName:   "wgnet-test",
		ProviderConfigName:  "test-provider-config",
		PodNamespace:        "gateway-operator",
		ResponderImage:      "registry.example.com/gateway-responder:test",
	}
}

// testGatewayUID is a stable UID for builder assertions.
const testGatewayUID = types.UID("11112222-3333-4444-5555-666677778888")

func newGateway(name, namespace string, forwards []wgnetv1alpha1.Forward, hostnames []string) *wgnetv1alpha1.Gateway {
	return &wgnetv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: testGatewayUID},
		Spec: wgnetv1alpha1.GatewaySpec{
			GCP: wgnetv1alpha1.GatewayGCPSpec{
				ProjectID:   "test-project",
				Region:      "us-central1",
				Zone:        "us-central1-a",
				MachineType: "e2-small",
			},
			Forwards:     forwards,
			DNSHostnames: hostnames,
		},
	}
}

func assertNestedString(t *testing.T, u *unstructured.Unstructured, want string, path ...string) {
	t.Helper()
	got, found, err := unstructured.NestedString(u.Object, path...)
	if err != nil {
		t.Fatalf("read %v: %v", path, err)
	}
	if !found {
		t.Fatalf("%v not found, want %q", path, want)
	}
	if got != want {
		t.Errorf("%v = %q, want %q", path, got, want)
	}
}

func decodeJSON(t *testing.T, raw string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		t.Fatalf("unmarshal %q: %v", raw, err)
	}
}

// TestHashedNamesArePinned fixes the exact bytes both hashedName callers produce, so a
// prefix, digest, encoding or truncation change cannot silently rename live objects.
func TestHashedNamesArePinned(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"gcp id", gcpID("default", "gw1"), "gw-aggomndtxrzb5qrg4d7sunz5muq"},
		{
			"clusterrolebinding",
			linkClusterRoleBindingName(newGateway("edge", "wg-system", nil, nil)),
			"gateway-link-cnvcej5geqr66udgtvezbh73rsj",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("name = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

// hasOpenEgressPort matches the 0.0.0.0/0 peer the link's forward and WireGuard rules use,
// so the policy holds whether the CNI matches on ClusterIP or on pod IP.
func hasOpenEgressPort(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol, port int32) bool {
	for _, r := range rules {
		open := false
		for _, peer := range r.To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR == "0.0.0.0/0" {
				open = true
				break
			}
		}
		if !open {
			continue
		}
		for _, p := range r.Ports {
			if p.Protocol != nil && *p.Protocol == proto && p.Port != nil && p.Port.IntVal == port {
				return true
			}
		}
	}
	return false
}

// hasProtocolOnlyEgress reports whether any egress rule permits the whole of proto to a
// 0.0.0.0/0 peer, the port-less shape an unresolved (named) backend port renders.
func hasProtocolOnlyEgress(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol) bool {
	for _, r := range rules {
		open := false
		for _, peer := range r.To {
			if peer.IPBlock != nil && peer.IPBlock.CIDR == "0.0.0.0/0" {
				open = true
				break
			}
		}
		if !open {
			continue
		}
		for _, p := range r.Ports {
			if p.Protocol != nil && *p.Protocol == proto && p.Port == nil {
				return true
			}
		}
	}
	return false
}
