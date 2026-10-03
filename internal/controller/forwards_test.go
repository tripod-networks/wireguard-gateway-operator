package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// TestEffectiveForwardNamespace pins the namespace-defaulting rule the FQDN builder and the
// cross-namespace gate both depend on.
func TestEffectiveForwardNamespace(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	tests := []struct {
		name    string
		forward wgnetv1alpha1.Forward
		want    string
	}{
		{"unset defaults to gateway namespace", wgnetv1alpha1.Forward{Service: "web"}, "wg-system"},
		{"explicit namespace honored", wgnetv1alpha1.Forward{Service: "web", Namespace: "prod"}, "prod"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveForwardNamespace(tt.forward, gw); got != tt.want {
				t.Errorf("effectiveForwardNamespace = %q, want %q", got, tt.want)
			}
		})
	}
}

// portedNodePortService builds a NodePort Service publishing port/proto; like ClusterIP it
// carries a real ClusterIP, so classification must accept it when the port matches.
func portedNodePortService(ns, name string, port int32, proto corev1.Protocol) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{Port: port, Protocol: proto}},
		},
	}
}

// externalNameService builds an ExternalName Service, which has no ClusterIP and
// must be rejected by forward classification.
func externalNameService(ns, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "example.com",
		},
	}
}

// headlessService builds a headless ClusterIP Service (clusterIP None), which has no
// stable VIP and so backs a forward in Local mode only.
func headlessService(ns, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: corev1.ClusterIPNone,
			Ports:     []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
		},
	}
}

func TestClassifyForwards(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	type outcome struct {
		// accepted means classification passed and provisioning ran.
		accepted bool
		// wantReason is the expected Ready reason on a denial (ignored when accepted).
		wantReason string
		// wantRequeue is the expected RequeueAfter from the reconcile that ran
		// classification; zero means none asserted.
		wantRequeue time.Duration
	}

	tests := []struct {
		name string
		// setup creates the prerequisite namespaces/services for the case in the
		// given gateway namespace and returns the forward under test.
		setup func(t *testing.T, gwNS string) wgnetv1alpha1.Forward
		want  outcome
	}{
		{
			name: "same-namespace ClusterIP service accepted",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedClusterIPService(gwNS, "web", 443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{accepted: true},
		},
		{
			name: "NodePort service accepted",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedNodePortService(gwNS, "web", 443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{accepted: true},
		},
		{
			name: "target port matching a published service port accepted",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedClusterIPService(gwNS, "web", 8443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443}
			},
			want: outcome{accepted: true},
		},
		{
			name: "ExternalName service rejected",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, externalNameService(gwNS, "web"))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonUnsupportedServiceType},
		},
		{
			name: "headless service rejected in cluster mode",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, headlessService(gwNS, "web"))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonUnsupportedServiceType},
		},
		{
			name: "target port not among published ports rejected",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedClusterIPService(gwNS, "web", 80, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonTargetPortNotListening, wantRequeue: validationRequeueAfter},
		},
		{
			name: "target port published under a different protocol rejected",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				mustCreate(ctx, t, cl, portedClusterIPService(gwNS, "web", 443, corev1.ProtocolUDP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonTargetPortNotListening, wantRequeue: validationRequeueAfter},
		},
		{
			name: "cross-namespace with consent label accepted",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				target := gwNS + "-target"
				mustCreate(ctx, t, cl, namespaceWithLabels(target, map[string]string{
					crossNamespaceIngressLabel: crossNamespaceIngressValue,
				}))
				mustCreate(ctx, t, cl, portedClusterIPService(target, "web", 443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", Namespace: target}
			},
			want: outcome{accepted: true},
		},
		{
			name: "cross-namespace without consent label denied",
			setup: func(t *testing.T, gwNS string) wgnetv1alpha1.Forward {
				target := gwNS + "-target"
				mustCreate(ctx, t, cl, namespaceWithLabels(target, nil))
				mustCreate(ctx, t, cl, portedClusterIPService(target, "web", 443, corev1.ProtocolTCP))
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", Namespace: target}
			},
			want: outcome{wantReason: reasonCrossNamespaceForwardDenied},
		},
		{
			name: "cross-namespace target namespace missing denied",
			setup: func(_ *testing.T, gwNS string) wgnetv1alpha1.Forward {
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", Namespace: gwNS + "-ghost"}
			},
			want: outcome{wantReason: reasonTargetNamespaceNotFound, wantRequeue: validationRequeueAfter},
		},
		{
			name: "backend service not found requeues",
			setup: func(_ *testing.T, _ string) wgnetv1alpha1.Forward {
				return wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			},
			want: outcome{wantReason: reasonServiceNotFound, wantRequeue: validationRequeueAfter},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gwNS := fmt.Sprintf("vf-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(gwNS, nil))

			forward := tt.setup(t, gwNS)
			gw := newGateway(gwNS, gwNS, []wgnetv1alpha1.Forward{forward}, nil)
			mustCreate(ctx, t, cl, gw)

			gen, _ := countingKeyGen()
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
			key := client.ObjectKeyFromObject(gw)

			result := reconcileToClassification(ctx, t, r, key)

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)

			bundleExists := !apierrors.IsNotFound(
				cl.Get(ctx, client.ObjectKey{Namespace: gwNS, Name: bundleSecretName(gw)}, &corev1.Secret{}))

			if tt.want.accepted {
				if !bundleExists {
					t.Errorf("accepted forward did not provision: bundle Secret absent")
				}
				if cond != nil && isValidationDenialReason(cond.Reason) {
					t.Errorf("accepted forward carries denial reason %q", cond.Reason)
				}
				return
			}

			if bundleExists {
				t.Errorf("denied forward provisioned children: bundle Secret present")
			}
			if cond == nil || cond.Status != metav1.ConditionFalse {
				t.Fatalf("Ready condition = %+v, want False", cond)
			}
			if cond.Reason != tt.want.wantReason {
				t.Errorf("Ready reason = %q, want %q (message: %q)", cond.Reason, tt.want.wantReason, cond.Message)
			}
			if tt.want.wantRequeue != 0 && result.RequeueAfter != tt.want.wantRequeue {
				t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, tt.want.wantRequeue)
			}
		})
	}
}

// TestBackendPortOf pins the pod-side port classification hands to the NetworkPolicy builder.
// An unset targetPort is not a case here: the API server defaults it, so envtest covers it.
func TestBackendPortOf(t *testing.T) {
	tests := []struct {
		name string
		port corev1.ServicePort
		want int32
	}{
		{
			name: "numeric target port resolves to the pod port",
			port: corev1.ServicePort{Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(10443)},
			want: 10443,
		},
		{
			name: "named target port is unresolved",
			port: corev1.ServicePort{Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("https")},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := backendPortOf(&tt.port); got != tt.want {
				t.Errorf("backendPortOf = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestClassifyForwardsResolvesBackendPort runs against a real API server: every case turns on
// server-side behaviour the fake client does not reproduce, starting with targetPort defaulting.
func TestClassifyForwardsResolvesBackendPort(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name string
		// ports are the backing Service's published ports.
		ports []corev1.ServicePort
		// forwardPort is the public port of the single forward under test; the forward
		// carries no TargetPort, so it matches the Service port of the same number.
		forwardPort int32
		want        int32
		// wantWarning expects one UnresolvedBackendPort Warning event.
		wantWarning bool
		// local runs the case under the Local traffic policy.
		local bool
	}{
		{
			name:        "api server defaults an unset target port to the service port",
			ports:       []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			forwardPort: 443,
			want:        443,
		},
		{
			name: "forward matching the second published port resolves that port's target",
			ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(10443)},
				{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(10080)},
			},
			forwardPort: 80,
			want:        10080,
		},
		{
			name:        "named target port stays unresolved and warns",
			ports:       []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("https")}},
			forwardPort: 443,
			want:        0,
			wantWarning: true,
		},
		{
			name:        "named target port in local mode warns about nothing",
			ports:       []corev1.ServicePort{{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("https")}},
			forwardPort: 443,
			want:        0,
			local:       true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gwNS := fmt.Sprintf("bp-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(gwNS, nil))

			mustCreate(ctx, t, cl, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: gwNS},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Ports: tt.ports},
			})

			gw := newGateway(gwNS, gwNS, []wgnetv1alpha1.Forward{
				{Port: tt.forwardPort, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			if tt.local {
				gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
			}
			rec := &fakeEventRecorder{}
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), Recorder: rec})

			valid, invalid, err := r.classifyForwards(ctx, gw)
			if err != nil {
				t.Fatalf("classify forwards: %v", err)
			}
			if len(invalid) != 0 {
				t.Fatalf("invalid = %+v, want none", invalid)
			}
			if len(valid) != 1 {
				t.Fatalf("valid = %d, want 1", len(valid))
			}
			if got := valid[0].BackendPort; got != tt.want {
				t.Errorf("backend port = %d, want %d", got, tt.want)
			}

			// A second pass stands in for the steady-state requeue: the warning is tied to
			// the unresolved set changing, so the event counts also assert it is not re-emitted.
			if _, _, err := r.classifyForwards(ctx, gw); err != nil {
				t.Fatalf("classify forwards (second pass): %v", err)
			}

			if !tt.wantWarning {
				if len(rec.events) != 0 {
					t.Errorf("recorded %+v, want no events", rec.events)
				}
				return
			}
			if len(rec.events) != 1 {
				t.Fatalf("recorded %d events, want 1: %+v", len(rec.events), rec.events)
			}
			ev := rec.events[0]
			if ev.eventtype != corev1.EventTypeWarning || ev.reason != reasonUnresolvedBackendPort {
				t.Errorf("event = %s/%s, want %s/%s", ev.eventtype, ev.reason, corev1.EventTypeWarning, reasonUnresolvedBackendPort)
			}
			if !strings.Contains(ev.note, "https") {
				t.Errorf("event note = %q, want it to name the unresolved targetPort", ev.note)
			}
		})
	}
}

// isValidationDenialReason reports whether reason is one of the forward-validation denial
// reasons, used to assert an accepted forward did not land in a denied state.
func isValidationDenialReason(reason string) bool {
	switch reason {
	case reasonCrossNamespaceForwardDenied, reasonTargetNamespaceNotFound,
		reasonUnsupportedServiceType, reasonServiceNotFound, reasonTargetPortNotListening:
		return true
	default:
		return false
	}
}

// reconcileToClassification reconciles past the finalizer-add pass, which requeues before
// classification runs, and returns the result of the second pass.
func reconcileToClassification(ctx context.Context, t *testing.T, r *GatewayReconciler, key client.ObjectKey) ctrl.Result {
	t.Helper()
	req := ctrl.Request{NamespacedName: key}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile (finalizer pass): %v", err)
	}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile (classification pass): %v", err)
	}
	return result
}

// linkConfigForwards reads the link ConfigMap rendered for the Gateway at key and returns its
// runtime forwards, the assertion surface for which forwards the operator exposed.
func linkConfigForwards(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey) []link.Forward {
	t.Helper()
	var cm corev1.ConfigMap
	cmKey := client.ObjectKey{Namespace: key.Namespace, Name: key.Name + "-link"}
	if err := cl.Get(ctx, cmKey, &cm); err != nil {
		t.Fatalf("get link configmap %s: %v", cmKey, err)
	}
	raw, ok := cm.Data[linkConfigKey]
	if !ok {
		t.Fatalf("link configmap %s missing %q", cmKey, linkConfigKey)
	}
	var rc link.RuntimeConfig
	decodeJSON(t, raw, &rc)
	return rc.Forwards
}

// forwardServiceNames returns the Service FQDNs of the given runtime forwards, the
// stable field for asserting which forwards a link config carries.
func forwardServiceNames(forwards []link.Forward) []string {
	names := make([]string, 0, len(forwards))
	for _, f := range forwards {
		names = append(names, f.Service)
	}
	return names
}

// TestMixedForwards covers per-forward classification: one valid and one invalid forward still
// provisions, exposes only the valid forward, and reports Ready=False with the invalid reason.
func TestMixedForwards(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	const ns = "mixed"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

	gw := newGateway("mixed-gw", ns, []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
		{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "absent"},
	}, nil)
	mustCreate(ctx, t, cl, gw)

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})
	key := client.ObjectKeyFromObject(gw)

	result := reconcileToClassification(ctx, t, r, key)

	// A valid forward exists, so the Gateway provisions: the bundle Secret appears.
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bundleSecretName(gw)}, &corev1.Secret{}); err != nil {
		t.Fatalf("mixed Gateway did not provision (bundle Secret absent): %v", err)
	}

	// The link config carries only the valid forward, not the invalid one.
	got := forwardServiceNames(linkConfigForwards(ctx, t, cl, key))
	want := []string{"web." + ns + ".svc.cluster.local"}
	if !slices.Equal(got, want) {
		t.Errorf("link config forwards = %v, want %v (only the valid forward)", got, want)
	}

	// Ready=False with the invalid forward's reason.
	var live wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &live)
	cond := apimeta.FindStatusCondition(live.Status.Conditions, conditionReady)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %+v, want False", cond)
	}
	if cond.Reason != reasonServiceNotFound {
		t.Errorf("Ready reason = %q, want %q (message: %q)", cond.Reason, reasonServiceNotFound, cond.Message)
	}
	// The invalid forward's reason is transient, so the reconcile requeues.
	if result.RequeueAfter != validationRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v (transient invalid forward)", result.RequeueAfter, validationRequeueAfter)
	}
}

// TestClassifyForwardsRecordsServicePortName pins that the matched Service port name is carried
// through: a Local link matches it in the EndpointSlice, and an unnamed port stays empty.
func TestClassifyForwardsRecordsServicePortName(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name  string
		ports []corev1.ServicePort
		want  string
	}{
		{
			name:  "unnamed single port carries no name",
			ports: []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}},
			want:  "",
		},
		{
			name: "named port carries its name",
			ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(8443)},
				{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(8080)},
			},
			want: "https",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("spn-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			mustCreate(ctx, t, cl, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Ports: tt.ports},
			})

			gw := newGateway(ns, ns, []wgnetv1alpha1.Forward{
				{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			}, nil)
			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), Recorder: &fakeEventRecorder{}})

			valid, invalid, err := r.classifyForwards(ctx, gw)
			if err != nil {
				t.Fatalf("classify forwards: %v", err)
			}
			if len(invalid) != 0 || len(valid) != 1 {
				t.Fatalf("valid = %d, invalid = %+v, want 1 valid and none invalid", len(valid), invalid)
			}
			if got := valid[0].ServicePortName; got != tt.want {
				t.Errorf("servicePortName = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClassifyForwardsHeadlessByTrafficPolicy pins which backend shapes each policy accepts:
// only Cluster mode DNATs to a ClusterIP, so only it needs one.
func TestClassifyForwardsHeadlessByTrafficPolicy(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		// service builds the forward's backend in ns.
		service func(ns string) *corev1.Service
		// wantValid expects the forward to classify as valid.
		wantValid bool
	}{
		{
			name:      "cluster mode rejects a headless service",
			policy:    wgnetv1alpha1.TrafficPolicyCluster,
			service:   func(ns string) *corev1.Service { return headlessService(ns, "web") },
			wantValid: false,
		},
		{
			name:      "local mode accepts a headless service",
			policy:    wgnetv1alpha1.TrafficPolicyLocal,
			service:   func(ns string) *corev1.Service { return headlessService(ns, "web") },
			wantValid: true,
		},
		{
			name:      "local mode rejects an externalname service",
			policy:    wgnetv1alpha1.TrafficPolicyLocal,
			service:   func(ns string) *corev1.Service { return externalNameService(ns, "web") },
			wantValid: false,
		},
		{
			name:   "cluster mode accepts a clusterip service",
			policy: wgnetv1alpha1.TrafficPolicyCluster,
			service: func(ns string) *corev1.Service {
				return portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP)
			},
			wantValid: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gwNS := fmt.Sprintf("hl-%d", i)
			mustCreate(ctx, t, cl, namespaceWithLabels(gwNS, nil))
			mustCreate(ctx, t, cl, tt.service(gwNS))

			forward := wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}
			gw := newGateway(gwNS, gwNS, []wgnetv1alpha1.Forward{forward}, nil)
			gw.Spec.TrafficPolicy = tt.policy
			mustCreate(ctx, t, cl, gw)

			r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig()})
			valid, invalid, err := r.classifyForwards(ctx, gw)
			if err != nil {
				t.Fatalf("classify forwards: %v", err)
			}

			if !tt.wantValid {
				if len(valid) != 0 {
					t.Fatalf("valid = %+v, want the forward rejected", valid)
				}
				if len(invalid) != 1 || invalid[0].reason != reasonUnsupportedServiceType {
					t.Fatalf("invalid = %+v, want one %s", invalid, reasonUnsupportedServiceType)
				}
				return
			}

			if len(invalid) != 0 {
				t.Fatalf("invalid = %+v, want none", invalid)
			}
			if len(valid) != 1 || valid[0].Forward != forward {
				t.Fatalf("valid = %+v, want the forward carried through", valid)
			}
		})
	}
}
