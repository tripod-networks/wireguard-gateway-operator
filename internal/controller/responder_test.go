package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// responderWorkloadNames lists every Deployment and DaemonSet in ns as sorted "kind/name"
// strings, so a test pins the exact positive set of workloads rather than one kind's absence.
func responderWorkloadNames(ctx context.Context, t *testing.T, cl client.Client, ns string) []string {
	t.Helper()
	var deployments appsv1.DeploymentList
	if err := cl.List(ctx, &deployments, client.InNamespace(ns)); err != nil {
		t.Fatalf("list deployments: %v", err)
	}
	var daemonSets appsv1.DaemonSetList
	if err := cl.List(ctx, &daemonSets, client.InNamespace(ns)); err != nil {
		t.Fatalf("list daemonsets: %v", err)
	}
	names := make([]string, 0, len(deployments.Items)+len(daemonSets.Items))
	for _, d := range deployments.Items {
		names = append(names, "Deployment/"+d.Name)
	}
	for _, d := range daemonSets.Items {
		names = append(names, "DaemonSet/"+d.Name)
	}
	slices.Sort(names)
	return names
}

// wantResponderOwnerRef is the controller reference every responder object must carry back to
// its owning Gateway; envtest runs no garbage collector, so the reference itself is asserted.
func wantResponderOwnerRef(t *testing.T, cl client.Client, key client.ObjectKey, refs []metav1.OwnerReference) {
	t.Helper()
	var gw wgnetv1alpha1.Gateway
	mustGet(context.Background(), t, cl, key, &gw)
	if len(refs) != 1 {
		t.Fatalf("owner references = %+v, want exactly one", refs)
	}
	ref := refs[0]
	if ref.Kind != "Gateway" || ref.Name != gw.Name || ref.UID != gw.UID || ref.Controller == nil || !*ref.Controller {
		t.Errorf("owner reference = %+v, want a controller reference to Gateway %s (uid %s)", ref, gw.Name, gw.UID)
	}
}

// TestEnsureGatewayResponderCluster pins that reconciling a Cluster Gateway creates its own
// responder Deployment, Service and PDB (default replicas 2), each owned by the Gateway.
func TestEnsureGatewayResponderCluster(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	r, key := linkGatewayFixture(ctx, t, te, "responder-cluster", wgnetv1alpha1.TrafficPolicyCluster)
	drainReconcile(ctx, t, r, key)

	var dep appsv1.Deployment
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: key.Namespace, Name: "gw-responder"}, &dep)
	wantResponderOwnerRef(t, cl, key, dep.OwnerReferences)

	var svc corev1.Service
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: key.Namespace, Name: "gw-responder"}, &svc)
	wantResponderOwnerRef(t, cl, key, svc.OwnerReferences)
	if svc.Spec.ClusterIP == "" {
		t.Error("responder service clusterIP = \"\", want a non-empty ClusterIP")
	}

	wantWorkloads := []string{"Deployment/gw-link", "Deployment/gw-responder"}
	if got := responderWorkloadNames(ctx, t, cl, key.Namespace); !slices.Equal(got, wantWorkloads) {
		t.Errorf("workloads = %v, want exactly %v", got, wantWorkloads)
	}

	var pdbs policyv1.PodDisruptionBudgetList
	if err := cl.List(ctx, &pdbs, client.InNamespace(key.Namespace)); err != nil {
		t.Fatalf("list poddisruptionbudgets: %v", err)
	}
	pdbNames := make([]string, 0, len(pdbs.Items))
	for _, p := range pdbs.Items {
		pdbNames = append(pdbNames, p.Name)
	}
	slices.Sort(pdbNames)
	wantPDBs := []string{"gw-responder"}
	if !slices.Equal(pdbNames, wantPDBs) {
		t.Errorf("poddisruptionbudgets = %v, want exactly %v", pdbNames, wantPDBs)
	}
}

// TestEnsureGatewayResponderPolicySwitch pins that reconciling a Gateway whose traffic policy
// differs from a same-named stale responder workload's kind replaces it, leaving exactly one.
func TestEnsureGatewayResponderPolicySwitch(t *testing.T) {
	tests := []struct {
		name          string
		policy        wgnetv1alpha1.TrafficPolicy
		seed          func(cfg Config, gw *wgnetv1alpha1.Gateway) client.Object
		wantWorkloads []string
		wantDeletes   []string
	}{
		{
			name:   "cluster-to-local",
			policy: wgnetv1alpha1.TrafficPolicyLocal,
			seed: func(cfg Config, gw *wgnetv1alpha1.Gateway) client.Object {
				return buildResponderDeployment(cfg, gw)
			},
			wantWorkloads: []string{"DaemonSet/gw-responder"},
			wantDeletes:   []string{"Delete/Deployment=1"},
		},
		{
			name:   "local-to-cluster",
			policy: wgnetv1alpha1.TrafficPolicyCluster,
			seed: func(cfg Config, gw *wgnetv1alpha1.Gateway) client.Object {
				return buildResponderDaemonSet(cfg, gw)
			},
			wantWorkloads: []string{"Deployment/gw-responder"},
			wantDeletes:   []string{"Delete/DaemonSet=1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			te := setupEnvtestRBAC(t)
			cl := te.client

			ns := "responder-switch-" + tt.name
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			cfg := reconcileConfig()

			gw := newGateway("gw", ns, nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			mustCreate(ctx, t, cl, tt.seed(cfg, gw))
			mustCreate(ctx, t, cl, gw)

			r := newOperatorReconciler(te, &GatewayReconciler{Config: cfg})
			writes := countingResponderClient(t, te, r, "gw-responder", nil)
			if _, err := r.ensureGatewayResponder(ctx, gw); err != nil {
				t.Fatalf("ensureGatewayResponder: %v", err)
			}
			if got := writes.verbEntries("Delete"); !slices.Equal(got, tt.wantDeletes) {
				t.Errorf("deletes on the switch = %v, want exactly %v", got, tt.wantDeletes)
			}

			writes.reset()
			if _, err := r.ensureGatewayResponder(ctx, gw); err != nil {
				t.Fatalf("steady ensureGatewayResponder: %v", err)
			}
			if got := writes.verbEntries("Delete"); len(got) != 0 {
				t.Errorf("deletes on the steady pass = %v, want exactly []", got)
			}

			if got := responderWorkloadNames(ctx, t, cl, ns); !slices.Equal(got, tt.wantWorkloads) {
				t.Errorf("workloads = %v, want exactly %v once the policy switched", got, tt.wantWorkloads)
			}
			wantResponderOwnerRef(t, cl, client.ObjectKeyFromObject(gw), currentResponderOwnerRefs(ctx, t, cl, ns))
		})
	}
}

// currentResponderOwnerRefs returns the owner references of whichever workload kind
// responderWorkloadNames found for ns, so a table row need not know which kind won.
func currentResponderOwnerRefs(ctx context.Context, t *testing.T, cl client.Client, ns string) []metav1.OwnerReference {
	t.Helper()
	var dep appsv1.Deployment
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: "gw-responder"}, &dep); err == nil {
		return dep.OwnerReferences
	}
	var ds appsv1.DaemonSet
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-responder"}, &ds)
	return ds.OwnerReferences
}

// createTerminatingResponderWorkload creates obj held by a test finalizer, then deletes it so
// envtest sets DeletionTimestamp; t.Cleanup strips the finalizer so the object can go away.
func createTerminatingResponderWorkload(ctx context.Context, t *testing.T, cl client.Client, obj client.Object) {
	t.Helper()
	const finalizer = "wgnet.dev/test-hold"
	obj.SetFinalizers([]string{finalizer})
	key := client.ObjectKeyFromObject(obj)
	mustCreate(ctx, t, cl, obj)
	if err := cl.Delete(ctx, obj); err != nil {
		t.Fatalf("delete %T %s: %v", obj, key, err)
	}
	live, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		t.Fatalf("deep copy of %T is not a client.Object", obj)
	}
	mustGet(ctx, t, cl, key, live)
	if live.GetDeletionTimestamp().IsZero() {
		t.Fatalf("%T %s deletionTimestamp = zero, want it terminating", obj, key)
	}
	t.Cleanup(func() {
		clean, ok := obj.DeepCopyObject().(client.Object)
		if !ok {
			t.Fatalf("deep copy of %T is not a client.Object", obj)
		}
		if err := cl.Get(ctx, key, clean); err != nil {
			if apierrors.IsNotFound(err) {
				return
			}
			t.Fatalf("get %T %s for cleanup: %v", obj, key, err)
		}
		clean.SetFinalizers(nil)
		if err := cl.Update(ctx, clean); err != nil {
			t.Fatalf("clear %T %s finalizer: %v", obj, key, err)
		}
	})
}

// TestEnsureGatewayResponderLeftoverTerminating pins that a leftover responder workload already
// carrying a deletionTimestamp draws no Delete when the traffic policy switches away from it.
func TestEnsureGatewayResponderLeftoverTerminating(t *testing.T) {
	tests := []struct {
		name          string
		policy        wgnetv1alpha1.TrafficPolicy
		leftover      func(cfg Config, gw *wgnetv1alpha1.Gateway) client.Object
		wantWorkloads []string
	}{
		{
			name:   "cluster-to-local",
			policy: wgnetv1alpha1.TrafficPolicyLocal,
			leftover: func(cfg Config, gw *wgnetv1alpha1.Gateway) client.Object {
				return buildResponderDeployment(cfg, gw)
			},
			wantWorkloads: []string{"DaemonSet/gw-responder", "Deployment/gw-responder"},
		},
		{
			name:   "local-to-cluster",
			policy: wgnetv1alpha1.TrafficPolicyCluster,
			leftover: func(cfg Config, gw *wgnetv1alpha1.Gateway) client.Object {
				return buildResponderDaemonSet(cfg, gw)
			},
			wantWorkloads: []string{"DaemonSet/gw-responder", "Deployment/gw-responder"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			te := setupEnvtestRBAC(t)
			cl := te.client

			ns := "responder-terminating-" + tt.name
			mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
			cfg := reconcileConfig()

			gw := newGateway("gw", ns, nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			createTerminatingResponderWorkload(ctx, t, cl, tt.leftover(cfg, gw))
			mustCreate(ctx, t, cl, gw)

			r := newOperatorReconciler(te, &GatewayReconciler{Config: cfg})
			writes := countingResponderClient(t, te, r, "gw-responder", nil)
			if _, err := r.ensureGatewayResponder(ctx, gw); err != nil {
				t.Fatalf("ensureGatewayResponder: %v", err)
			}
			if got := writes.verbEntries("Delete"); !slices.Equal(got, []string{}) {
				t.Errorf("deletes with a terminating leftover = %v, want exactly []", got)
			}
			if got := responderWorkloadNames(ctx, t, cl, ns); !slices.Equal(got, tt.wantWorkloads) {
				t.Errorf("workloads = %v, want exactly %v", got, tt.wantWorkloads)
			}
		})
	}
}

// TestEnsureGatewayResponderTwoGateways pins that two Gateways in one namespace each get a
// distinct responder Deployment and Service, named after their own Gateway.
func TestEnsureGatewayResponderTwoGateways(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	const ns = "responder-two-gateways"
	mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
	mustCreate(ctx, t, cl, portedClusterIPService(ns, "web", 443, corev1.ProtocolTCP))

	forwards := []wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}
	gwA := newGateway("gw-a", ns, forwards, nil)
	gwB := newGateway("gw-b", ns, forwards, nil)
	mustCreate(ctx, t, cl, gwA)
	mustCreate(ctx, t, cl, gwB)

	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig()})
	drainReconcile(ctx, t, r, client.ObjectKeyFromObject(gwA))
	drainReconcile(ctx, t, r, client.ObjectKeyFromObject(gwB))

	var depA, depB appsv1.Deployment
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-a-responder"}, &depA)
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-b-responder"}, &depB)
	wantResponderOwnerRef(t, cl, client.ObjectKeyFromObject(gwA), depA.OwnerReferences)
	wantResponderOwnerRef(t, cl, client.ObjectKeyFromObject(gwB), depB.OwnerReferences)

	var svcA, svcB corev1.Service
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-a-responder"}, &svcA)
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-b-responder"}, &svcB)
	if svcA.Spec.ClusterIP == "" || svcB.Spec.ClusterIP == "" {
		t.Fatalf("responder service clusterIPs = %q, %q, want both non-empty", svcA.Spec.ClusterIP, svcB.Spec.ClusterIP)
	}
	if svcA.Spec.ClusterIP == svcB.Spec.ClusterIP {
		t.Errorf("responder service clusterIPs = %q for both gateways, want distinct Services", svcA.Spec.ClusterIP)
	}
}

// TestWarnResponderMissingEventText pins the Cluster-shape Warning event text against the
// ResponderMissing condition message: both name the responder workload, not the namespace.
func TestWarnResponderMissingEventText(t *testing.T) {
	gw := newGateway("gw", "responder-missing-event", nil, nil)
	rec := &fakeEventRecorder{}
	r := &GatewayReconciler{Recorder: rec}

	r.warnResponderMissing(gw, &responderMissingStatus{local: false, present: false})

	if len(rec.events) != 1 {
		t.Fatalf("recorded %d events, want 1: %+v", len(rec.events), rec.events)
	}
	ev := rec.events[0]
	wantNote := "no ready responder pod for gw-responder"
	if ev.eventtype != corev1.EventTypeWarning || ev.reason != reasonNoResponderRunning || ev.note != wantNote {
		t.Errorf("event = %s/%s %q, want %s/%s %q",
			ev.eventtype, ev.reason, ev.note, corev1.EventTypeWarning, reasonNoResponderRunning, wantNote)
	}
}

// configHashHex hashes data the same way responderConfigHash does, letting a test assert the
// pod-template annotation without depending on the production helper's own correctness.
func configHashHex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// TestBuildResponderDeployment table-tests the Cluster-mode responder Deployment: identity,
// labels, replicas, image, container port, resources and the anti-affinity block.
func TestBuildResponderDeployment(t *testing.T) {
	tests := []struct {
		name         string
		mutate       func(gw *wgnetv1alpha1.Gateway)
		wantReplicas int32
		wantImage    string
		wantPort     int32
	}{
		{
			name:         "unset spec falls back to defaults",
			wantReplicas: 2,
			wantImage:    "registry.example.com/gateway-responder:test",
			wantPort:     27000,
		},
		{
			name: "spec overrides replicas, image and port",
			mutate: func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.Responder.Replicas = 3
				gw.Spec.Responder.Image = "registry.example.com/custom-responder:v2"
				gw.Spec.Responder.Port = 9090
			},
			wantReplicas: 3,
			wantImage:    "registry.example.com/custom-responder:v2",
			wantPort:     9090,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.Responder.Resources = corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m")},
			}
			if tt.mutate != nil {
				tt.mutate(gw)
			}

			dep := buildResponderDeployment(cfg, gw)

			if dep.Name != "edge-responder" || dep.Namespace != "wg-system" {
				t.Errorf("deployment = %s/%s, want wg-system/edge-responder", dep.Namespace, dep.Name)
			}
			if !maps.Equal(dep.Labels, commonLabels(gw, componentResponder)) {
				t.Errorf("labels = %v, want %v", dep.Labels, commonLabels(gw, componentResponder))
			}
			if got := *dep.Spec.Replicas; got != tt.wantReplicas {
				t.Errorf("replicas = %d, want %d", got, tt.wantReplicas)
			}
			if !maps.Equal(dep.Spec.Selector.MatchLabels, responderSelectorLabels(gw)) {
				t.Errorf("selector = %v, want %v", dep.Spec.Selector.MatchLabels, responderSelectorLabels(gw))
			}

			if dep.Spec.Template.Spec.AutomountServiceAccountToken == nil || *dep.Spec.Template.Spec.AutomountServiceAccountToken {
				t.Errorf("automountServiceAccountToken = %v, want false", dep.Spec.Template.Spec.AutomountServiceAccountToken)
			}

			if len(dep.Spec.Template.Spec.Containers) != 1 {
				t.Fatalf("containers = %+v, want exactly one", dep.Spec.Template.Spec.Containers)
			}
			c := dep.Spec.Template.Spec.Containers[0]
			if c.Image != tt.wantImage {
				t.Errorf("image = %q, want %q", c.Image, tt.wantImage)
			}
			if len(c.Ports) != 1 || c.Ports[0].ContainerPort != tt.wantPort {
				t.Errorf("container ports = %+v, want a single port %d", c.Ports, tt.wantPort)
			}
			if !apiequality.Semantic.DeepEqual(c.Resources, gw.Spec.Responder.Resources) {
				t.Errorf("resources = %+v, want %+v", c.Resources, gw.Spec.Responder.Resources)
			}

			aff := dep.Spec.Template.Spec.Affinity
			if aff == nil || aff.PodAntiAffinity == nil || len(aff.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) != 1 {
				t.Fatalf("affinity = %+v, want one preferred pod anti-affinity term", aff)
			}
			term := aff.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution[0]
			if term.PodAffinityTerm.TopologyKey != "kubernetes.io/hostname" {
				t.Errorf("anti-affinity topologyKey = %q, want kubernetes.io/hostname", term.PodAffinityTerm.TopologyKey)
			}
			if !maps.Equal(term.PodAffinityTerm.LabelSelector.MatchLabels, responderSelectorLabels(gw)) {
				t.Errorf("anti-affinity selector = %v, want %v", term.PodAffinityTerm.LabelSelector.MatchLabels, responderSelectorLabels(gw))
			}
			if len(dep.Spec.Template.Spec.Tolerations) != 0 {
				t.Errorf("tolerations = %+v, want none on the deployment", dep.Spec.Template.Spec.Tolerations)
			}

			wantHash := configHashHex(buildResponderConfigMap(gw).Data[nginxConfKey])
			if got := dep.Spec.Template.Annotations[configHashAnnotation]; got != wantHash {
				t.Errorf("config-hash annotation = %q, want %q", got, wantHash)
			}
		})
	}

	t.Run("port-only difference changes the config-hash annotation", func(t *testing.T) {
		cfg := testConfig()
		gwA := newGateway("edge", "wg-system", nil, nil)
		gwB := newGateway("edge", "wg-system", nil, nil)
		gwB.Spec.Responder.Port = 9090

		hashA := buildResponderDeployment(cfg, gwA).Spec.Template.Annotations[configHashAnnotation]
		hashB := buildResponderDeployment(cfg, gwB).Spec.Template.Annotations[configHashAnnotation]
		if hashA == hashB {
			t.Errorf("config-hash annotation = %q for both ports, want distinct once spec.responder.port differs", hashA)
		}
	})
}

type podScheduling struct {
	NodeSelector map[string]string
	Tolerations  []corev1.Toleration
	Affinity     *corev1.Affinity
}

func schedulingOf(spec corev1.PodSpec) podScheduling {
	return podScheduling{NodeSelector: spec.NodeSelector, Tolerations: spec.Tolerations, Affinity: spec.Affinity}
}

// TestBuildResponderDaemonSet pins the Local-mode responder DaemonSet: identity, labels, selector,
// and scheduling constraints identical to the link DaemonSet's, so both land on the same nodes.
func TestBuildResponderDaemonSet(t *testing.T) {
	tests := []struct {
		name             string
		wantNodeSelector map[string]string
	}{
		{name: "no nodeSelector"},
		{name: "spec.link.nodeSelector carried onto the template", wantNodeSelector: map[string]string{"pool": "edge"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
			gw.Spec.Link.NodeSelector = tt.wantNodeSelector
			gw.Status.Link.ID = 3

			ds := buildResponderDaemonSet(cfg, gw)

			if ds.Name != "edge-responder" || ds.Namespace != "wg-system" {
				t.Errorf("daemonset = %s/%s, want wg-system/edge-responder", ds.Namespace, ds.Name)
			}
			if !maps.Equal(ds.Labels, commonLabels(gw, componentResponder)) {
				t.Errorf("labels = %v, want %v", ds.Labels, commonLabels(gw, componentResponder))
			}
			if !maps.Equal(ds.Spec.Selector.MatchLabels, responderSelectorLabels(gw)) {
				t.Errorf("selector = %v, want %v", ds.Spec.Selector.MatchLabels, responderSelectorLabels(gw))
			}
			if ds.Spec.Template.Spec.AutomountServiceAccountToken == nil || *ds.Spec.Template.Spec.AutomountServiceAccountToken {
				t.Errorf("automountServiceAccountToken = %v, want false", ds.Spec.Template.Spec.AutomountServiceAccountToken)
			}
			if !maps.Equal(ds.Spec.Template.Spec.NodeSelector, tt.wantNodeSelector) {
				t.Errorf("nodeSelector = %v, want %v", ds.Spec.Template.Spec.NodeSelector, tt.wantNodeSelector)
			}
			linkDS := buildLinkDaemonSet(gw, cfg, linkIdentityOf(gw))
			got := schedulingOf(ds.Spec.Template.Spec)
			if want := schedulingOf(linkDS.Spec.Template.Spec); !reflect.DeepEqual(got, want) {
				t.Errorf("responder scheduling = %+v, want the link daemonset's %+v", got, want)
			}
			if ds.Spec.UpdateStrategy.Type != appsv1.RollingUpdateDaemonSetStrategyType {
				t.Errorf("updateStrategy = %q, want RollingUpdate", ds.Spec.UpdateStrategy.Type)
			}

			wantHash := configHashHex(buildResponderConfigMap(gw).Data[nginxConfKey])
			if got := ds.Spec.Template.Annotations[configHashAnnotation]; got != wantHash {
				t.Errorf("config-hash annotation = %q, want %q", got, wantHash)
			}
		})
	}
}

// TestBuildResponderPodDisruptionBudget pins the responder PDB's shape at default replicas (2),
// and that ensureGatewayResponder applies none at replicas 1: it would only block its own pod.
func TestBuildResponderPodDisruptionBudget(t *testing.T) {
	t.Run("default replicas 2 builds the exact pdb shape", func(t *testing.T) {
		gw := newGateway("edge", "wg-system", nil, nil)
		pdb := buildResponderPodDisruptionBudget(gw)

		if pdb.Name != "edge-responder" || pdb.Namespace != "wg-system" {
			t.Errorf("pdb = %s/%s, want wg-system/edge-responder", pdb.Namespace, pdb.Name)
		}
		if !maps.Equal(pdb.Labels, commonLabels(gw, componentResponder)) {
			t.Errorf("labels = %v, want %v", pdb.Labels, commonLabels(gw, componentResponder))
		}
		if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntVal != 1 {
			t.Errorf("minAvailable = %+v, want 1", pdb.Spec.MinAvailable)
		}
		if pdb.Spec.Selector == nil || !maps.Equal(pdb.Spec.Selector.MatchLabels, responderSelectorLabels(gw)) {
			t.Errorf("selector = %+v, want responder selector %v", pdb.Spec.Selector, responderSelectorLabels(gw))
		}
		if pdb.Spec.UnhealthyPodEvictionPolicy == nil || *pdb.Spec.UnhealthyPodEvictionPolicy != policyv1.AlwaysAllow {
			t.Errorf("unhealthyPodEvictionPolicy = %v, want AlwaysAllow", pdb.Spec.UnhealthyPodEvictionPolicy)
		}
	})

	t.Run("replicas 1 applies no pdb", func(t *testing.T) {
		ctx := context.Background()
		te := setupEnvtestRBAC(t)
		cl := te.client

		const ns = "responder-pdb-single"
		mustCreate(ctx, t, cl, namespaceWithLabels(ns, nil))
		gw := newGateway("gw", ns, nil, nil)
		gw.Spec.Responder.Replicas = 1
		mustCreate(ctx, t, cl, gw)

		r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig()})
		if _, err := r.ensureGatewayResponder(ctx, gw); err != nil {
			t.Fatalf("ensureGatewayResponder: %v", err)
		}

		var deployments appsv1.DeploymentList
		if err := cl.List(ctx, &deployments, client.InNamespace(ns)); err != nil {
			t.Fatalf("list deployments: %v", err)
		}
		var pdbs policyv1.PodDisruptionBudgetList
		if err := cl.List(ctx, &pdbs, client.InNamespace(ns)); err != nil {
			t.Fatalf("list poddisruptionbudgets: %v", err)
		}
		names := make([]string, 0, len(deployments.Items)+len(pdbs.Items))
		for _, d := range deployments.Items {
			names = append(names, "Deployment/"+d.Name)
		}
		for _, p := range pdbs.Items {
			names = append(names, "PodDisruptionBudget/"+p.Name)
		}
		slices.Sort(names)
		want := []string{"Deployment/gw-responder"}
		if !slices.Equal(names, want) {
			t.Errorf("responder deployments+pdbs = %v, want exactly %v", names, want)
		}
	})
}

// TestBuildResponderService pins the responder Service: identity, labels, selector and port.
func TestBuildResponderService(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Responder.Port = 9090

	svc := buildResponderService(gw)

	if svc.Name != "edge-responder" || svc.Namespace != "wg-system" {
		t.Errorf("service = %s/%s, want wg-system/edge-responder", svc.Namespace, svc.Name)
	}
	if !maps.Equal(svc.Labels, commonLabels(gw, componentResponder)) {
		t.Errorf("labels = %v, want %v", svc.Labels, commonLabels(gw, componentResponder))
	}
	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("type = %q, want ClusterIP", svc.Spec.Type)
	}
	if !maps.Equal(svc.Spec.Selector, responderSelectorLabels(gw)) {
		t.Errorf("selector = %v, want %v", svc.Spec.Selector, responderSelectorLabels(gw))
	}
	if len(svc.Spec.Ports) != 1 {
		t.Fatalf("ports = %+v, want exactly one", svc.Spec.Ports)
	}
	port := svc.Spec.Ports[0]
	if port.Name != "http" || port.Port != 9090 || port.TargetPort != intstr.FromString("http") {
		t.Errorf("port = %+v, want name http, port 9090, targetPort http", port)
	}
}

// TestBuildResponderConfigMap pins the responder ConfigMap's identity and its nginx.conf's
// listen port.
func TestBuildResponderConfigMap(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Responder.Port = 9090

	cm := buildResponderConfigMap(gw)

	if cm.Name != "edge-responder" || cm.Namespace != "wg-system" {
		t.Errorf("configmap = %s/%s, want wg-system/edge-responder", cm.Namespace, cm.Name)
	}
	if !maps.Equal(cm.Labels, commonLabels(gw, componentResponder)) {
		t.Errorf("labels = %v, want %v", cm.Labels, commonLabels(gw, componentResponder))
	}
	conf := cm.Data[nginxConfKey]
	if !strings.Contains(conf, "listen 9090;") || !strings.Contains(conf, "location = /forwarded-healthz") {
		t.Errorf("nginx.conf = %q, want it to contain the listen port and the forwarded-healthz location", conf)
	}
}

// createTerminatingLinkPod creates a Running link pod held by a finalizer, then deletes it so
// envtest sets DeletionTimestamp; t.Cleanup strips the finalizer to let the namespace tear down.
func createTerminatingLinkPod(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway, name, nodeName string) {
	t.Helper()
	const finalizer = "wgnet.dev/test-hold"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: name, Labels: linkSelectorLabels(gw), Finalizers: []string{finalizer}},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{{Name: "link", Image: "registry.example.com/gateway-link:test"}},
		},
	}
	if err := cl.Create(ctx, pod); err != nil {
		t.Fatalf("create link pod %s/%s: %v", gw.Namespace, name, err)
	}
	pod.Status.Phase = corev1.PodRunning
	if err := cl.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update link pod %s/%s status: %v", gw.Namespace, name, err)
	}
	if err := cl.Delete(ctx, pod); err != nil {
		t.Fatalf("delete link pod %s/%s: %v", gw.Namespace, name, err)
	}
	t.Cleanup(func() {
		var p corev1.Pod
		if err := cl.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: name}, &p); err != nil {
			if apierrors.IsNotFound(err) {
				return
			}
			t.Fatalf("get link pod %s/%s for cleanup: %v", gw.Namespace, name, err)
		}
		p.Finalizers = nil
		if err := cl.Update(ctx, &p); err != nil {
			t.Fatalf("clear link pod %s/%s finalizer: %v", gw.Namespace, name, err)
		}
	})
}

// createTerminatingResponderPod creates a Running, Ready responder pod held by a finalizer,
// then deletes it so envtest sets DeletionTimestamp; t.Cleanup strips the finalizer.
func createTerminatingResponderPod(ctx context.Context, t *testing.T, cl client.Client, namespace, name, nodeName, podIP string, labels map[string]string) {
	t.Helper()
	const finalizer = "wgnet.dev/test-hold"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels, Finalizers: []string{finalizer}},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{{Name: "responder", Image: "registry.example.com/responder:test"}},
		},
	}
	if err := cl.Create(ctx, pod); err != nil {
		t.Fatalf("create responder pod %s/%s: %v", namespace, name, err)
	}
	pod.Status.Phase = corev1.PodRunning
	pod.Status.PodIP = podIP
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := cl.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update responder pod %s/%s status: %v", namespace, name, err)
	}
	if err := cl.Delete(ctx, pod); err != nil {
		t.Fatalf("delete responder pod %s/%s: %v", namespace, name, err)
	}
	t.Cleanup(func() {
		var p corev1.Pod
		if err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &p); err != nil {
			if apierrors.IsNotFound(err) {
				return
			}
			t.Fatalf("get responder pod %s/%s for cleanup: %v", namespace, name, err)
		}
		p.Finalizers = nil
		if err := cl.Update(ctx, &p); err != nil {
			t.Fatalf("clear responder pod %s/%s finalizer: %v", namespace, name, err)
		}
	})
}

// TestResponderMissingCondition pins the ResponderMissing condition's transitions: True naming a
// link pod's node with no Running responder, False once every node has one.
func TestResponderMissingCondition(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	r, key := localGatewayFixture(ctx, t, te, "responder-missing")
	drainReconcile(ctx, t, r, key)

	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)

	createLinkPod(ctx, t, cl, &gw, "gw-link-a", "node-a")
	createLinkPod(ctx, t, cl, &gw, "gw-link-b", "node-b")
	createResponderPod(ctx, t, cl, gw.Namespace, "responder-a", "node-a", "10.10.0.1", responderSelectorLabels(&gw))

	drainReconcile(ctx, t, r, key)
	mustGet(ctx, t, cl, key, &gw)
	cond := findCondition(gw.Status.Conditions, conditionResponderMissing)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != reasonNoResponderOnNode || !strings.Contains(cond.Message, "node-b") {
		t.Fatalf("ResponderMissing condition = %+v, want True/%s naming node-b", cond, reasonNoResponderOnNode)
	}

	createResponderPod(ctx, t, cl, gw.Namespace, "responder-b", "node-b", "10.10.0.2", responderSelectorLabels(&gw))
	drainReconcile(ctx, t, r, key)
	mustGet(ctx, t, cl, key, &gw)
	cond = findCondition(gw.Status.Conditions, conditionResponderMissing)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonResponderPresent {
		t.Errorf("ResponderMissing condition = %+v, want False/%s once every node has a responder", cond, reasonResponderPresent)
	}

	notReadyAndTerminating := []struct {
		name      string
		ns        string
		createPod func(ctx context.Context, t *testing.T, cl client.Client, namespace, name, nodeName, podIP string, labels map[string]string)
	}{
		{
			name: "running but not ready pod counts as missing",
			ns:   "responder-missing-notready",
			createPod: func(ctx context.Context, t *testing.T, cl client.Client, namespace, name, nodeName, podIP string, labels map[string]string) {
				createResponderPodWithReady(ctx, t, cl, namespace, name, nodeName, podIP, labels, false)
			},
		},
		{
			name:      "terminating pod counts as missing",
			ns:        "responder-missing-terminating",
			createPod: createTerminatingResponderPod,
		},
	}
	for _, tt := range notReadyAndTerminating {
		t.Run(tt.name, func(t *testing.T) {
			r, key := localGatewayFixture(ctx, t, te, tt.ns)
			drainReconcile(ctx, t, r, key)

			var gw wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &gw)
			createLinkPod(ctx, t, cl, &gw, "gw-link-a", "node-a")
			tt.createPod(ctx, t, cl, gw.Namespace, "responder-a", "node-a", "10.10.0.1", responderSelectorLabels(&gw))

			drainReconcile(ctx, t, r, key)
			mustGet(ctx, t, cl, key, &gw)
			cond := findCondition(gw.Status.Conditions, conditionResponderMissing)
			if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != reasonNoResponderOnNode {
				t.Fatalf("ResponderMissing condition = %+v, want True/%s", cond, reasonNoResponderOnNode)
			}
		})
	}

	// A node whose only link pod is terminating or not yet Running carries no live link pod, so
	// responderMissingNodes must not name it; the empty set surfaces as False/reasonResponderPresent.
	linkPodExcludedByPhase := []struct {
		name          string
		ns            string
		createLinkPod func(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway, name, nodeName string)
	}{
		{
			name:          "terminating link pod's node is excluded from the missing set",
			ns:            "responder-missing-link-terminating",
			createLinkPod: createTerminatingLinkPod,
		},
		{
			name: "failed link pod's node is excluded from the missing set",
			ns:   "responder-missing-link-failed",
			createLinkPod: func(ctx context.Context, t *testing.T, cl client.Client, gw *wgnetv1alpha1.Gateway, name, nodeName string) {
				createLinkPodWithPhase(ctx, t, cl, gw, name, nodeName, corev1.PodFailed)
			},
		},
	}
	for _, tt := range linkPodExcludedByPhase {
		t.Run(tt.name, func(t *testing.T) {
			r, key := localGatewayFixture(ctx, t, te, tt.ns)
			drainReconcile(ctx, t, r, key)

			var gw wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &gw)
			tt.createLinkPod(ctx, t, cl, &gw, "gw-link-a", "node-a")

			drainReconcile(ctx, t, r, key)
			mustGet(ctx, t, cl, key, &gw)
			cond := findCondition(gw.Status.Conditions, conditionResponderMissing)
			if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonResponderPresent {
				t.Fatalf("ResponderMissing condition = %+v, want False/%s: node-a excluded from the missing set", cond, reasonResponderPresent)
			}
		})
	}
}

// TestResponderMissingConditionCluster pins the Cluster-shape ResponderMissing condition: True
// naming the responder workload and namespace while no responder pod is ready, False once one is.
func TestResponderMissingConditionCluster(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	r, key := linkGatewayFixture(ctx, t, te, "responder-missing-cluster", wgnetv1alpha1.TrafficPolicyCluster)
	drainReconcile(ctx, t, r, key)

	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)
	cond := findCondition(gw.Status.Conditions, conditionResponderMissing)
	wantMessage := "no ready responder pod for gw-responder in namespace responder-missing-cluster"
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != reasonNoResponderRunning || cond.Message != wantMessage {
		t.Fatalf("ResponderMissing condition = %+v, want True/%s %q", cond, reasonNoResponderRunning, wantMessage)
	}

	createResponderPod(ctx, t, cl, gw.Namespace, "responder-a", "node-a", "10.10.0.5", responderSelectorLabels(&gw))
	drainReconcile(ctx, t, r, key)
	mustGet(ctx, t, cl, key, &gw)
	cond = findCondition(gw.Status.Conditions, conditionResponderMissing)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != reasonResponderPresent {
		t.Errorf("ResponderMissing condition = %+v, want False/%s once a responder pod is ready", cond, reasonResponderPresent)
	}

	notReadyAndTerminating := []struct {
		name      string
		ns        string
		createPod func(ctx context.Context, t *testing.T, cl client.Client, namespace, name, nodeName, podIP string, labels map[string]string)
	}{
		{
			name: "running but not ready pod counts as missing",
			ns:   "responder-missing-cluster-notready",
			createPod: func(ctx context.Context, t *testing.T, cl client.Client, namespace, name, nodeName, podIP string, labels map[string]string) {
				createResponderPodWithReady(ctx, t, cl, namespace, name, nodeName, podIP, labels, false)
			},
		},
		{
			name:      "terminating pod counts as missing",
			ns:        "responder-missing-cluster-terminating",
			createPod: createTerminatingResponderPod,
		},
	}
	for _, tt := range notReadyAndTerminating {
		t.Run(tt.name, func(t *testing.T) {
			r, key := linkGatewayFixture(ctx, t, te, tt.ns, wgnetv1alpha1.TrafficPolicyCluster)
			drainReconcile(ctx, t, r, key)

			var gw wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &gw)
			tt.createPod(ctx, t, cl, gw.Namespace, "responder-a", "node-a", "10.10.0.9", responderSelectorLabels(&gw))

			drainReconcile(ctx, t, r, key)
			mustGet(ctx, t, cl, key, &gw)
			cond := findCondition(gw.Status.Conditions, conditionResponderMissing)
			if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != reasonNoResponderRunning {
				t.Fatalf("ResponderMissing condition = %+v, want True/%s", cond, reasonNoResponderRunning)
			}
		})
	}
}

// TestResponderObjectHash table-tests the gate hash: builder output hashes stably, every input
// that changes an object changes it, and a stale gate annotation on the input is ignored.
func TestResponderObjectHash(t *testing.T) {
	cfg := testConfig()
	gwWith := func(mutate func(gw *wgnetv1alpha1.Gateway)) *wgnetv1alpha1.Gateway {
		gw := newGateway("edge", "wg-system", nil, nil)
		if mutate != nil {
			mutate(gw)
		}
		return gw
	}
	staleDeployment := func() client.Object {
		dep := buildResponderDeployment(cfg, gwWith(nil))
		dep.Annotations = map[string]string{responderHashAnnotation: "stale"}
		return dep
	}

	tests := []struct {
		name      string
		a, b      client.Object
		wantEqual bool
	}{
		{
			name:      "same deployment built twice",
			a:         buildResponderDeployment(cfg, gwWith(nil)),
			b:         buildResponderDeployment(cfg, gwWith(nil)),
			wantEqual: true,
		},
		{
			name:      "stale gate annotation is excluded",
			a:         staleDeployment(),
			b:         buildResponderDeployment(cfg, gwWith(nil)),
			wantEqual: true,
		},
		{
			name: "replicas change",
			a:    buildResponderDeployment(cfg, gwWith(nil)),
			b:    buildResponderDeployment(cfg, gwWith(func(gw *wgnetv1alpha1.Gateway) { gw.Spec.Responder.Replicas = 3 })),
		},
		{
			name: "image change",
			a:    buildResponderDeployment(cfg, gwWith(nil)),
			b: buildResponderDeployment(cfg, gwWith(func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.Responder.Image = "registry.example.com/custom-responder:v2"
			})),
		},
		{
			name: "port change",
			a:    buildResponderDeployment(cfg, gwWith(nil)),
			b:    buildResponderDeployment(cfg, gwWith(func(gw *wgnetv1alpha1.Gateway) { gw.Spec.Responder.Port = 9090 })),
		},
		{
			name: "configmap data change",
			a:    buildResponderConfigMap(gwWith(nil)),
			b:    buildResponderConfigMap(gwWith(func(gw *wgnetv1alpha1.Gateway) { gw.Spec.Responder.Port = 9090 })),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantAnnotations := maps.Clone(tt.a.GetAnnotations())

			hashA, err := objectHash(tt.a, responderHashAnnotation)
			if err != nil {
				t.Fatalf("hash a: %v", err)
			}
			hashB, err := objectHash(tt.b, responderHashAnnotation)
			if err != nil {
				t.Fatalf("hash b: %v", err)
			}

			if (hashA == hashB) != tt.wantEqual {
				t.Errorf("hashes %q and %q equal = %v, want %v", hashA, hashB, hashA == hashB, tt.wantEqual)
			}
			if !maps.Equal(tt.a.GetAnnotations(), wantAnnotations) {
				t.Errorf("input annotations = %v, want %v unchanged by hashing", tt.a.GetAnnotations(), wantAnnotations)
			}
		})
	}
}

// responderWriteLog counts the responder-object writes a reconcile issues, keyed "<verb>/<kind>",
// so a test pins the exact set of calls instead of asserting one kind's absence.
type responderWriteLog struct {
	mu    sync.Mutex
	name  string
	calls map[string]int
}

// countedResponderKind names the kind obj is counted under, or "" for a kind the write-gate
// tests do not count (the Gateway itself, the link objects' kinds, RBAC, the GCP composites).
func countedResponderKind(obj client.Object) string {
	switch obj.(type) {
	case *corev1.ConfigMap:
		return "ConfigMap"
	case *corev1.Service:
		return "Service"
	case *appsv1.Deployment:
		return "Deployment"
	case *appsv1.DaemonSet:
		return "DaemonSet"
	case *policyv1.PodDisruptionBudget:
		return "PodDisruptionBudget"
	default:
		return ""
	}
}

func (l *responderWriteLog) record(verb string, obj client.Object) {
	kind := countedResponderKind(obj)
	if kind == "" || obj.GetName() != l.name {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls[verb+"/"+kind]++
}

func (l *responderWriteLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = map[string]int{}
}

// entries renders the recorded calls as sorted "<verb>/<kind>=<count>" strings.
func (l *responderWriteLog) entries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.calls))
	for call, n := range l.calls {
		out = append(out, fmt.Sprintf("%s=%d", call, n))
	}
	slices.Sort(out)
	return out
}

// verbEntries is entries narrowed to one verb, for a test that pins only deletes.
func (l *responderWriteLog) verbEntries(verb string) []string {
	var out []string
	for _, e := range l.entries() {
		if strings.HasPrefix(e, verb+"/") {
			out = append(out, e)
		}
	}
	return out
}

// countingResponderClient rewires r's client to the operator identity through an interceptor
// recording every Patch and Delete of responder object componentName; patchErr may fail a Patch.
func countingResponderClient(t *testing.T, te *testEnv, r *GatewayReconciler, componentName string, patchErr func(obj client.Object) error) *responderWriteLog {
	t.Helper()
	wc, err := client.NewWithWatch(te.operatorCfg, client.Options{Scheme: te.scheme})
	if err != nil {
		t.Fatalf("build watch client: %v", err)
	}
	writes := &responderWriteLog{name: componentName, calls: map[string]int{}}
	r.Client = interceptor.NewClient(wc, interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if patchErr != nil {
				if err := patchErr(obj); err != nil {
					return err
				}
			}
			writes.record("Patch", obj)
			return c.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			writes.record("Delete", obj)
			return c.Delete(ctx, obj, opts...)
		},
	})
	return writes
}

// responderObjectsPresent reports whether gw's ConfigMap, Service, workload and, in the Cluster
// shape, its PDB are all readable through cl.
func responderObjectsPresent(ctx context.Context, cl client.Client, ns, workloadKind string) bool {
	key := client.ObjectKey{Namespace: ns, Name: "gw-responder"}
	objs := []client.Object{&corev1.ConfigMap{}, &corev1.Service{}}
	if workloadKind == "Deployment" {
		objs = append(objs, &appsv1.Deployment{}, &policyv1.PodDisruptionBudget{})
	} else {
		objs = append(objs, &appsv1.DaemonSet{})
	}
	for _, obj := range objs {
		if err := cl.Get(ctx, key, obj); err != nil {
			return false
		}
	}
	return true
}

// responderWriteStep is one Gateway spec edit in the steady-write table together with the exact
// set of responder writes the reconcile following it must issue.
type responderWriteStep struct {
	name        string
	mutate      func(gw *wgnetv1alpha1.Gateway)
	wantEntries []string
}

// responderSteadyTimeout bounds the wait for a fresh Gateway's responder objects to exist.
const responderSteadyTimeout = 30 * time.Second

// TestEnsureGatewayResponderSteadyWrites pins the write gate in both shapes: a reconcile that
// changes nothing issues no responder write, and a spec edit patches only the workload.
func TestEnsureGatewayResponderSteadyWrites(t *testing.T) {
	tests := []struct {
		name      string
		policy    wgnetv1alpha1.TrafficPolicy
		workload  string
		wantDirty []string
		steps     []responderWriteStep
	}{
		{
			name:     "cluster",
			policy:   wgnetv1alpha1.TrafficPolicyCluster,
			workload: "Deployment",
			wantDirty: []string{
				"Patch/ConfigMap=1", "Patch/Deployment=1", "Patch/PodDisruptionBudget=1", "Patch/Service=1",
			},
			steps: []responderWriteStep{
				{
					name:        "replicas",
					mutate:      func(gw *wgnetv1alpha1.Gateway) { gw.Spec.Responder.Replicas = 3 },
					wantEntries: []string{"Patch/Deployment=1"},
				},
				{
					name: "image",
					mutate: func(gw *wgnetv1alpha1.Gateway) {
						gw.Spec.Responder.Image = "registry.example.com/custom-responder:v2"
					},
					wantEntries: []string{"Patch/Deployment=1"},
				},
			},
		},
		{
			name:      "local",
			policy:    wgnetv1alpha1.TrafficPolicyLocal,
			workload:  "DaemonSet",
			wantDirty: []string{"Patch/ConfigMap=1", "Patch/DaemonSet=1", "Patch/Service=1"},
			steps: []responderWriteStep{
				{
					name: "image",
					mutate: func(gw *wgnetv1alpha1.Gateway) {
						gw.Spec.Responder.Image = "registry.example.com/custom-responder:v2"
					},
					wantEntries: []string{"Patch/DaemonSet=1"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			te := setupEnvtestRBAC(t)

			r, key := linkGatewayFixture(ctx, t, te, "responder-steady-"+tt.name, tt.policy)
			writes := countingResponderClient(t, te, r, "gw-responder", nil)
			req := ctrl.Request{NamespacedName: key}

			pollUntil(ctx, t, responderSteadyTimeout, "gw's responder objects to exist", func() bool {
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatalf("reconcile: %v", err)
				}
				return responderObjectsPresent(ctx, r.Client, key.Namespace, tt.workload)
			})

			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("steady reconcile: %v", err)
			}
			if got := writes.entries(); len(got) != 0 {
				t.Errorf("steady reconcile responder writes = %v, want exactly []", got)
			}

			r.responderDirty.mark(key)
			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("dirty reconcile: %v", err)
			}
			if got := writes.entries(); !slices.Equal(got, tt.wantDirty) {
				t.Errorf("dirty reconcile responder writes = %v, want exactly %v", got, tt.wantDirty)
			}

			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("reconcile after the dirty pass: %v", err)
			}
			if got := writes.entries(); len(got) != 0 {
				t.Errorf("responder writes after the dirty pass = %v, want exactly []", got)
			}

			for _, step := range tt.steps {
				var gw wgnetv1alpha1.Gateway
				mustGet(ctx, t, te.client, key, &gw)
				step.mutate(&gw)
				if err := te.client.Update(ctx, &gw); err != nil {
					t.Fatalf("%s: update gateway: %v", step.name, err)
				}

				writes.reset()
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatalf("%s: reconcile: %v", step.name, err)
				}
				if got := writes.entries(); !slices.Equal(got, step.wantEntries) {
					t.Errorf("%s: responder writes = %v, want exactly %v", step.name, got, step.wantEntries)
				}
			}
		})
	}
}

// TestResponderDirty table-tests the per-Gateway dirty flag: an unseen key forces one apply, a
// mark forces the next pass only, and forgetting a key returns it to unseen.
func TestResponderDirty(t *testing.T) {
	key := types.NamespacedName{Namespace: "wg-system", Name: "edge"}
	tests := []struct {
		name  string
		setup func(r *GatewayReconciler)
		want  []bool
	}{
		{
			name: "unseen key",
			want: []bool{true, false},
		},
		{
			name:  "seen and clean",
			setup: func(r *GatewayReconciler) { r.responderDirty.take(key) },
			want:  []bool{false, false},
		},
		{
			name: "marked after a take",
			setup: func(r *GatewayReconciler) {
				r.responderDirty.take(key)
				r.responderDirty.mark(key)
			},
			want: []bool{true, false},
		},
		{
			name: "forgotten after a take",
			setup: func(r *GatewayReconciler) {
				r.responderDirty.take(key)
				r.responderDirty.forget(key)
			},
			want: []bool{true, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GatewayReconciler{}
			if tt.setup != nil {
				tt.setup(r)
			}
			got := []bool{r.responderDirty.take(key), r.responderDirty.take(key)}
			if !slices.Equal(got, tt.want) {
				t.Errorf("successive takes = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGatewaysForResponderObject table-tests the responder-object mapper: only a Gateway
// controller reference yields a request, and that request's Gateway is marked dirty.
func TestGatewaysForResponderObject(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.UID = testGatewayUID
	key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
	gatewayRef := metav1.OwnerReference{
		APIVersion: wgnetv1alpha1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       gw.Name,
		UID:        gw.UID,
		Controller: new(true),
	}
	daemonSetRef := metav1.OwnerReference{
		APIVersion: appsv1.SchemeGroupVersion.String(),
		Kind:       "DaemonSet",
		Name:       "gw-responder",
		UID:        "22223333-4444-5555-6666-777788889999",
		Controller: new(true),
	}
	foreignGatewayRef := metav1.OwnerReference{
		APIVersion: "gateway.networking.k8s.io/v1",
		Kind:       "Gateway",
		Name:       gw.Name,
		UID:        "33334444-5555-6666-7777-888899990000",
		Controller: new(true),
	}

	tests := []struct {
		name         string
		refs         []metav1.OwnerReference
		wantRequests []reconcile.Request
		wantDirty    bool
	}{
		{
			name:         "gateway controller reference",
			refs:         []metav1.OwnerReference{gatewayRef},
			wantRequests: []reconcile.Request{{NamespacedName: key}},
			wantDirty:    true,
		},
		{
			name: "no owner reference",
		},
		{
			name: "controller reference of another kind",
			refs: []metav1.OwnerReference{daemonSetRef},
		},
		{
			name: "gateway controller reference of another api group",
			refs: []metav1.OwnerReference{foreignGatewayRef},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GatewayReconciler{}
			// Take once so the key is seen and clean: a mark by the mapper is then observable.
			r.responderDirty.take(key)

			obj := buildResponderService(gw)
			obj.OwnerReferences = tt.refs

			got := r.gatewaysForResponderObject(context.Background(), obj)
			if !slices.Equal(got, tt.wantRequests) {
				t.Errorf("requests = %v, want exactly %v", got, tt.wantRequests)
			}
			if dirty := r.responderDirty.take(key); dirty != tt.wantDirty {
				t.Errorf("gateway %s dirty = %v, want %v", key, dirty, tt.wantDirty)
			}
		})
	}
}

// TestIsResponderObject table-tests the responder-object predicate, including the drifted-label
// case: an edit that overwrites the component label must still reach the reconciler.
func TestIsResponderObject(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.UID = testGatewayUID
	gatewayRef := metav1.OwnerReference{
		APIVersion: wgnetv1alpha1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       gw.Name,
		UID:        gw.UID,
		Controller: new(true),
	}

	tests := []struct {
		name  string
		build func() client.Object
		want  bool
	}{
		{
			name:  "component label",
			build: func() client.Object { return buildResponderService(gw) },
			want:  true,
		},
		{
			name: "drifted label under the gateway's responder name",
			build: func() client.Object {
				svc := buildResponderService(gw)
				svc.Labels["app.kubernetes.io/component"] = "drifted"
				svc.OwnerReferences = []metav1.OwnerReference{gatewayRef}
				return svc
			},
			want: true,
		},
		{
			name: "drifted label under another name",
			build: func() client.Object {
				svc := buildResponderService(gw)
				svc.Name = "edge-link"
				svc.Labels["app.kubernetes.io/component"] = "drifted"
				svc.OwnerReferences = []metav1.OwnerReference{gatewayRef}
				return svc
			},
		},
		{
			name: "drifted label with no controller reference",
			build: func() client.Object {
				svc := buildResponderService(gw)
				svc.Labels["app.kubernetes.io/component"] = "drifted"
				return svc
			},
		},
		{
			name: "gateway controller reference of another api group",
			build: func() client.Object {
				svc := buildResponderService(gw)
				delete(svc.Labels, "app.kubernetes.io/component")
				svc.OwnerReferences = []metav1.OwnerReference{{
					APIVersion: "gateway.networking.k8s.io/v1",
					Kind:       "Gateway",
					Name:       gw.Name,
					UID:        "33334444-5555-6666-7777-888899990000",
					Controller: new(true),
				}}
				return svc
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isResponderObject(tt.build()); got != tt.want {
				t.Errorf("isResponderObject = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestResponderWorkloadPredicate table-tests the Deployment, DaemonSet and PDB watch predicate:
// a status-only write is dropped, while spec, label and annotation drift still reaches the queue.
func TestResponderWorkloadPredicate(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.UID = testGatewayUID
	gatewayRef := metav1.OwnerReference{
		APIVersion: wgnetv1alpha1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       gw.Name,
		UID:        gw.UID,
		Controller: new(true),
	}
	responderDeployment := func() *appsv1.Deployment {
		dep := buildResponderDeployment(testConfig(), gw)
		dep.Generation = 3
		dep.ResourceVersion = "100"
		dep.Annotations = map[string]string{responderHashAnnotation: "cafe"}
		dep.OwnerReferences = []metav1.OwnerReference{gatewayRef}
		return dep
	}
	foreignDeployment := func() *appsv1.Deployment {
		dep := responderDeployment()
		dep.Labels = nil
		dep.OwnerReferences = nil
		return dep
	}
	updated := func(build func() *appsv1.Deployment, mutate func(dep *appsv1.Deployment)) event.UpdateEvent {
		old := build()
		next := build()
		next.ResourceVersion = "101"
		mutate(next)
		return event.UpdateEvent{ObjectOld: old, ObjectNew: next}
	}

	tests := []struct {
		name string
		eval func(p predicate.Predicate) bool
		want bool
	}{
		{
			name: "status-only update",
			eval: func(p predicate.Predicate) bool {
				return p.Update(updated(responderDeployment, func(dep *appsv1.Deployment) {
					dep.Status.ReadyReplicas = 2
				}))
			},
		},
		{
			name: "generation bumped",
			eval: func(p predicate.Predicate) bool {
				return p.Update(updated(responderDeployment, func(dep *appsv1.Deployment) { dep.Generation = 4 }))
			},
			want: true,
		},
		{
			name: "label changed",
			eval: func(p predicate.Predicate) bool {
				return p.Update(updated(responderDeployment, func(dep *appsv1.Deployment) {
					dep.Labels["app.kubernetes.io/component"] = "drifted"
				}))
			},
			want: true,
		},
		{
			name: "annotation changed",
			eval: func(p predicate.Predicate) bool {
				return p.Update(updated(responderDeployment, func(dep *appsv1.Deployment) {
					dep.Annotations[responderHashAnnotation] = "beef"
				}))
			},
			want: true,
		},
		{
			name: "create",
			eval: func(p predicate.Predicate) bool {
				return p.Create(event.CreateEvent{Object: responderDeployment()})
			},
			want: true,
		},
		{
			name: "delete",
			eval: func(p predicate.Predicate) bool {
				return p.Delete(event.DeleteEvent{Object: responderDeployment()})
			},
			want: true,
		},
		{
			name: "generation bumped on a foreign deployment",
			eval: func(p predicate.Predicate) bool {
				return p.Update(updated(foreignDeployment, func(dep *appsv1.Deployment) { dep.Generation = 4 }))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.eval(responderWorkloadPredicate()); got != tt.want {
				t.Errorf("responderWorkloadPredicate = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEnsureGatewayResponderDirtyKeptOnError pins that an apply failing mid-pass keeps the
// Gateway dirty, so the retry force-applies every responder object rather than trusting the hash.
func TestEnsureGatewayResponderDirtyKeptOnError(t *testing.T) {
	tests := []struct {
		name       string
		policy     wgnetv1alpha1.TrafficPolicy
		workload   string
		wantForced []string
	}{
		{
			name:     "cluster",
			policy:   wgnetv1alpha1.TrafficPolicyCluster,
			workload: "Deployment",
			wantForced: []string{
				"Patch/ConfigMap=1", "Patch/Deployment=1", "Patch/PodDisruptionBudget=1", "Patch/Service=1",
			},
		},
		{
			name:       "local",
			policy:     wgnetv1alpha1.TrafficPolicyLocal,
			workload:   "DaemonSet",
			wantForced: []string{"Patch/ConfigMap=1", "Patch/DaemonSet=1", "Patch/Service=1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			te := setupEnvtestRBAC(t)

			r, key := linkGatewayFixture(ctx, t, te, "responder-dirty-error-"+tt.name, tt.policy)
			var failService atomic.Bool
			writes := countingResponderClient(t, te, r, "gw-responder", func(obj client.Object) error {
				if _, ok := obj.(*corev1.Service); ok && obj.GetName() == "gw-responder" && failService.Load() {
					return fmt.Errorf("synthetic responder service apply failure")
				}
				return nil
			})
			req := ctrl.Request{NamespacedName: key}

			pollUntil(ctx, t, responderSteadyTimeout, "gw's responder objects to exist", func() bool {
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatalf("reconcile: %v", err)
				}
				return responderObjectsPresent(ctx, r.Client, key.Namespace, tt.workload)
			})

			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("steady reconcile: %v", err)
			}
			if got := writes.entries(); len(got) != 0 {
				t.Errorf("steady reconcile responder writes = %v, want exactly []", got)
			}

			r.responderDirty.mark(key)
			failService.Store(true)
			if _, err := r.Reconcile(ctx, req); err == nil {
				t.Fatal("reconcile with a failing responder service apply = nil, want an error")
			}
			if dirty := r.responderDirty.take(key); !dirty {
				t.Errorf("gateway %s dirty after the failed pass = false, want true", key)
			}
			r.responderDirty.mark(key)

			failService.Store(false)
			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("reconcile after clearing the failure: %v", err)
			}
			if got := writes.entries(); !slices.Equal(got, tt.wantForced) {
				t.Errorf("retry responder writes = %v, want exactly %v", got, tt.wantForced)
			}

			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("reconcile after the retry: %v", err)
			}
			if got := writes.entries(); len(got) != 0 {
				t.Errorf("responder writes after the retry = %v, want exactly []", got)
			}
		})
	}
}
