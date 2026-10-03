package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpmembers"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// gatewayFinalizer holds Gateway deletion until Crossplane has drained the cloud
// resources. The other children are reaped by owner-ref GC.
const gatewayFinalizer = "wgnet.dev/gateway-teardown"

// fieldOwner is the server-side-apply field manager for every applied object; a stable
// name keeps the operator from fighting Crossplane over defaulted fields.
const fieldOwner = client.FieldOwner("gateway-operator")

const (
	conditionReady        = "Ready"
	reasonProvisioning    = "Provisioning"
	reasonReady           = "Ready"
	reasonReconcileFailed = "ReconcileFailed"
	reasonTerminating     = "Terminating"
	// actionReconcile is the action verb on emitted failure events. The events API
	// requires an UpperCamelCase action describing what the controller was doing.
	actionReconcile = "Reconcile"
	// GCP-fleet Ready=False reasons.
	reasonInvalidTunnelAddresses      = "InvalidTunnelAddresses"
	reasonInsufficientTunnelAddresses = "InsufficientTunnelAddresses"
	reasonMemberDiscoveryFailed       = "MemberDiscoveryFailed"
	reasonMembersNotReady             = "MembersNotReady"
)

// validationRequeueAfter is the transient backoff before re-checking an absent backend,
// kept separate from RequeueInterval (zero in tests) so it cannot spin a hot loop.
const validationRequeueAfter = 10 * time.Second

// Poll before steady state so the Lease tunnel annotation is observed soon after PodReady.
// The controller does not watch Leases.
const tunnelReadyPollInterval = 3 * time.Second

// KeyGenerator produces a WireGuard keypair. It is injected so tests can supply
// deterministic key material; production binds it to wg.GenerateKeypair.
type KeyGenerator func() (privateKey, publicKey string, err error)

// GatewayReconciler reconciles a Gateway into its XGatewayGCP composite, key Secrets,
// the link workload with its RBAC and NetworkPolicy, and an optional DNSEndpoint, then
// mirrors the composite's observed status back onto the Gateway.
type GatewayReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Config   Config
	Recorder events.EventRecorder

	// APIReader bypasses the manager cache for objects it never tracks: the shared
	// XGatewayNetwork, link Leases and holder pods. SetupWithManager binds it.
	APIReader client.Reader

	// GenerateKey supplies WireGuard keypairs. Nil defaults to wg.GenerateKeypair.
	GenerateKey KeyGenerator

	// unresolvedWarned maps a Gateway UID to the last warned unresolved-backend-port signature,
	// suppressing an identical Warning every requeue. In-memory: a restart warns once more.
	unresolvedWarned sync.Map

	// gcpCreds shares a client until its operator-wide credential bytes change.
	gcpCreds gcpCredentialCache

	gcpAddressRefreshed sync.Map
	now                 func() time.Time

	// responderDirty and linkDirty carry the per-Gateway re-apply flag for their component's
	// objects, so drift that leaves the hash unchanged is still corrected.
	responderDirty dirtyTracker
	linkDirty      dirtyTracker
}

// dirtyTracker records, per Gateway, whether the next pass must re-apply every object of one
// component. It is in-memory: a key it has never seen counts as dirty.
type dirtyTracker struct {
	mu   sync.Mutex
	keys map[types.NamespacedName]bool
}

// mark forces the next reconcile of key to re-apply.
func (d *dirtyTracker) mark(key types.NamespacedName) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.keys == nil {
		d.keys = make(map[types.NamespacedName]bool)
	}
	d.keys[key] = true
}

// take reports whether key is dirty or unseen, and clears the flag. Unseen counts as dirty so
// the first pass after an operator restart re-applies once.
func (d *dirtyTracker) take(key types.NamespacedName) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.keys == nil {
		d.keys = make(map[types.NamespacedName]bool)
	}
	dirty, seen := d.keys[key]
	d.keys[key] = false
	return dirty || !seen
}

// forget drops key's entry, returning it to unseen.
func (d *dirtyTracker) forget(key types.NamespacedName) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.keys, key)
}

// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaygcps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaygcps/status,verbs=get
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaynetworks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaynetworks/status,verbs=get
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=secretmanager.gcp.m.upbound.io,resources=secrets;secretversions;secretiammembers,verbs=get
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=bind,resourceNames=gateway-link-endpointslice-reader
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=externaldns.k8s.io,resources=dnsendpoints,verbs=create;get;patch;update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile exposes exactly the valid forward subset and never provisions while every
// forward is invalid, but once provisioned keeps its VM through a backend outage.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var gw wgnetv1alpha1.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		if apierrors.IsNotFound(err) {
			r.responderDirty.forget(req.NamespacedName)
			r.linkDirty.forget(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !gw.DeletionTimestamp.IsZero() {
		r.responderDirty.forget(req.NamespacedName)
		r.linkDirty.forget(req.NamespacedName)
		return r.reconcileDelete(ctx, &gw)
	}

	if !controllerutil.ContainsFinalizer(&gw, gatewayFinalizer) {
		controllerutil.AddFinalizer(&gw, gatewayFinalizer)
		if err := r.Update(ctx, &gw); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	eligibleAddresses, tunnelOK, tunnelReason := tunnelAddresses(
		effectiveWGSubnet(&gw), effectiveWGGatewayAddress(&gw), effectiveWGLinkAddress(&gw))
	if !tunnelOK {
		r.warnInvalidTunnelAddresses(&gw, tunnelReason)
		if serr := r.mirrorStatusWithForwards(ctx, &gw, "", "", linkStatus{},
			readySignals{InvalidTunnelAddresses: true, InvalidTunnelMessage: tunnelReason}, nil, nil); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mirror status: %w", serr)
		}
		logger.V(1).Info("gateway not provisioned: invalid tunnel addresses", "reason", tunnelReason)
		return ctrl.Result{RequeueAfter: validationRequeueAfter}, nil
	}
	// Suppression covers a repeat of an unchanged state: once validation passes, the same
	// reason recurring later warns again.
	r.unresolvedWarned.Delete(invalidTunnelWarnKeyPrefix + unresolvedWarnKey(&gw))

	valid, invalid, err := r.classifyForwards(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "classify forwards", err)
	}

	provisioned, err := r.xgatewayGCPExists(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "check xgatewaygcp existence", err)
	}

	if err := r.ensureLinkID(ctx, &gw); err != nil {
		if errors.Is(err, errNoFreeLinkID) {
			return r.failReported(ctx, &gw, "allocate link id", err)
		}
		return r.fail(ctx, &gw, "allocate link id", err)
	}

	// Health-port validation requires the allocated local link ID.
	valid, invalid, rejectedOnHealthPort := rejectReservedHealthPort(&gw, valid, invalid)
	r.warnReservedHealthPort(&gw, rejectedOnHealthPort)

	// Provision only when validation leaves at least one usable forward.
	if len(valid) == 0 && !provisioned {
		// Read the link the healthy path's way: it may still hold its Lease and serve
		// the last applied config, and status.link must not blink on this pass.
		ls, lerr := r.linkStatusOf(ctx, &gw)
		if lerr != nil {
			return r.fail(ctx, &gw, "read link activity", lerr)
		}
		if serr := r.mirrorStatusWithForwards(ctx, &gw, "", "", ls,
			readySignals{InvalidForward: firstInvalidForward(invalid)}, nil, nil); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mirror status: %w", serr)
		}
		result := ctrl.Result{}
		if anyTransientReason(invalid) {
			result.RequeueAfter = validationRequeueAfter
		}
		logger.V(1).Info("gateway not provisioned: no valid forwards", "invalid", len(invalid))
		return result, nil
	}

	loadBalanced := gw.Spec.GCP.LoadBalancer != nil
	healthPort := effectiveHealthPort(&gw)

	// Read observed names before apply because roster rendering depends on them.
	observed, err := r.readXGatewayGCPStatus(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read xgatewaygcp status", err)
	}
	address, saEmail, message := observed.Address, observed.ServiceAccountEmail, observed.Message

	// Capacity decides before anything is written: over the bound no secret, no shared
	// network and no composite is touched this pass.
	if limit := capacity(effectiveWGSubnet(&gw)); loadBalanced && int(gw.Spec.GCP.Replicas) > limit {
		capacityMessage := fmt.Sprintf("spec.gcp.replicas %d exceeds capacity %d of spec.wireguard.subnet",
			gw.Spec.GCP.Replicas, limit)
		r.warnInsufficientTunnelAddresses(&gw, capacityMessage)
		if aerr := r.applyOverCapacityXGatewayGCP(ctx, &gw, forwardSpecs(valid), healthPort); aerr != nil {
			return r.fail(ctx, &gw, "ensure xgatewaygcp", aerr)
		}
		ls, lerr := r.linkStatusOf(ctx, &gw)
		if lerr != nil {
			return r.fail(ctx, &gw, "read link activity", lerr)
		}
		if serr := r.mirrorStatusWithForwards(ctx, &gw, address, saEmail, ls, readySignals{
			InvalidForward:       firstInvalidForward(invalid),
			LinkFaultReason:      ls.FaultReason,
			LinkFaultMessage:     ls.FaultMessage,
			LoadBalanced:         true,
			InsufficientCapacity: true,
			CapacityMessage:      capacityMessage,
			ProvisionMessage:     message,
		}, nil, nil); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mirror status: %w", serr)
		}
		logger.V(1).Info("gateway not provisioned: insufficient tunnel addresses",
			"replicas", gw.Spec.GCP.Replicas, "capacity", limit)
		return ctrl.Result{RequeueAfter: r.steadyRequeue(loadBalanced)}, nil
	}
	// As with the tunnel-address warning: a pass that fits releases the suppression.
	r.unresolvedWarned.Delete(capacityWarnKeyPrefix + unresolvedWarnKey(&gw))

	if err := r.ensureSecrets(ctx, &gw); err != nil {
		return r.fail(ctx, &gw, "ensure key secrets", err)
	}
	if err := r.ensureXGatewayNetwork(ctx); err != nil {
		return r.fail(ctx, &gw, "ensure shared network", err)
	}

	var result *gcpmembers.Result
	var discoveryFailed bool
	var discoveryMessage string
	if loadBalanced {
		result, discoveryFailed, discoveryMessage, err = r.reconcileMembers(ctx, &gw, observed.MIGName, eligibleAddresses)
		if err != nil {
			return r.fail(ctx, &gw, "reconcile gcp members", err)
		}
	} else {
		result, err = r.reconcileSingleMember(ctx, &gw, observed.InstanceName)
		if err != nil {
			return r.fail(ctx, &gw, "reconcile single instance member", err)
		}
	}

	if err := r.ensureXGatewayGCP(ctx, &gw, forwardSpecs(valid), loadBalanced, result, healthPort); err != nil {
		return r.fail(ctx, &gw, "ensure xgatewaygcp", err)
	}

	var fleetPeers []link.Peer
	switch {
	case loadBalanced && result != nil && !result.Unusable:
		fleetPeers = fleetLinkPeers(&gw, fillPeerListenPort(result.Peers, int(effectiveWireguardPort(&gw))))
	case loadBalanced:
		// A pass with no usable snapshot publishes no membership: keep the peers the last
		// usable pass applied rather than unpeering a live fleet.
		fleetPeers, err = r.appliedLinkPeers(ctx, &gw)
		if err != nil {
			return r.fail(ctx, &gw, "read applied link peers", err)
		}
	}

	var gatewayPublicKey string
	if !loadBalanced {
		gatewayPublicKey, err = r.readLinkPeerPublicKey(ctx, &gw)
		if err != nil {
			return r.fail(ctx, &gw, "read link peer public key", err)
		}
	}

	responderClusterIP, err := r.ensureGatewayResponder(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "ensure responder", err)
	}

	ident := linkIdentityOf(&gw)
	responders, err := r.responderPods(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "list responder pods", err)
	}

	var responderMissing []string
	if isLocal(&gw) {
		var linkPods corev1.PodList
		if err := r.List(ctx, &linkPods, client.InNamespace(gw.Namespace), client.MatchingLabels(linkSelectorLabels(&gw))); err != nil {
			return r.fail(ctx, &gw, "list link pods", err)
		}
		responderMissing = responderMissingNodes(linkPods.Items, responders)
	}
	responderStatus := &responderMissingStatus{
		local:   isLocal(&gw),
		missing: responderMissing,
		present: len(responders) > 0,
	}
	r.warnResponderMissing(&gw, responderStatus)

	if err := r.ensureLink(ctx, &gw, address, valid, ident, gatewayPublicKey, fleetPeers, healthPort, responders, responderClusterIP); err != nil {
		return r.fail(ctx, &gw, "ensure link", err)
	}

	if err := r.ensureDNSEndpoint(ctx, &gw, address); err != nil {
		return r.fail(ctx, &gw, "ensure dns endpoint", err)
	}

	ls, err := r.linkStatusOf(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read link activity", err)
	}

	ready := address != "" && ls.Active
	provisionAddress := ""
	if ready {
		provisionAddress = address
	}

	signals := readySignals{
		InvalidForward:   firstInvalidForward(invalid),
		LinkFaultReason:  ls.FaultReason,
		LinkFaultMessage: ls.FaultMessage,
		LoadBalanced:     loadBalanced,
		DiscoveryFailed:  discoveryFailed,
		DiscoveryMessage: discoveryMessage,
		PeerCount:        len(fleetPeers),
		MembersNotReady:  loadBalanced && !ls.Active,
		ProvisionAddress: provisionAddress,
		ProvisionMessage: message,
	}
	// status.gcp.members mirrors a fleet: the single-Instance branch's own record is
	// published through the composite roster and carries no membership status.
	var membersResult *gcpmembers.Result
	if loadBalanced {
		membersResult = result
	}
	if err := r.mirrorStatusWithForwards(ctx, &gw, address, saEmail, ls, signals, membersResult, responderStatus); err != nil {
		return ctrl.Result{}, fmt.Errorf("mirror status: %w", err)
	}

	// Transient invalid forwards requeue on the transient floor, independent of the
	// steady-state poll (which may be zero in tests).
	reconcileResult := ctrl.Result{RequeueAfter: r.steadyRequeue(loadBalanced)}
	if anyTransientReason(invalid) {
		reconcileResult.RequeueAfter = validationRequeueAfter
	}
	// Poll before steady state so the Lease tunnel annotation is observed soon after PodReady.
	// The controller does not watch Leases.
	if ls.PodReady && !ls.Active {
		reconcileResult.RequeueAfter = tunnelReadyPollInterval
	}

	logger.V(1).Info("reconciled gateway",
		"address", address, "linkActive", ls.Active, "activeNode", ls.Node, "linkFault", ls.FaultReason, "ready", ready,
		"valid", len(valid), "invalid", len(invalid))
	return reconcileResult, nil
}

// reconcileDelete waits for the XGatewayGCP to disappear before releasing the finalizer,
// so Crossplane drains GCP while the namespace still lives.
func (r *GatewayReconciler) reconcileDelete(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(gw, gatewayFinalizer) {
		return ctrl.Result{}, nil
	}

	xg := newXGatewayGCP()
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg)
	switch {
	case apierrors.IsNotFound(err):
		return r.releaseAfterSharedNetwork(ctx, gw)
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get xgatewaygcp for deletion: %w", err)
	}

	if xg.GetDeletionTimestamp().IsZero() {
		if err := r.Delete(ctx, xg); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete xgatewaygcp: %w", err)
		}
	}

	if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonTerminating,
		Message:            "waiting for xgatewaygcp to finish draining cloud resources",
		ObservedGeneration: gw.Generation,
	}); changed {
		if err := r.Status().Update(ctx, gw); err != nil {
			return ctrl.Result{}, fmt.Errorf("update gateway status: %w", err)
		}
	}

	return ctrl.Result{RequeueAfter: validationRequeueAfter}, nil
}

// releaseAfterSharedNetwork refcounts the shared VPC: it releases the finalizer at once
// while any Gateway remains, and on the last delete holds until the network is gone.
func (r *GatewayReconciler) releaseAfterSharedNetwork(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.APIReader.List(ctx, &gateways); err != nil {
		return ctrl.Result{}, fmt.Errorf("list gateways for shared-network refcount: %w", err)
	}

	remaining := 0
	for i := range gateways.Items {
		if gateways.Items[i].DeletionTimestamp.IsZero() {
			remaining++
		}
	}

	if remaining > 0 {
		return r.releaseFinalizer(ctx, gw)
	}

	net := newXGatewayNetwork()
	err := r.APIReader.Get(ctx, client.ObjectKey{Name: r.Config.SharedNetworkName, Namespace: r.Config.PodNamespace}, net)
	switch {
	case apierrors.IsNotFound(err):
		return r.releaseFinalizer(ctx, gw)
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get shared network for deletion: %w", err)
	}

	if net.GetDeletionTimestamp().IsZero() {
		if err := r.Delete(ctx, net); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete shared network: %w", err)
		}
		if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonTerminating,
			Message:            "waiting for shared network to finish draining cloud resources",
			ObservedGeneration: gw.Generation,
		}); changed {
			if err := r.Status().Update(ctx, gw); err != nil {
				return ctrl.Result{}, fmt.Errorf("update gateway status: %w", err)
			}
		}
	}

	return ctrl.Result{RequeueAfter: validationRequeueAfter}, nil
}

// Deletes the link workload before the Lease and ClusterRoleBinding: nothing owner-reaps the Lease
// and a live elector re-creates it. The pod wait is bounded so one stuck Terminating cannot strand.
func (r *GatewayReconciler) releaseFinalizer(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	objMeta := metav1.ObjectMeta{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	var workload client.Object = &appsv1.Deployment{ObjectMeta: objMeta}
	if isLocal(gw) {
		workload = &appsv1.DaemonSet{ObjectMeta: objMeta}
	}
	if err := r.deleteIfPresent(ctx, workload, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
		return ctrl.Result{}, err
	}

	var pods corev1.PodList
	if err := r.APIReader.List(ctx, &pods,
		client.InNamespace(gw.Namespace), client.MatchingLabels(linkSelectorLabels(gw))); err != nil {
		return ctrl.Result{}, fmt.Errorf("list link pods for teardown: %w", err)
	}
	holding, stuck := partitionTerminatingLinkPods(pods.Items)
	if len(stuck) > 0 {
		log.FromContext(ctx).Info("proceeding with link teardown past pods stuck terminating",
			"pods", stuck, "reason", "deletionTimestamp older than the pod grace period plus slack",
			"slack", linkTeardownSlack.String())
	}
	if len(holding) > 0 {
		if err := r.markTerminatingOnLinkPods(ctx, gw, holding); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: linkTeardownRequeueAfter}, nil
	}

	if err := r.deleteLinkLease(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}
	// Unconditional: it tolerates a NotFound, so a mode that never created one is a no-op here.
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: linkClusterRoleBindingName(gw)}}
	if err := r.deleteIfPresent(ctx, crb); err != nil {
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(gw, gatewayFinalizer)
	if err := r.Update(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	r.dropWarnSuppression(gw)
	r.gcpAddressRefreshed.Delete(gatewayRefreshKey(gw))
	return ctrl.Result{}, nil
}

// dropWarnSuppression clears the suppression entries the Gateway being deleted owns, so a
// Gateway re-created under the same name warns again on the same condition.
func (r *GatewayReconciler) dropWarnSuppression(gw *wgnetv1alpha1.Gateway) {
	key := unresolvedWarnKey(gw)
	r.unresolvedWarned.Delete(key)
	r.unresolvedWarned.Delete(blockedCleanupWarnKeyPrefix + key)
	r.unresolvedWarned.Delete(invalidTunnelWarnKeyPrefix + key)
	r.unresolvedWarned.Delete(capacityWarnKeyPrefix + key)
	r.unresolvedWarned.Delete(reservedHealthPortWarnKeyPrefix + key)
	r.unresolvedWarned.Delete(responderMissingWarnKeyPrefix + key)
}

// unresolvedWarnKey identifies a Gateway instance for unresolvedWarned, carrying the UID
// so a recreated same-named Gateway does not inherit its predecessor's suppression.
func unresolvedWarnKey(gw *wgnetv1alpha1.Gateway) string {
	return client.ObjectKeyFromObject(gw).String() + "/" + string(gw.UID)
}

// linkTeardownRequeueAfter paces the wait for the link pods to exit. Nothing watches
// those pods, so this requeue timer is the only trigger that re-checks them.
const linkTeardownRequeueAfter = 2 * time.Second

// linkTeardownSlack pads each pod's grace period before teardown stops waiting on it. A pod on a
// partitioned node stays Terminating until its Node goes away. Var so tests can shorten it.
var linkTeardownSlack = 30 * time.Second

// deleteIfPresent deletes obj, tolerating a NotFound. opts carries whatever delete semantics
// the caller's object needs (for example a propagation policy); a caller with none passes none.
func (r *GatewayReconciler) deleteIfPresent(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if err := r.Delete(ctx, obj, opts...); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %T %s/%s: %w", obj, obj.GetNamespace(), obj.GetName(), err)
	}
	return nil
}

// steadyRequeue is the steady-state poll: a load-balanced Gateway re-lists its fleet no more
// often than GCPDiscoveryInterval, every other Gateway keeps the general RequeueInterval.
func (r *GatewayReconciler) steadyRequeue(loadBalanced bool) time.Duration {
	if loadBalanced && r.Config.GCPDiscoveryInterval > r.Config.RequeueInterval {
		return r.Config.GCPDiscoveryInterval
	}
	return r.Config.RequeueInterval
}

// maxFaultMessageBytes bounds the Lease fault message copied into the Ready condition;
// the API rejects messages beyond 32768 characters, turning a fault into a write loop.
const maxFaultMessageBytes = 4096

const faultMessageTruncationMarker = "... (truncated)"

// truncateFaultMessage shortens msg to maxFaultMessageBytes, cutting on a rune boundary
// so the result stays valid UTF-8 and the API server accepts it.
func truncateFaultMessage(msg string) string {
	if len(msg) <= maxFaultMessageBytes {
		return msg
	}
	cut := maxFaultMessageBytes - len(faultMessageTruncationMarker)
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + faultMessageTruncationMarker
}

// readySignals holds the inputs to Ready-condition precedence.
type readySignals struct {
	InvalidTunnelAddresses bool
	InvalidTunnelMessage   string
	InvalidForward         *invalidForward // first invalid forward, nil when none
	LinkFaultReason        string
	LinkFaultMessage       string
	LoadBalanced           bool
	InsufficientCapacity   bool
	CapacityMessage        string
	DiscoveryFailed        bool
	DiscoveryMessage       string
	// PeerCount is how many peers this pass rendered into the link config. Read only when
	// loadBalanced: none means no fleet member has been observed yet.
	PeerCount        int
	MembersNotReady  bool // true only when loadBalanced and no member has a live session
	ProvisionAddress string
	ProvisionMessage string
}

// readyPrecedence returns the first applicable Ready-condition reason.
func readyPrecedence(in readySignals) (reason, message string, ready bool) {
	switch {
	case in.InvalidTunnelAddresses:
		return reasonInvalidTunnelAddresses, in.InvalidTunnelMessage, false
	case in.InvalidForward != nil:
		return in.InvalidForward.reason, in.InvalidForward.message, false
	case in.LinkFaultReason != "":
		return in.LinkFaultReason, in.LinkFaultMessage, false
	case in.LoadBalanced && in.InsufficientCapacity:
		return reasonInsufficientTunnelAddresses, in.CapacityMessage, false
	case in.DiscoveryFailed:
		return reasonMemberDiscoveryFailed, in.DiscoveryMessage, false
	case in.LoadBalanced && in.PeerCount == 0:
		return reasonMembersNotReady, "no fleet member observed yet", false
	case in.LoadBalanced && in.MembersNotReady:
		return reasonMembersNotReady, "no fleet member has a live wireguard session", false
	case in.ProvisionAddress != "":
		return reasonReady, "gateway address provisioned and active link tunnel up", true
	default:
		message = "waiting for gateway address and active link tunnel"
		if m := truncateFaultMessage(in.ProvisionMessage); m != "" {
			message += ": " + m
		}
		return reasonProvisioning, message, false
	}
}

// mirrorStatusWithForwards writes changed Gateway status while retaining unusable members. A nil
// responder skips writing the ResponderMissing condition, for a pass too early to know it.
func (r *GatewayReconciler) mirrorStatusWithForwards(ctx context.Context, gw *wgnetv1alpha1.Gateway, address, saEmail string, ls linkStatus, signals readySignals, result *gcpmembers.Result, responder *responderMissingStatus) error {
	reason, message, ready := readyPrecedence(signals)
	cond := metav1.Condition{Type: conditionReady, Reason: reason, Message: message}
	if ready {
		cond.Status = metav1.ConditionTrue
	} else {
		cond.Status = metav1.ConditionFalse
	}

	var responderCond *metav1.Condition
	if responder != nil {
		rc := responder.condition(gw)
		responderCond = &rc
	}

	// Re-read after SSA because its resourceVersion may be stale.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Use the uncached reader so a retry does not resubmit a stale object.
		reader := r.APIReader
		if reader == nil {
			reader = r.Client
		}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for status update: %w", err)
		}

		// A concurrent spec edit requires the fresh observed generation.
		cond.ObservedGeneration = fresh.Generation

		prevAddress := fresh.Status.Address
		prevSAEmail := fresh.Status.ServiceAccountEmail
		prevNode := fresh.Status.Link.ActiveNode
		fresh.Status.Address = address
		fresh.Status.ServiceAccountEmail = saEmail
		fresh.Status.Link.ActiveNode = ls.Node

		membersChanged := false
		if result != nil && !result.Unusable {
			membersChanged = !slices.EqualFunc(fresh.Status.GCP.Members, result.Members,
				func(a, b wgnetv1alpha1.GatewayGCPMemberStatus) bool { return a == b })
			fresh.Status.GCP.Members = result.Members
		}

		conditionChanged := meta.SetStatusCondition(&fresh.Status.Conditions, cond)
		responderChanged := false
		if responderCond != nil {
			responderCond.ObservedGeneration = fresh.Generation
			responderChanged = meta.SetStatusCondition(&fresh.Status.Conditions, *responderCond)
		}

		if prevAddress == address && prevSAEmail == saEmail && prevNode == ls.Node && !conditionChanged && !membersChanged && !responderChanged {
			return nil
		}

		if err := r.Status().Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway status: %w", err)
		}
		return nil
	})
}

// recordFailure emits the Warning and writes Ready=False for a reconcile failure,
// returning the wrapped cause and any status-write error.
func (r *GatewayReconciler) recordFailure(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (wrapped, statusErr error) {
	wrapped = fmt.Errorf("%s: %w", op, cause)
	if r.Recorder != nil {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonReconcileFailed, actionReconcile, "%s", wrapped.Error())
	}
	statusErr = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		reader := r.APIReader
		if reader == nil {
			reader = r.Client
		}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for status update: %w", err)
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonReconcileFailed,
			Message:            wrapped.Error(),
			ObservedGeneration: fresh.Generation,
		})
		return r.Status().Update(ctx, &fresh)
	})
	return wrapped, statusErr
}

// fail records the error on the Gateway's Ready condition and surfaces it so the
// manager requeues with backoff.
func (r *GatewayReconciler) fail(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (ctrl.Result, error) {
	wrapped, uerr := r.recordFailure(ctx, gw, op, cause)
	if uerr != nil {
		return ctrl.Result{}, fmt.Errorf("%w; additionally failed to update status: %w", wrapped, uerr)
	}
	return ctrl.Result{}, wrapped
}

// failReported records the error like fail but requeues on the regular interval instead
// of returning it, for causes retrying cannot resolve.
func (r *GatewayReconciler) failReported(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (ctrl.Result, error) {
	wrapped, uerr := r.recordFailure(ctx, gw, op, cause)
	if uerr != nil {
		return ctrl.Result{}, fmt.Errorf("%w; additionally failed to update status: %w", wrapped, uerr)
	}
	return ctrl.Result{RequeueAfter: r.Config.RequeueInterval}, nil
}

// objectExists reports whether the named object is present. probe is mutated by the Get;
// callers pass a fresh empty object of the desired kind.
func (r *GatewayReconciler) objectExists(ctx context.Context, namespace, name string, probe client.Object) (bool, error) {
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, probe)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get %s/%s: %w", namespace, name, err)
	}
	return true, nil
}

// objectHash returns the lowercase hex SHA-256 of obj's JSON encoding with gateAnnotation
// excluded, so the gate value never feeds itself. obj is not mutated.
func objectHash(obj client.Object, gateAnnotation string) (string, error) {
	clone, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return "", fmt.Errorf("deep copy of %T is not a client.Object", obj)
	}
	annotations := clone.GetAnnotations()
	delete(annotations, gateAnnotation)
	if len(annotations) == 0 {
		annotations = nil
	}
	clone.SetAnnotations(annotations)
	data, err := json.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("marshal %T: %w", obj, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// applyObjectIfChanged stamps desired's hash under gateAnnotation and applies only when live
// differs, reporting whether it applied; force applies always, owner is nil if cluster-scoped.
func (r *GatewayReconciler) applyObjectIfChanged(ctx context.Context, owner *wgnetv1alpha1.Gateway, gateAnnotation string, desired, live client.Object, force bool) (bool, error) {
	hash, err := objectHash(desired, gateAnnotation)
	if err != nil {
		return false, err
	}
	annotations := desired.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string, 1)
	}
	annotations[gateAnnotation] = hash
	desired.SetAnnotations(annotations)

	key := client.ObjectKeyFromObject(desired)
	switch err := r.Get(ctx, key, live); {
	case apierrors.IsNotFound(err):
	case err != nil:
		return false, fmt.Errorf("get %T %s: %w", live, key, err)
	case !force && live.GetAnnotations()[gateAnnotation] == hash:
		return false, nil
	}
	if err := r.apply(ctx, owner, desired); err != nil {
		return false, err
	}
	return true, nil
}

// apply server-side-applies desired, filling the GVK from the scheme because typed builders omit
// the TypeMeta SSA requires. A nil gw stamps no ownerReference, as cluster-scoped children need.
func (r *GatewayReconciler) apply(ctx context.Context, gw *wgnetv1alpha1.Gateway, desired client.Object) error {
	gvks, _, err := r.Scheme.ObjectKinds(desired)
	if err != nil {
		return fmt.Errorf("gvk for %T: %w", desired, err)
	}
	desired.GetObjectKind().SetGroupVersionKind(gvks[0])
	if gw != nil {
		if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
			return fmt.Errorf("set owner reference: %w", err)
		}
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal %T: %w", desired, err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply %T: %w", desired, err)
	}
	return nil
}

// SetupWithManager registers the reconciler. The XGatewayGCP watch omits
// GenerationChangedPredicate so its status-only address writes trigger a reconcile.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.APIReader = mgr.GetAPIReader()

	xg := &unstructured.Unstructured{}
	xg.SetGroupVersionKind(XGatewayGCPGVK)

	// genChanged filters NetworkPolicy, whose spec-only changes bump metadata.generation.
	genChanged := builder.WithPredicates(predicate.GenerationChangedPredicate{})

	responderObjectPredicate := builder.WithPredicates(predicate.NewPredicateFuncs(isResponderObject))
	responderWorkloadDrift := builder.WithPredicates(responderWorkloadPredicate())
	responderObjectEvents := handler.EnqueueRequestsFromMapFunc(r.gatewaysForResponderObject)

	linkObjectPredicate := builder.WithPredicates(predicate.NewPredicateFuncs(isLinkObject))
	linkWorkloadDrift := builder.WithPredicates(linkWorkloadPredicate())
	linkObjectEvents := handler.EnqueueRequestsFromMapFunc(r.gatewaysForLinkObject)

	return ctrl.NewControllerManagedBy(mgr).
		For(&wgnetv1alpha1.Gateway{}).
		// No predicate: the workload status event is the only push signal for pod readiness,
		// since pods and Leases are unwatched; ConfigMap/Secret/Service never bump metadata.generation.
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.Service{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Owns(&networkingv1.NetworkPolicy{}, genChanged).
		Owns(xg).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForService)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForNamespace)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForResponderPod),
			builder.WithPredicates(predicate.NewPredicateFuncs(isResponderObject))).
		// Drift on a responder object carries no hash change, so the owning Gateway is marked
		// dirty here and its next pass re-applies every object.
		Watches(&corev1.ConfigMap{}, responderObjectEvents, responderObjectPredicate).
		Watches(&corev1.Service{}, responderObjectEvents, responderObjectPredicate).
		Watches(&appsv1.Deployment{}, responderObjectEvents, responderWorkloadDrift).
		Watches(&appsv1.DaemonSet{}, responderObjectEvents, responderWorkloadDrift).
		Watches(&policyv1.PodDisruptionBudget{}, responderObjectEvents, responderWorkloadDrift).
		// The same drift signal for the link objects, including the three RBAC kinds and the
		// cluster-scoped binding, which no Owns covers.
		Watches(&corev1.ServiceAccount{}, linkObjectEvents, linkObjectPredicate).
		Watches(&rbacv1.Role{}, linkObjectEvents, linkObjectPredicate).
		Watches(&rbacv1.RoleBinding{}, linkObjectEvents, linkObjectPredicate).
		Watches(&rbacv1.ClusterRoleBinding{}, linkObjectEvents, linkObjectPredicate).
		Watches(&corev1.ConfigMap{}, linkObjectEvents, linkObjectPredicate).
		Watches(&appsv1.Deployment{}, linkObjectEvents, linkWorkloadDrift).
		Watches(&appsv1.DaemonSet{}, linkObjectEvents, linkWorkloadDrift).
		Watches(&networkingv1.NetworkPolicy{}, linkObjectEvents, linkWorkloadDrift).
		Watches(&policyv1.PodDisruptionBudget{}, linkObjectEvents, linkWorkloadDrift).
		Complete(r)
}

// gatewaysForService maps a changed Service to the Gateways forwarding to it, matching
// on effective namespace so cross-namespace forwards resolve.
func (r *GatewayReconciler) gatewaysForService(ctx context.Context, obj client.Object) []reconcile.Request {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		log.FromContext(ctx).Error(err, "list gateways for service watch", "service", client.ObjectKeyFromObject(obj))
		return nil
	}

	var requests []reconcile.Request
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		for _, f := range gw.Spec.Forwards {
			if f.Service == obj.GetName() && effectiveForwardNamespace(f, gw) == obj.GetNamespace() {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
				break
			}
		}
	}
	return requests
}

// gatewaysForNamespace maps a Namespace to the Gateways forwarding into it from elsewhere, so a
// consent-label edit re-classifies them. Same-namespace forwards need no consent.
func (r *GatewayReconciler) gatewaysForNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		log.FromContext(ctx).Error(err, "list gateways for namespace watch", "namespace", obj.GetName())
		return nil
	}

	var requests []reconcile.Request
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		for _, f := range gw.Spec.Forwards {
			ns := effectiveForwardNamespace(f, gw)
			if ns == obj.GetName() && ns != gw.Namespace {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
				break
			}
		}
	}
	return requests
}

// hashedName derives prefix + lowercase base32 of SHA-256 over "<namespace>/<name>",
// truncated to maxLen. The input is namespace-qualified so equal names do not collide.
func hashedName(prefix, namespace, name string, maxLen int) string {
	sum := sha256.Sum256([]byte(namespace + "/" + name))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	id := prefix + strings.ToLower(enc)
	if len(id) > maxLen {
		id = id[:maxLen]
	}
	return id
}

// commonLabels are the identifying labels stamped on every child object.
func commonLabels(gw *wgnetv1alpha1.Gateway, component string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "wireguard-gateway-operator",
		"app.kubernetes.io/instance":   gw.Name,
		"app.kubernetes.io/component":  component,
		"app.kubernetes.io/managed-by": "gateway-operator",
	}
}
