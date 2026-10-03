package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

const (
	// Forward-validation Ready=False reasons. Each reflects external state a backend
	// change can clear without a spec edit, so all are transient.
	reasonCrossNamespaceForwardDenied = "CrossNamespaceForwardDenied"
	reasonTargetNamespaceNotFound     = "TargetNamespaceNotFound"
	reasonUnsupportedServiceType      = "UnsupportedServiceType"
	reasonServiceNotFound             = "ServiceNotFound"
	reasonTargetPortNotListening      = "TargetPortNotListening"
)

// reasonUnresolvedBackendPort is event-only, never a Ready reason: the forward stays
// valid, but its named targetPort widens the link's egress rule to the whole protocol.
const reasonUnresolvedBackendPort = "UnresolvedBackendPort"

// crossNamespaceIngressLabel is the consent label a target namespace must carry before a
// Gateway elsewhere may forward public traffic into it.
const (
	crossNamespaceIngressLabel = "wgnet.dev/allow-gateway-ingress"
	crossNamespaceIngressValue = "true"
)

// invalidForward is a forward classifyForwards rejected, paired with the
// Ready=False reason and a human-readable message naming the specific failure.
type invalidForward struct {
	reason  string
	message string
}

// forwardBackend pairs a valid forward with its backend port and Service port name.
// BackendPort is 0 for a named targetPort; ServicePortName is empty for an unnamed port.
type forwardBackend struct {
	Forward         wgnetv1alpha1.Forward
	BackendPort     int32
	ServicePortName string
}

// unresolvedBackend is a valid forward whose backend Service names its targetPort, so
// the link's egress rule widens to the whole protocol.
type unresolvedBackend struct {
	service    string
	namespace  string
	targetPort string
	protocol   string
}

// effectiveForwardNamespace is the namespace a forward's Service lives in: its
// explicit Namespace, or the Gateway's own namespace when left unset.
func effectiveForwardNamespace(f wgnetv1alpha1.Forward, gw *wgnetv1alpha1.Gateway) string {
	if f.Namespace != "" {
		return f.Namespace
	}
	return gw.Namespace
}

// effectiveServicePort is the forward's TargetPort, or its public Port when unset. It is
// the Service's published port, not the pod-side port the Service may remap it to.
func effectiveServicePort(f wgnetv1alpha1.Forward) int32 {
	if f.TargetPort == 0 {
		return f.Port
	}
	return f.TargetPort
}

// forwardServiceFQDN is the fully-qualified cluster DNS name of a forward's backend,
// built here so resolution does not depend on the pod's resolv.conf ndots.
func forwardServiceFQDN(f wgnetv1alpha1.Forward, gw *wgnetv1alpha1.Gateway) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", f.Service, effectiveForwardNamespace(f, gw))
}

// corev1ProtocolOf maps a Gateway L4 protocol to its corev1 equivalent, falling back to
// TCP rather than the empty protocol the API would reject.
func corev1ProtocolOf(p wgnetv1alpha1.Protocol) corev1.Protocol {
	if p == wgnetv1alpha1.ProtocolUDP {
		return corev1.ProtocolUDP
	}
	return corev1.ProtocolTCP
}

func forwardSpecs(backends []forwardBackend) []wgnetv1alpha1.Forward {
	forwards := make([]wgnetv1alpha1.Forward, 0, len(backends))
	for _, b := range backends {
		forwards = append(forwards, b.Forward)
	}
	return forwards
}

// classifyForwards partitions forwards into valid and invalid, preserving spec order. A
// non-NotFound API error fails the reconcile rather than misclassifying a forward.
func (r *GatewayReconciler) classifyForwards(ctx context.Context, gw *wgnetv1alpha1.Gateway) (valid []forwardBackend, invalid []invalidForward, err error) {
	local := isLocal(gw)
	var unresolved []unresolvedBackend
	for _, f := range gw.Spec.Forwards {
		ns := effectiveForwardNamespace(f, gw)

		if ns != gw.Namespace {
			allowed, aerr := r.namespaceAllowsIngress(ctx, ns)
			switch {
			case apierrors.IsNotFound(aerr):
				invalid = append(invalid, invalidForward{reasonTargetNamespaceNotFound,
					fmt.Sprintf("forward target namespace %q does not exist", ns)})
				continue
			case aerr != nil:
				return nil, nil, fmt.Errorf("get target namespace %q: %w", ns, aerr)
			case !allowed:
				invalid = append(invalid, invalidForward{reasonCrossNamespaceForwardDenied,
					fmt.Sprintf("cross-namespace forward to %q denied: target namespace must carry label %s=%s",
						ns, crossNamespaceIngressLabel, crossNamespaceIngressValue)})
				continue
			}
		}

		var svc corev1.Service
		serr := r.APIReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: f.Service}, &svc)
		switch {
		case apierrors.IsNotFound(serr):
			invalid = append(invalid, invalidForward{reasonServiceNotFound,
				fmt.Sprintf("forward backend Service %q in namespace %q not found yet", f.Service, ns)})
			continue
		case serr != nil:
			return nil, nil, fmt.Errorf("get forward Service %s/%s: %w", ns, f.Service, serr)
		}

		if msg := unsupportedServiceMessage(&svc, local); msg != "" {
			invalid = append(invalid, invalidForward{reasonUnsupportedServiceType, msg})
			continue
		}

		port := effectiveServicePort(f)
		sp := servicePortFor(&svc, port, corev1.Protocol(f.Protocol))
		if sp == nil {
			invalid = append(invalid, invalidForward{reasonTargetPortNotListening,
				fmt.Sprintf("forward backend Service %q in namespace %q does not publish %s port %d",
					f.Service, ns, f.Protocol, port)})
			continue
		}

		backendPort := backendPortOf(sp)
		// Local resolves a named targetPort through the EndpointSlice and runs without an
		// egress NetworkPolicy, so an unresolved port widens nothing there.
		if backendPort == 0 && !local {
			unresolved = append(unresolved, unresolvedBackend{
				service: f.Service, namespace: ns, targetPort: sp.TargetPort.String(), protocol: string(f.Protocol),
			})
		}

		valid = append(valid, forwardBackend{Forward: f, BackendPort: backendPort, ServicePortName: sp.Name})
	}
	r.warnUnresolvedBackendPorts(gw, unresolved)
	return valid, invalid, nil
}

// namespaceAllowsIngress reports whether the namespace carries the consent label. A
// NotFound is returned so the caller can tell a missing namespace from an unlabelled one.
func (r *GatewayReconciler) namespaceAllowsIngress(ctx context.Context, name string) (bool, error) {
	var ns corev1.Namespace
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: name}, &ns); err != nil {
		return false, err
	}
	return ns.Labels[crossNamespaceIngressLabel] == crossNamespaceIngressValue, nil
}

// servicePortFor returns the port svc publishes for port and proto, or nil. It matches
// spec.ports[].port, not the containerPort; an empty protocol defaults to TCP.
func servicePortFor(svc *corev1.Service, port int32, proto corev1.Protocol) *corev1.ServicePort {
	for i := range svc.Spec.Ports {
		p := &svc.Spec.Ports[i]
		svcProto := p.Protocol
		if svcProto == "" {
			svcProto = corev1.ProtocolTCP
		}
		if p.Port == port && svcProto == proto {
			return p
		}
	}
	return nil
}

// backendPortOf is sp's numeric targetPort. A named targetPort yields 0: resolving it
// needs the backing EndpointSlices. An unset one is defaulted by the API server.
func backendPortOf(sp *corev1.ServicePort) int32 {
	if sp.TargetPort.Type == intstr.String {
		return 0
	}
	return sp.TargetPort.IntVal
}

// unsupportedServiceMessage reports why svc cannot back a forward, or "" when it can.
// ExternalName publishes no endpoints; headless lacks the VIP Cluster mode DNATs to.
func unsupportedServiceMessage(svc *corev1.Service, local bool) string {
	switch {
	case svc.Spec.Type == corev1.ServiceTypeExternalName:
		return fmt.Sprintf("forward backend Service %q in namespace %q has unsupported type %q: an ExternalName Service publishes no endpoints to forward to",
			svc.Name, svc.Namespace, svc.Spec.Type)
	case !local && (svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone):
		return fmt.Sprintf("forward backend Service %q in namespace %q is headless: the Cluster traffic policy requires a ClusterIP to DNAT to, set spec.trafficPolicy to Local to forward to a headless Service",
			svc.Name, svc.Namespace)
	}
	return ""
}

// anyTransientReason reports whether any invalid forward can clear without a spec edit.
// Reasons are enumerated so a permanent one is excluded by default.
func anyTransientReason(invalid []invalidForward) bool {
	for _, inv := range invalid {
		switch inv.reason {
		case reasonServiceNotFound, reasonTargetPortNotListening, reasonTargetNamespaceNotFound,
			reasonCrossNamespaceForwardDenied, reasonUnsupportedServiceType:
			return true
		}
	}
	return false
}

// invalidForwardsMessage joins the per-forward messages into one Ready condition line,
// so kubectl alone shows which forwards are rejected and why.
func invalidForwardsMessage(invalid []invalidForward) string {
	parts := make([]string, 0, len(invalid))
	for _, inv := range invalid {
		parts = append(parts, inv.message)
	}
	return fmt.Sprintf("%d forward(s) invalid: %s", len(invalid), strings.Join(parts, "; "))
}

// firstInvalidForward preserves the first reason and all rejection messages.
func firstInvalidForward(invalid []invalidForward) *invalidForward {
	if len(invalid) == 0 {
		return nil
	}
	return &invalidForward{reason: invalid[0].reason, message: invalidForwardsMessage(invalid)}
}

// warnUnresolvedBackendPorts emits one Warning per unresolved backend, only when the set
// changed: the condition is steady state, so every pass would otherwise re-emit it.
func (r *GatewayReconciler) warnUnresolvedBackendPorts(gw *wgnetv1alpha1.Gateway, unresolved []unresolvedBackend) {
	if r.Recorder == nil {
		return
	}

	key := unresolvedWarnKey(gw)
	if len(unresolved) == 0 {
		r.unresolvedWarned.Delete(key)
		return
	}

	signature := fmt.Sprintf("%v", unresolved)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
		return
	}
	r.unresolvedWarned.Store(key, signature)

	for _, u := range unresolved {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonUnresolvedBackendPort, actionReconcile,
			"forward backend Service %q in namespace %q names its targetPort %q: the link's egress policy allows every %s port to the backend rather than that one",
			u.service, u.namespace, u.targetPort, u.protocol)
	}
}
