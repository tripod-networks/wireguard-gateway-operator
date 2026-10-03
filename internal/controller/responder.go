package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/responder"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// nginxConfKey is the responder ConfigMap's data key, mounted as the nginx config file.
const nginxConfKey = "nginx.conf"

// responderNameSuffix turns a Gateway's name into its responder objects' shared name.
const responderNameSuffix = "-responder"

// responderComponentName names every object of a Gateway's responder: its ConfigMap, Service
// and workload (a Deployment or a DaemonSet, never both at once).
func responderComponentName(gw *wgnetv1alpha1.Gateway) string { return gw.Name + responderNameSuffix }

// responderSelectorLabels are the pod-template and selector labels for a Gateway's responder
// workload; the same scheme as linkSelectorLabels, distinguished by component value.
func responderSelectorLabels(gw *wgnetv1alpha1.Gateway) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "wireguard-gateway-operator",
		"app.kubernetes.io/instance":  gw.Name,
		"app.kubernetes.io/component": componentResponder,
	}
}

// The default consts mirror the CRD defaults for spec.responder.
const (
	responderDefaultPort     int32 = 27000
	responderDefaultReplicas int32 = 2
)

// configHashAnnotation carries the rendered nginx.conf's hash on a responder pod template, so a
// spec-only workload diff rolls pods when only the SubPath-mounted ConfigMap content changed.
const configHashAnnotation = "wgnet.dev/config-hash"

// responderConfigHash returns the lowercase hex SHA-256 of gw's rendered nginx.conf, the same
// content buildResponderConfigMap writes under nginxConfKey.
func responderConfigHash(gw *wgnetv1alpha1.Gateway) string {
	sum := sha256.Sum256([]byte(responder.NginxConf(effectiveResponderPort(gw))))
	return hex.EncodeToString(sum[:])
}

// effectiveResponderImage returns the Gateway's responder container image: its own
// spec.responder.image, or cfg's install-wide default when unset.
func effectiveResponderImage(cfg Config, gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Responder.Image != "" {
		return gw.Spec.Responder.Image
	}
	return cfg.ResponderImage
}

// effectiveResponderPort returns the port the Gateway's responder listens on, defaulting
// an unset value.
func effectiveResponderPort(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Responder.Port != 0 {
		return gw.Spec.Responder.Port
	}
	return responderDefaultPort
}

// effectiveResponderReplicas returns the responder Deployment's replica count, defaulting
// an unset value. Local mode ignores it: the responder runs as a DaemonSet there.
func effectiveResponderReplicas(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Responder.Replicas != 0 {
		return gw.Spec.Responder.Replicas
	}
	return responderDefaultReplicas
}

// responderEgressPorts allows the responder Service port, mirroring backendEgressPorts's shape.
func responderEgressPorts(gw *wgnetv1alpha1.Gateway) []networkingv1.NetworkPolicyPort {
	proto := corev1.ProtocolTCP
	port := effectiveResponderPort(gw)
	return []networkingv1.NetworkPolicyPort{{Protocol: &proto, Port: new(intstr.FromInt32(port))}}
}

// buildResponderConfigMap builds the nginx config ConfigMap the Gateway's responder pods mount.
func buildResponderConfigMap(gw *wgnetv1alpha1.Gateway) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      responderComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentResponder),
		},
		Data: map[string]string{nginxConfKey: responder.NginxConf(effectiveResponderPort(gw))},
	}
}

// buildResponderService builds the ClusterIP Service a Cluster Gateway's link DNATs its
// health probe to; a Local Gateway's link talks to responder pods directly instead.
func buildResponderService(gw *wgnetv1alpha1.Gateway) *corev1.Service {
	port := effectiveResponderPort(gw)
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      responderComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentResponder),
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: responderSelectorLabels(gw),
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Port:       port,
				TargetPort: intstr.FromString("http"),
			}},
		},
	}
}

// responderPodTemplate builds the pod template a Gateway's responder Deployment and DaemonSet
// share; callers add the mode-specific tolerations or anti-affinity.
func responderPodTemplate(cfg Config, gw *wgnetv1alpha1.Gateway) corev1.PodTemplateSpec {
	runAsNonRoot := true
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := true
	port := effectiveResponderPort(gw)

	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      responderSelectorLabels(gw),
			Annotations: map[string]string{configHashAnnotation: responderConfigHash(gw)},
		},
		Spec: corev1.PodSpec{
			// The responder never calls the API and only answers the public health-check path.
			AutomountServiceAccountToken: new(false),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   &runAsNonRoot,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:  "nginx",
				Image: effectiveResponderImage(cfg, gw),
				Ports: []corev1.ContainerPort{{
					Name:          "http",
					ContainerPort: port,
					Protocol:      corev1.ProtocolTCP,
				}},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path: responder.HealthPath,
							Port: intstr.FromString("http"),
						},
					},
				},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &allowPrivilegeEscalation,
					ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "tmp", MountPath: "/tmp"},
					{
						Name:      "config",
						MountPath: "/etc/nginx/nginx.conf",
						SubPath:   nginxConfKey,
						ReadOnly:  true,
					},
				},
				Resources: gw.Spec.Responder.Resources,
			}},
			Volumes: []corev1.Volume{
				{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: responderComponentName(gw)},
						},
					},
				},
			},
		},
	}
}

// buildResponderDeployment builds a Cluster Gateway's responder workload:
// effectiveResponderReplicas(gw) pods spread across nodes on a best-effort basis.
func buildResponderDeployment(cfg Config, gw *wgnetv1alpha1.Gateway) *appsv1.Deployment {
	replicas := effectiveResponderReplicas(gw)
	selector := responderSelectorLabels(gw)
	tmpl := responderPodTemplate(cfg, gw)
	tmpl.Spec.Affinity = &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
				Weight: 100,
				PodAffinityTerm: corev1.PodAffinityTerm{
					TopologyKey:   "kubernetes.io/hostname",
					LabelSelector: &metav1.LabelSelector{MatchLabels: selector},
				},
			}},
		},
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      responderComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentResponder),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Template: tmpl,
		},
	}
}

// buildResponderDaemonSet builds a Local Gateway's responder workload: one pod per node the link
// DaemonSet can land on, through the same spec.link.nodeSelector and absence of tolerations.
func buildResponderDaemonSet(cfg Config, gw *wgnetv1alpha1.Gateway) *appsv1.DaemonSet {
	selector := responderSelectorLabels(gw)
	tmpl := responderPodTemplate(cfg, gw)
	tmpl.Spec.NodeSelector = gw.Spec.Link.NodeSelector

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      responderComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentResponder),
		},
		Spec: appsv1.DaemonSetSpec{
			Selector:       &metav1.LabelSelector{MatchLabels: selector},
			Template:       tmpl,
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType},
		},
	}
}

// buildResponderPodDisruptionBudget keeps one responder pod available through a voluntary
// disruption, mirroring buildLinkPodDisruptionBudget; meaningful only at replicas>1.
func buildResponderPodDisruptionBudget(gw *wgnetv1alpha1.Gateway) *policyv1.PodDisruptionBudget {
	minAvailable := intstr.FromInt32(1)
	unhealthyPolicy := policyv1.AlwaysAllow
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      responderComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentResponder),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable:               &minAvailable,
			Selector:                   &metav1.LabelSelector{MatchLabels: responderSelectorLabels(gw)},
			UnhealthyPodEvictionPolicy: &unhealthyPolicy,
		},
	}
}

// responderHashAnnotation carries the hash of the desired responder object the operator last
// applied, so a reconcile that changes nothing issues no write.
const responderHashAnnotation = "wgnet.dev/responder-hash"

// deleteResponderLeftover deletes gw's responder object of probe's kind once it is no longer
// wanted, and only while the cached client still sees it live and not already deleting.
func (r *GatewayReconciler) deleteResponderLeftover(ctx context.Context, gw *wgnetv1alpha1.Gateway, probe client.Object) error {
	found, err := r.objectExists(ctx, gw.Namespace, responderComponentName(gw), probe)
	if err != nil {
		return err
	}
	if !found || probe.GetDeletionTimestamp() != nil {
		return nil
	}
	return r.deleteIfPresent(ctx, probe, client.PropagationPolicy(metav1.DeletePropagationBackground))
}

// isGatewayOwner reports whether ref is a controller reference to this operator's Gateway,
// excluding another API group's Gateway kind owning a same-named object.
func isGatewayOwner(ref *metav1.OwnerReference) bool {
	return ref != nil && ref.Kind == "Gateway" && ref.APIVersion == wgnetv1alpha1.GroupVersion.String()
}

// gatewaysForResponderObject marks the Gateway owning obj dirty and enqueues it, so an
// out-of-band edit to a responder object is re-applied even though its hash still matches.
func (r *GatewayReconciler) gatewaysForResponderObject(_ context.Context, obj client.Object) []reconcile.Request {
	owner := metav1.GetControllerOf(obj)
	if !isGatewayOwner(owner) {
		return nil
	}
	key := types.NamespacedName{Namespace: obj.GetNamespace(), Name: owner.Name}
	r.responderDirty.mark(key)
	return []reconcile.Request{{NamespacedName: key}}
}

// ensureGatewayResponder applies gw's responder ConfigMap, Service and workload and deletes any
// leftovers, returning the responder Service ClusterIP for the Cluster shape and "" for Local.
func (r *GatewayReconciler) ensureGatewayResponder(ctx context.Context, gw *wgnetv1alpha1.Gateway) (clusterIP string, retErr error) {
	key := client.ObjectKeyFromObject(gw)
	force := r.responderDirty.take(key)
	// A forced pass that fails leaves objects unapplied under a matching hash; keep the flag.
	defer func() {
		if force && retErr != nil {
			r.responderDirty.mark(key)
		}
	}()

	if _, err := r.applyObjectIfChanged(ctx, gw, responderHashAnnotation, buildResponderConfigMap(gw), &corev1.ConfigMap{}, force); err != nil {
		return "", fmt.Errorf("apply responder configmap: %w", err)
	}

	svc := buildResponderService(gw)
	var liveSvc corev1.Service
	applied, err := r.applyObjectIfChanged(ctx, gw, responderHashAnnotation, svc, &liveSvc, force)
	if err != nil {
		return "", fmt.Errorf("apply responder service: %w", err)
	}

	if isLocal(gw) {
		if _, err := r.applyObjectIfChanged(ctx, gw, responderHashAnnotation, buildResponderDaemonSet(r.Config, gw), &appsv1.DaemonSet{}, force); err != nil {
			return "", fmt.Errorf("apply responder daemonset: %w", err)
		}
		if err := r.deleteResponderLeftover(ctx, gw, &appsv1.Deployment{}); err != nil {
			return "", err
		}
		if err := r.deleteResponderLeftover(ctx, gw, &policyv1.PodDisruptionBudget{}); err != nil {
			return "", err
		}
		return "", nil
	}

	if _, err := r.applyObjectIfChanged(ctx, gw, responderHashAnnotation, buildResponderDeployment(r.Config, gw), &appsv1.Deployment{}, force); err != nil {
		return "", fmt.Errorf("apply responder deployment: %w", err)
	}
	if err := r.deleteResponderLeftover(ctx, gw, &appsv1.DaemonSet{}); err != nil {
		return "", err
	}
	if effectiveResponderReplicas(gw) > 1 {
		if _, err := r.applyObjectIfChanged(ctx, gw, responderHashAnnotation, buildResponderPodDisruptionBudget(gw), &policyv1.PodDisruptionBudget{}, force); err != nil {
			return "", fmt.Errorf("apply responder poddisruptionbudget: %w", err)
		}
	} else if err := r.deleteResponderLeftover(ctx, gw, &policyv1.PodDisruptionBudget{}); err != nil {
		return "", err
	}

	clusterIP = liveSvc.Spec.ClusterIP
	if applied {
		clusterIP = svc.Spec.ClusterIP
	}
	if clusterIP == "" {
		return "", fmt.Errorf("get responder service: %s/%s has no clusterIP", gw.Namespace, responderComponentName(gw))
	}
	return clusterIP, nil
}

// gatewaysForResponderPod enqueues the pod's own Gateway (its app.kubernetes.io/instance label,
// same namespace): ResponderMissing depends only on a Gateway's own responder pods.
func (r *GatewayReconciler) gatewaysForResponderPod(_ context.Context, obj client.Object) []reconcile.Request {
	name := obj.GetLabels()["app.kubernetes.io/instance"]
	if name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: obj.GetNamespace(), Name: name}}}
}

// responderPods returns node name -> pod IP for every Running, Ready responder pod of gw not
// already terminating, with a status.podIP, read from the informer cache in gw's own namespace.
func (r *GatewayReconciler) responderPods(ctx context.Context, gw *wgnetv1alpha1.Gateway) (map[string]string, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(gw.Namespace),
		client.MatchingLabels(responderSelectorLabels(gw))); err != nil {
		return nil, fmt.Errorf("list responder pods: %w", err)
	}
	responders := make(map[string]string, len(pods.Items))
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || !podReady(&p) {
			continue
		}
		responders[p.Spec.NodeName] = p.Status.PodIP
	}
	return responders, nil
}

// podReady reports whether p's PodReady condition is True.
func podReady(p *corev1.Pod) bool {
	for _, cond := range p.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// responderMissingNodes returns the sorted, distinct nodes hosting a live link pod that
// responders carries no entry for; a terminating or not-yet-Running link pod is skipped.
func responderMissingNodes(linkPods []corev1.Pod, responders map[string]string) []string {
	seen := make(map[string]bool, len(linkPods))
	var missing []string
	for _, p := range linkPods {
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
			continue
		}
		node := p.Spec.NodeName
		if node == "" || seen[node] {
			continue
		}
		seen[node] = true
		if _, ok := responders[node]; !ok {
			missing = append(missing, node)
		}
	}
	slices.Sort(missing)
	return missing
}

// responderMissingWarnKeyPrefix distinguishes warnResponderMissing's suppression entries from
// the other warn helpers' in the shared unresolvedWarned map.
const responderMissingWarnKeyPrefix = "responder-missing/"

// responderMissingStatus is the ResponderMissing condition's inputs for either shape. Local
// carries the link pods' missing nodes; Cluster carries whether any responder pod is Running.
type responderMissingStatus struct {
	local   bool
	missing []string
	present bool
}

// condition renders the ResponderMissing condition for s's shape: Local names the node(s) with
// no responder pod, Cluster names the workload and namespace holding no ready pod for it.
func (s *responderMissingStatus) condition(gw *wgnetv1alpha1.Gateway) metav1.Condition {
	cond := metav1.Condition{Type: conditionResponderMissing}
	switch {
	case s.local && len(s.missing) > 0:
		cond.Status = metav1.ConditionTrue
		cond.Reason = reasonNoResponderOnNode
		cond.Message = fmt.Sprintf("no responder pod on node(s): %s", strings.Join(s.missing, ", "))
	case s.local:
		cond.Status = metav1.ConditionFalse
		cond.Reason = reasonResponderPresent
		cond.Message = "every link pod's node has a responder"
	case !s.present:
		cond.Status = metav1.ConditionTrue
		cond.Reason = reasonNoResponderRunning
		cond.Message = fmt.Sprintf("no ready responder pod for %s in namespace %s", responderComponentName(gw), gw.Namespace)
	default:
		cond.Status = metav1.ConditionFalse
		cond.Reason = reasonResponderPresent
		cond.Message = fmt.Sprintf("a ready responder pod exists for %s in namespace %s", responderComponentName(gw), gw.Namespace)
	}
	return cond
}

// warnResponderMissing emits a Warning while the ResponderMissing condition would be True,
// suppressing a repeat while the cause is unchanged, mirroring warnUnresolvedBackendPorts.
func (r *GatewayReconciler) warnResponderMissing(gw *wgnetv1alpha1.Gateway, status *responderMissingStatus) {
	if r.Recorder == nil || status == nil {
		return
	}
	key := responderMissingWarnKeyPrefix + unresolvedWarnKey(gw)

	if status.local {
		if len(status.missing) == 0 {
			r.unresolvedWarned.Delete(key)
			return
		}
		signature := strings.Join(status.missing, ",")
		if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
			return
		}
		r.unresolvedWarned.Store(key, signature)
		for _, node := range status.missing {
			r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonNoResponderOnNode, actionReconcile,
				"no responder pod on node %s", node)
		}
		return
	}

	if status.present {
		r.unresolvedWarned.Delete(key)
		return
	}
	const signature = "no-running-responder"
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
		return
	}
	r.unresolvedWarned.Store(key, signature)
	r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonNoResponderRunning, actionReconcile,
		"no ready responder pod for %s", responderComponentName(gw))
}

const (
	// componentResponder labels and names a Gateway's responder objects, distinguishing
	// them from its link objects under the same app.kubernetes.io/component key.
	componentResponder = "responder"
)

const (
	// conditionResponderMissing: True means the health probe can't reach a responder though
	// the tunnel is up. Local names the missing node(s); Cluster means none are Running.
	conditionResponderMissing = "ResponderMissing"
	// ResponderMissing reasons.
	reasonNoResponderOnNode  = "NoResponderOnNode"
	reasonNoResponderRunning = "NoResponderRunning"
	reasonResponderPresent   = "ResponderPresent"
)

// responderWorkloadPredicate filters the responder Deployment, DaemonSet and PodDisruptionBudget
// watches to spec, label and annotation changes: other controllers write their status.
func responderWorkloadPredicate() predicate.Predicate {
	return predicate.And(
		predicate.NewPredicateFuncs(isResponderObject),
		predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
		),
	)
}

// isResponderObject reports whether obj is a Gateway's responder child: it carries the responder
// component label, or an edit dropped that label from an object a Gateway owns under its name.
func isResponderObject(obj client.Object) bool {
	if obj.GetLabels()["app.kubernetes.io/component"] == componentResponder {
		return true
	}
	owner := metav1.GetControllerOf(obj)
	return isGatewayOwner(owner) && obj.GetName() == owner.Name+responderNameSuffix
}
