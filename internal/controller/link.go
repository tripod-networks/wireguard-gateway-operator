package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpmembers"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

const (
	// linkConfigKey is the data key under which the link Deployment's RuntimeConfig
	// JSON is stored in its ConfigMap and mounted into the container.
	linkConfigKey = "config.json"
	// componentLink labels and names the in-cluster link objects.
	componentLink = "link"
	// linkNameSuffix trails the Gateway name in every namespaced link object's name.
	linkNameSuffix = "-link"
	// linkEndpointSliceClusterRole is the chart-shipped ClusterRole granting EndpointSlice
	// reads; a fixed cluster-scoped name, the resourceName of the operator's bind grant.
	linkEndpointSliceClusterRole = "gateway-link-endpointslice-reader"
	// linkClusterRoleBindingPrefix leads every per-Gateway ClusterRoleBinding name so
	// the objects are identifiable in a cluster-wide listing.
	linkClusterRoleBindingPrefix = "gateway-link-"
	// linkClusterRoleBindingMaxLen caps the hashed ClusterRoleBinding name, leaving 27
	// base32 digest characters, far more than collision resistance needs here.
	linkClusterRoleBindingMaxLen = len(linkClusterRoleBindingPrefix) + 27
	// ownerNamespaceLabel and ownerNameLabel name the owning Gateway on a cluster-scoped
	// child, which cannot carry an ownerReference to a namespaced owner.
	ownerNamespaceLabel = "wgnet.dev/gateway-namespace"
	ownerNameLabel      = "wgnet.dev/gateway-name"
	// clusterHealthPort is the Cluster-mode default readiness port when spec.link.healthPort
	// is unset; it must match link.Config's GATEWAY_HEALTH_ADDR default. Local binds loopback.
	clusterHealthPort = 27000
)

const (
	reasonReservedHealthPort = "ReservedHealthPort"
)

// linkIDAnnotation records the allocated Local link id on the Gateway itself, so an id
// outlives a restore that keeps metadata and spec but drops status.
const linkIDAnnotation = "wgnet.dev/link-id"

// reservedHealthPortWarnKeyPrefix distinguishes warnReservedHealthPort's suppression entries
// from the other warn helpers' in the shared unresolvedWarned map.
const reservedHealthPortWarnKeyPrefix = "health-port/"

// invalidTunnelWarnKeyPrefix distinguishes warnInvalidTunnelAddresses' suppression entries
// from warnUnresolvedBackendPorts' in the shared unresolvedWarned map.
const invalidTunnelWarnKeyPrefix = "tunnel/"

// capacityWarnKeyPrefix distinguishes warnInsufficientTunnelAddresses' suppression entries
// from the other warn helpers' in the shared unresolvedWarned map.
const capacityWarnKeyPrefix = "capacity/"

// errNoFreeLinkID reports that every id in 1..link.MaxLinkID is held. Only deleting a
// Local Gateway frees one, so it is surfaced on Ready instead of retried with backoff.
var errNoFreeLinkID = errors.New("no free link id")

// linkStatus is what the operator observes about a Gateway's link from the Lease and
// the pod holding it.
type linkStatus struct {
	// Active requires both holder PodReady and its tunnel-ready annotation; idle standbys
	// are PodReady too, so readiness must use the Lease holder rather than availability.
	Active bool
	// PodReady is checked before the tunnel annotation; this window needs a faster requeue.
	// The holder's first Lease write reports the tunnel after the probe latches ready.
	PodReady bool
	// Node is the holder pod's node name, empty when there is no readable holder.
	Node string
	// FaultReason and FaultMessage carry the holder's link-fault annotations.
	FaultReason  string
	FaultMessage string
}

// knownLinkFaults are the fault reasons a link may publish. An unrecognised value is
// ignored rather than copied into the API-validated Ready condition reason.
var knownLinkFaults = func() map[string]bool {
	faults := link.KnownFaults()
	m := make(map[string]bool, len(faults))
	for _, reason := range faults {
		m[reason] = true
	}
	return m
}()

// bundleSecretName and linkSecretName name the two WireGuard key Secrets a Gateway
// owns, per-Gateway so two Gateways in a namespace do not share key material.
func bundleSecretName(gw *wgnetv1alpha1.Gateway) string { return gw.Name + "-bundle" }
func linkSecretName(gw *wgnetv1alpha1.Gateway) string   { return gw.Name + "-link" }

// linkComponentName names every namespaced link object of a Gateway: the workload,
// ConfigMap, NetworkPolicy, PDB, ServiceAccount, Role, RoleBinding and Lease.
func linkComponentName(gw *wgnetv1alpha1.Gateway) string { return gw.Name + linkNameSuffix }

// linkClusterRoleBindingName hashes namespace and name into the cluster-scoped binding
// name; "<namespace>-<name>" is ambiguous when either contains a dash.
func linkClusterRoleBindingName(gw *wgnetv1alpha1.Gateway) string {
	return hashedName(linkClusterRoleBindingPrefix, gw.Namespace, gw.Name, linkClusterRoleBindingMaxLen)
}

// linkSelectorLabels are the pod-template and selector labels for the link
// Deployment; a stable subset of the common labels.
func linkSelectorLabels(gw *wgnetv1alpha1.Gateway) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "wireguard-gateway-operator",
		"app.kubernetes.io/instance":  gw.Name,
		"app.kubernetes.io/component": componentLink,
	}
}

const (
	// The default consts mirror the CRD defaults; the effective* accessors apply them only
	// to in-memory Gateways that bypassed CRD defaulting.
	wgDefaultListenPort        int32 = 51820
	wgDefaultSubnet                  = "10.99.0.0/29"
	wgDefaultGatewayAddress          = "10.99.0.1"
	wgDefaultLinkAddress             = "10.99.0.2"
	wgDefaultKeepalive         int32 = 25
	wgDefaultMTU               int32 = 1380
	wgDefaultReconcileInterval       = "10s"
	linkDefaultReplicas        int32 = 1
)

// effectiveWireguardPort returns the Gateway's WireGuard listen port, defaulting an
// unset value to wgDefaultListenPort for in-memory Gateways that bypassed CRD defaulting.
func effectiveWireguardPort(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Wireguard.ListenPort == 0 {
		return wgDefaultListenPort
	}
	return gw.Spec.Wireguard.ListenPort
}

// effectiveWGSubnet returns the WireGuard tunnel CIDR, defaulting an unset value.
func effectiveWGSubnet(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Wireguard.Subnet == "" {
		return wgDefaultSubnet
	}
	return gw.Spec.Wireguard.Subnet
}

// effectiveWGGatewayAddress returns the gateway VM's wg0 address, defaulting an
// unset value.
func effectiveWGGatewayAddress(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Wireguard.GatewayAddress == "" {
		return wgDefaultGatewayAddress
	}
	return gw.Spec.Wireguard.GatewayAddress
}

// effectiveWGLinkAddress returns the link end's wg0 address, defaulting an unset
// value.
func effectiveWGLinkAddress(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Wireguard.LinkAddress == "" {
		return wgDefaultLinkAddress
	}
	return gw.Spec.Wireguard.LinkAddress
}

// effectiveWGKeepalive returns the link's persistent-keepalive interval in
// seconds, defaulting an unset value.
func effectiveWGKeepalive(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Wireguard.Keepalive == 0 {
		return wgDefaultKeepalive
	}
	return gw.Spec.Wireguard.Keepalive
}

// effectiveWGMTU returns the link's wg0 MTU, defaulting an unset value.
func effectiveWGMTU(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Wireguard.MTU == 0 {
		return wgDefaultMTU
	}
	return gw.Spec.Wireguard.MTU
}

// effectiveWGReconcileInterval returns how often the link re-reads the
// XGatewayGCP address, defaulting an unset value.
func effectiveWGReconcileInterval(gw *wgnetv1alpha1.Gateway) string {
	if gw.Spec.Wireguard.ReconcileInterval == "" {
		return wgDefaultReconcileInterval
	}
	return gw.Spec.Wireguard.ReconcileInterval
}

// effectiveLinkReplicas returns the link Deployment's replica count, defaulting
// an unset value.
func effectiveLinkReplicas(gw *wgnetv1alpha1.Gateway) int32 {
	if gw.Spec.Link.Replicas == 0 {
		return linkDefaultReplicas
	}
	return gw.Spec.Link.Replicas
}

// effectiveTrafficPolicy defaults an empty data-path mode to Cluster, guarding
// in-memory Gateways that bypassed CRD defaulting.
func effectiveTrafficPolicy(gw *wgnetv1alpha1.Gateway) wgnetv1alpha1.TrafficPolicy {
	if gw.Spec.TrafficPolicy == "" {
		return wgnetv1alpha1.TrafficPolicyCluster
	}
	return gw.Spec.TrafficPolicy
}

func isLocal(gw *wgnetv1alpha1.Gateway) bool {
	return effectiveTrafficPolicy(gw) == wgnetv1alpha1.TrafficPolicyLocal
}

// linkIdentityOf returns the Gateway-level identity derived from the allocated id, nil in
// Cluster mode and before allocation. Local workload builders require a non-nil result.
func linkIdentityOf(gw *wgnetv1alpha1.Gateway) *link.GatewayIdentity {
	if !isLocal(gw) || gw.Status.Link.ID <= 0 {
		return nil
	}
	ident := link.NewGatewayIdentity(int(gw.Status.Link.ID))
	return &ident
}

// effectiveHealthPort returns the local identity port, spec.link.healthPort, or the
// cluster default, in that order.
func effectiveHealthPort(gw *wgnetv1alpha1.Gateway) int {
	if ident := linkIdentityOf(gw); ident != nil {
		return ident.HealthPort
	}
	if gw.Spec.Link.HealthPort > 0 {
		return int(gw.Spec.Link.HealthPort)
	}
	return clusterHealthPort
}

// buildBundleSecret builds the Secret read by the XGatewayGCP's SecretVersion; its
// single key holds "<gatewayPriv>\n<linkPub>\n", the payload the VM boot script splits.
func buildBundleSecret(gw *wgnetv1alpha1.Gateway, gatewayPriv, linkPub string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bundleSecretName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, "bundle"),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			wg.BundleKey: []byte(gatewayPriv + "\n" + linkPub + "\n"),
		},
	}
}

// buildLinkSecret builds the Secret the link mounts: its own private key and the
// gateway's public key (its sole peer).
func buildLinkSecret(gw *wgnetv1alpha1.Gateway, linkPriv, gatewayPub string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkSecretName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			wg.LinkPrivateKey:    []byte(linkPriv),
			wg.LinkPeerPublicKey: []byte(gatewayPub),
		},
	}
}

// fleetLinkPeers renders one link peer per fleet member. Local mode overrides every peer's
// AllowedIPs with the wildcard so cryptokey routing selects a peer for an arbitrary client.
func fleetLinkPeers(gw *wgnetv1alpha1.Gateway, fleetPeers []gcpmembers.Peer) []link.Peer {
	keepalive := int(effectiveWGKeepalive(gw))
	peers := make([]link.Peer, 0, len(fleetPeers))
	for _, p := range fleetPeers {
		var endpoint string
		if p.ExternalAddress != "" {
			endpoint = net.JoinHostPort(p.ExternalAddress, strconv.Itoa(p.ListenPort))
		}
		allowedIPs := []string{p.TunnelAddress + "/32"}
		if isLocal(gw) {
			allowedIPs = []string{"0.0.0.0/0"}
		}
		peers = append(peers, link.Peer{
			Slot:                p.Slot,
			PublicKey:           p.PublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          allowedIPs,
			PersistentKeepalive: keepalive,
		})
	}
	return peers
}

// buildLinkConfigMap renders the link configuration for either gateway branch. responders is
// Local mode only; responderTarget (the responder Service ClusterIP) is Cluster mode only.
func buildLinkConfigMap(gw *wgnetv1alpha1.Gateway, address string, backends []forwardBackend, ident *link.GatewayIdentity, gatewayPublicKey string, fleetPeers []link.Peer, healthPort int, responders map[string]string, responderTarget string) (*corev1.ConfigMap, error) {
	responderPort := int(effectiveResponderPort(gw))
	wgSubnet := effectiveWGSubnet(gw)
	suffix := wgSubnet
	if i := strings.LastIndex(suffix, "/"); i >= 0 {
		suffix = suffix[i+1:]
	}

	local := isLocal(gw)
	linkForwards := make([]link.Forward, 0, len(backends))
	for _, b := range backends {
		f := b.Forward
		proto := strings.ToLower(string(f.Protocol))
		lf := link.Forward{
			Name:       fmt.Sprintf("%s-%d", proto, f.Port),
			PublicPort: int(f.Port),
			Protocol:   proto,
		}
		if local {
			lf.Namespace = effectiveForwardNamespace(f, gw)
			lf.ServiceName = f.Service
			lf.ServicePortName = b.ServicePortName
		} else {
			lf.Service = forwardServiceFQDN(f, gw)
			lf.TargetPort = int(effectiveServicePort(f))
		}
		linkForwards = append(linkForwards, lf)
	}

	keepalive := int(effectiveWGKeepalive(gw))

	// Local mode needs wildcard routes for arbitrary client traffic.
	wildcardAllowedIPs := []string{"0.0.0.0/0"}

	peers := fleetPeers
	if gw.Spec.GCP.LoadBalancer != nil && peers == nil {
		peers = []link.Peer{}
	}
	if gw.Spec.GCP.LoadBalancer == nil {
		var endpoint string
		if address != "" {
			endpoint = net.JoinHostPort(address, strconv.Itoa(int(effectiveWireguardPort(gw))))
		}
		allowedIPs := []string{wgSubnet}
		if local {
			allowedIPs = wildcardAllowedIPs
		}
		peers = []link.Peer{{
			Slot:                0,
			PublicKey:           gatewayPublicKey,
			Endpoint:            endpoint,
			AllowedIPs:          allowedIPs,
			PersistentKeepalive: keepalive,
		}}
	}

	rc := link.RuntimeConfig{
		TrafficPolicy: string(effectiveTrafficPolicy(gw)),
		Identity:      ident,
		HealthPort:    healthPort,
		ResponderPort: responderPort,
		PublicAddress: address,
		WireGuard: link.WireGuard{
			Address:    fmt.Sprintf("%s/%s", effectiveWGLinkAddress(gw), suffix),
			ListenPort: 0,
			MTU:        int(effectiveWGMTU(gw)),
			Peers:      peers,
		},
		Forwards: linkForwards,
	}
	if local {
		rc.PodSelector = linkSelectorLabels(gw)
		rc.Responders = responders
	} else {
		rc.ResponderTarget = responderTarget
	}

	data, err := json.Marshal(rc)
	if err != nil {
		return nil, fmt.Errorf("encode link runtime config: %w", err)
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Data: map[string]string{linkConfigKey: string(data)},
	}, nil
}

// buildLinkNetworkPolicy permits egress to cluster DNS, the apiserver, the WireGuard underlay,
// the responder Service (health DNAT target) and each forward's backend; nftables DROPs the rest.
func buildLinkNetworkPolicy(gw *wgnetv1alpha1.Gateway, backends []forwardBackend) *networkingv1.NetworkPolicy {
	dnsPort53UDP := corev1.ProtocolUDP
	dnsPort53TCP := corev1.ProtocolTCP
	wgProto := corev1.ProtocolUDP
	apiserverProto := corev1.ProtocolTCP
	port53 := intstr.FromInt32(53)
	port443 := intstr.FromInt32(443)
	port6443 := intstr.FromInt32(6443)
	wgPort := intstr.FromInt32(effectiveWireguardPort(gw))

	egress := []networkingv1.NetworkPolicyEgressRule{
		{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
				},
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s-app": "kube-dns"},
				},
			}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &dnsPort53UDP, Port: &port53},
				{Protocol: &dnsPort53TCP, Port: &port53},
			},
		},
		{
			To: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
			}},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &wgProto, Port: &wgPort},
			},
		},
		// The apiserver's in-cluster addressing varies by environment, so the rule is
		// peer-less: 443 covers the Service, 6443 the direct apiserver port.
		{
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &apiserverProto, Port: &port443},
				{Protocol: &apiserverProto, Port: &port6443},
			},
		},
		{
			// Peer is 0.0.0.0/0, like a forward's backend rule: DNAT rewrites the probe to the
			// responder Service ClusterIP, which no pod selector matches; a pod-selector peer would deny it.
			To: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
			}},
			Ports: responderEgressPorts(gw),
		},
	}

	// The peer is 0.0.0.0/0 and both ports are allowed because a CNI may evaluate egress
	// against the ClusterIP and Service port or against the pod IP and DNAT'd port.
	for _, b := range backends {
		egress = append(egress, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{
				IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"},
			}},
			Ports: backendEgressPorts(b),
		})
	}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: linkSelectorLabels(gw)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      egress,
		},
	}
}

// backendEgressPorts allows the Service port and the pod-side port it is remapped to. A named
// backend port cannot be enumerated, so the rule goes port-less and classifyForwards warns.
func backendEgressPorts(b forwardBackend) []networkingv1.NetworkPolicyPort {
	proto := corev1ProtocolOf(b.Forward.Protocol)
	if b.BackendPort == 0 {
		return []networkingv1.NetworkPolicyPort{{Protocol: &proto}}
	}
	svcPort := effectiveServicePort(b.Forward)
	ports := []networkingv1.NetworkPolicyPort{{Protocol: &proto, Port: new(intstr.FromInt32(svcPort))}}
	if b.BackendPort != svcPort {
		ports = append(ports, networkingv1.NetworkPolicyPort{Protocol: &proto, Port: new(intstr.FromInt32(b.BackendPort))})
	}
	return ports
}

// linkPodSpec builds the pod spec both link workloads share. A nil ident selects Cluster
// mode (own netns, init container enables ip_forward); non-nil selects host-netns Local.
func linkPodSpec(gw *wgnetv1alpha1.Gateway, cfg Config, ident *link.GatewayIdentity) corev1.PodSpec {
	var runAsUser int64
	allowPrivilegeEscalation := false
	terminationGracePeriod := int64(30)

	const (
		// Whole-volume mount (no subPath) so the kubelet's "..data" symlink swap keeps it
		// live and the link's fsnotify watch reloads; a subPath mount never refreshes.
		configMountDir       = "/etc/gateway/config"
		configFilePath       = configMountDir + "/" + linkConfigKey
		wgKeysMountPath      = "/etc/gateway/wg"
		wgKeyPath            = "/etc/gateway/wg/" + wg.LinkPrivateKey
		wgPeerPubPath        = "/etc/gateway/wg/" + wg.LinkPeerPublicKey
		hostProcSysNetVolume = "host-proc-sys-net"
	)

	healthPort := effectiveHealthPort(gw)
	healthAddr := ":" + strconv.Itoa(healthPort)
	if ident != nil {
		// Loopback: the probe reaches a responder pod through the holder's health-port DNAT,
		// never this listener directly, which the kubelet alone still needs to reach.
		healthAddr = "127.0.0.1:" + strconv.Itoa(ident.HealthPort)
	}

	env := []corev1.EnvVar{
		{Name: "GATEWAY_CONFIG_PATH", Value: configFilePath},
		{Name: "GATEWAY_WG_KEY_PATH", Value: wgKeyPath},
		{Name: "GATEWAY_WG_PEER_PUBKEY_PATH", Value: wgPeerPubPath},
		{Name: "GATEWAY_HEALTH_ADDR", Value: healthAddr},
		{Name: "GATEWAY_RECONCILE_INTERVAL", Value: effectiveWGReconcileInterval(gw)},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
			},
		},
		{Name: "GATEWAY_LEASE_NAME", Value: linkComponentName(gw)},
	}

	mounts := []corev1.VolumeMount{
		{Name: "config", MountPath: configMountDir, ReadOnly: true},
		{Name: "wg-keys", MountPath: wgKeysMountPath, ReadOnly: true},
	}
	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: linkComponentName(gw)},
				},
			},
		},
		{
			Name: "wg-keys",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: linkSecretName(gw)},
			},
		},
	}

	var (
		hostNetwork    bool
		dnsPolicy      corev1.DNSPolicy
		initContainers []corev1.Container
		affinity       *corev1.Affinity
		ports          []corev1.ContainerPort
		probeHandler   corev1.HTTPGetAction
	)

	if ident != nil {
		hostNetwork = true
		dnsPolicy = corev1.DNSClusterFirstWithHostNet
		probeHandler = corev1.HTTPGetAction{
			Path: "/healthz",
			Host: "127.0.0.1",
			Port: intstr.FromInt32(int32(ident.HealthPort)),
		}
		env = append(env, corev1.EnvVar{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		})
		hostPathDir := corev1.HostPathDirectory
		volumes = append(volumes, corev1.Volume{
			Name: hostProcSysNetVolume,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/proc/sys/net", Type: &hostPathDir},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      hostProcSysNetVolume,
			MountPath: link.HostProcSysNetPath,
			ReadOnly:  false,
		})
	} else {
		privileged := true
		initContainers = []corev1.Container{{
			Name:            "enable-ip-forward",
			Image:           cfg.LinkImage,
			ImagePullPolicy: corev1.PullPolicy(cfg.LinkImagePullPolicy),
			Command:         []string{"sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser:  &runAsUser,
				Privileged: &privileged,
			},
		}}
		affinity = &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
					Weight: 100,
					PodAffinityTerm: corev1.PodAffinityTerm{
						TopologyKey:   "kubernetes.io/hostname",
						LabelSelector: &metav1.LabelSelector{MatchLabels: linkSelectorLabels(gw)},
					},
				}},
			},
		}
		ports = []corev1.ContainerPort{{
			Name:          "health",
			ContainerPort: int32(healthPort),
			Protocol:      corev1.ProtocolTCP,
		}}
		probeHandler = corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("health")}
	}

	return corev1.PodSpec{
		ServiceAccountName:            linkComponentName(gw),
		AutomountServiceAccountToken:  new(true),
		TerminationGracePeriodSeconds: &terminationGracePeriod,
		NodeSelector:                  gw.Spec.Link.NodeSelector,
		HostNetwork:                   hostNetwork,
		DNSPolicy:                     dnsPolicy,
		Affinity:                      affinity,
		InitContainers:                initContainers,
		Containers: []corev1.Container{{
			Name:            componentLink,
			Image:           cfg.LinkImage,
			ImagePullPolicy: corev1.PullPolicy(cfg.LinkImagePullPolicy),
			Command:         []string{"gateway-link"},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser:                &runAsUser,
				AllowPrivilegeEscalation: &allowPrivilegeEscalation,
				Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}},
			},
			Env:   env,
			Ports: ports,
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{HTTPGet: &probeHandler},
				// Readiness only: the link reports healthy once a fresh handshake
				// exists, and a liveness restart mid-converge would just reset progress.
				InitialDelaySeconds: 3,
				PeriodSeconds:       5,
				TimeoutSeconds:      2,
			},
			VolumeMounts: mounts,
		}},
		Volumes: volumes,
	}
}

// buildLinkDeployment builds the Cluster-mode link Deployment, leader-elected
// active-passive. maxUnavailable=0 with maxSurge=1 keeps a programmed pod through a roll.
func buildLinkDeployment(gw *wgnetv1alpha1.Gateway, cfg Config) *appsv1.Deployment {
	replicas := effectiveLinkReplicas(gw)
	selector := linkSelectorLabels(gw)
	maxSurge := intstr.FromInt32(1)
	maxUnavailable := intstr.FromInt32(0)

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       &maxSurge,
					MaxUnavailable: &maxUnavailable,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: selector},
				Spec:       linkPodSpec(gw, cfg, nil),
			},
		},
	}
}

// buildLinkDaemonSet builds the Local-mode link DaemonSet, one host-network pod per node.
// ident must be non-nil: every name, mark, route table and health port derives from it.
func buildLinkDaemonSet(gw *wgnetv1alpha1.Gateway, cfg Config, ident *link.GatewayIdentity) *appsv1.DaemonSet {
	selector := linkSelectorLabels(gw)

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: selector},
				Spec:       linkPodSpec(gw, cfg, ident),
			},
		},
	}
}

// buildLinkServiceAccount builds the ServiceAccount the link pods run under; its token
// is the only cluster credential they mount.
func buildLinkServiceAccount(gw *wgnetv1alpha1.Gateway) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
	}
}

// buildLinkRole grants the Lease verbs leader election needs, plus in Local mode the
// pod reads the election's liveness input needs.
func buildLinkRole(gw *wgnetv1alpha1.Gateway) *rbacv1.Role {
	rules := []rbacv1.PolicyRule{{
		APIGroups: []string{"coordination.k8s.io"},
		Resources: []string{"leases"},
		Verbs:     []string{"get", "list", "watch", "create", "update"},
	}}
	if isLocal(gw) {
		// Only a Local link watches pods: it reads this Gateway's link pods to learn
		// which nodes carry a ready peer, the election's liveness input.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		})
	}
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Rules: rules,
	}
}

// buildLinkRoleBinding binds the link Role to the link ServiceAccount, granting
// the link pods the Lease verbs in the Gateway's namespace.
func buildLinkRoleBinding(gw *wgnetv1alpha1.Gateway) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     linkComponentName(gw),
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
		}},
	}
}

// buildLinkClusterRoleBinding lets a Local Gateway's link resolve backend pods. Being
// cluster-scoped it has no ownerReference, so the delete path reaps it explicitly.
func buildLinkClusterRoleBinding(gw *wgnetv1alpha1.Gateway) *rbacv1.ClusterRoleBinding {
	labels := commonLabels(gw, componentLink)
	labels[ownerNamespaceLabel] = gw.Namespace
	labels[ownerNameLabel] = gw.Name

	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   linkClusterRoleBindingName(gw),
			Labels: labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     linkEndpointSliceClusterRole,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
		}},
	}
}

// buildLinkPodDisruptionBudget keeps one pod available through a voluntary disruption,
// so a drain cannot take the active and the standby at once. Meaningful only at replicas>1.
func buildLinkPodDisruptionBudget(gw *wgnetv1alpha1.Gateway) *policyv1.PodDisruptionBudget {
	minAvailable := intstr.FromInt32(1)
	// AlwaysAllow evicts an unhealthy pod even at the budget limit, so an unready
	// replica cannot block a node drain.
	unhealthyPolicy := policyv1.AlwaysAllow
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
			Labels:    commonLabels(gw, componentLink),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable:               &minAvailable,
			Selector:                   &metav1.LabelSelector{MatchLabels: linkSelectorLabels(gw)},
			UnhealthyPodEvictionPolicy: &unhealthyPolicy,
		},
	}
}

// bundleInputs are the values every member's bundle payload carries beside its own key,
// address and slot: they are uniform across a Gateway.
func bundleInputs(gw *wgnetv1alpha1.Gateway, linkPublicKey string) gcpmembers.BundleInputs {
	return gcpmembers.BundleInputs{
		SubnetPrefix:   subnetPrefix(effectiveWGSubnet(gw)),
		PeerPublicKey:  linkPublicKey,
		PeerAllowedIPs: effectiveWGLinkAddress(gw) + "/32",
	}
}

// ensureSecrets writes both key Secrets from one pair when either is missing.
func (r *GatewayReconciler) ensureSecrets(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	bundleExists, err := r.objectExists(ctx, gw.Namespace, bundleSecretName(gw), &corev1.Secret{})
	if err != nil {
		return err
	}
	linkExists, err := r.objectExists(ctx, gw.Namespace, linkSecretName(gw), &corev1.Secret{})
	if err != nil {
		return err
	}
	if bundleExists && linkExists {
		return nil
	}

	gen := r.GenerateKey
	if gen == nil {
		gen = wg.GenerateKeypair
	}
	gatewayPriv, gatewayPub, err := gen()
	if err != nil {
		return fmt.Errorf("generate gateway keypair: %w", err)
	}
	linkPriv, linkPub, err := gen()
	if err != nil {
		return fmt.Errorf("generate link keypair: %w", err)
	}

	if err := r.apply(ctx, gw, buildBundleSecret(gw, gatewayPriv, linkPub)); err != nil {
		return fmt.Errorf("write bundle secret: %w", err)
	}
	if err := r.apply(ctx, gw, buildLinkSecret(gw, linkPriv, gatewayPub)); err != nil {
		return fmt.Errorf("write link secret: %w", err)
	}
	return nil
}

// linkHashAnnotation carries the hash of the desired link object the operator last applied,
// so a reconcile that changes nothing issues no write.
const linkHashAnnotation = "wgnet.dev/link-hash"

// linkWorkloadPredicate filters the link Deployment, DaemonSet, NetworkPolicy and
// PodDisruptionBudget watches to spec, label and annotation changes: others write their status.
func linkWorkloadPredicate() predicate.Predicate {
	return predicate.And(
		predicate.NewPredicateFuncs(isLinkObject),
		predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
		),
	)
}

// isLinkObject reports whether obj is a Gateway's link child: it carries the link component
// label, or an edit dropped that label from an object a Gateway owns under its link name.
func isLinkObject(obj client.Object) bool {
	if obj.GetLabels()["app.kubernetes.io/component"] == componentLink {
		return true
	}
	owner := metav1.GetControllerOf(obj)
	return isGatewayOwner(owner) && obj.GetName() == owner.Name+linkNameSuffix
}

// LinkCacheSelector matches every link object the operator applies. It scopes the manager cache
// for the kinds the reconciler reads back only as link children, so the informers do not hold
// every such object in the cluster. A link object whose label drifted falls out of the cache and
// reads NotFound, which makes the next pass re-apply it and restore the label.
func LinkCacheSelector() labels.Selector {
	return labels.SelectorFromSet(labels.Set{"app.kubernetes.io/component": componentLink})
}

// gatewaysForLinkObject marks the Gateway owning obj dirty and enqueues it, so an out-of-band
// edit to a link object is re-applied even though its hash still matches.
func (r *GatewayReconciler) gatewaysForLinkObject(_ context.Context, obj client.Object) []reconcile.Request {
	key, ok := linkObjectGateway(obj)
	if !ok {
		return nil
	}
	r.linkDirty.mark(key)
	return []reconcile.Request{{NamespacedName: key}}
}

// linkObjectGateway resolves the Gateway obj belongs to: a namespaced child through its
// controller reference, the cluster-scoped binding through the owner labels standing in for one.
func linkObjectGateway(obj client.Object) (types.NamespacedName, bool) {
	if owner := metav1.GetControllerOf(obj); isGatewayOwner(owner) {
		return types.NamespacedName{Namespace: obj.GetNamespace(), Name: owner.Name}, true
	}
	labels := obj.GetLabels()
	namespace, name := labels[ownerNamespaceLabel], labels[ownerNameLabel]
	if namespace == "" || name == "" {
		return types.NamespacedName{}, false
	}
	return types.NamespacedName{Namespace: namespace, Name: name}, true
}

// ensureLink applies common link resources and the mode-specific workload. responderTarget is
// the responder Service ClusterIP, folded into a Cluster Gateway's health DNAT target.
func (r *GatewayReconciler) ensureLink(ctx context.Context, gw *wgnetv1alpha1.Gateway, address string, backends []forwardBackend, ident *link.GatewayIdentity, gatewayPublicKey string, fleetPeers []link.Peer, healthPort int, responders map[string]string, responderTarget string) (retErr error) {
	key := client.ObjectKeyFromObject(gw)
	force := r.linkDirty.take(key)
	// A forced pass that fails leaves objects unapplied under a matching hash; keep the flag.
	defer func() {
		if force && retErr != nil {
			r.linkDirty.mark(key)
		}
	}()

	if _, err := r.applyObjectIfChanged(ctx, gw, linkHashAnnotation, buildLinkServiceAccount(gw), &corev1.ServiceAccount{}, force); err != nil {
		return err
	}
	if _, err := r.applyObjectIfChanged(ctx, gw, linkHashAnnotation, buildLinkRole(gw), &rbacv1.Role{}, force); err != nil {
		return err
	}
	if _, err := r.applyObjectIfChanged(ctx, gw, linkHashAnnotation, buildLinkRoleBinding(gw), &rbacv1.RoleBinding{}, force); err != nil {
		return err
	}

	cm, err := buildLinkConfigMap(gw, address, backends, ident, gatewayPublicKey, fleetPeers, healthPort, responders, responderTarget)
	if err != nil {
		return err
	}
	if _, err := r.applyObjectIfChanged(ctx, gw, linkHashAnnotation, cm, &corev1.ConfigMap{}, force); err != nil {
		return err
	}

	if ident != nil {
		if _, err := r.applyObjectIfChanged(ctx, nil, linkHashAnnotation, buildLinkClusterRoleBinding(gw), &rbacv1.ClusterRoleBinding{}, force); err != nil {
			return err
		}
		_, err := r.applyObjectIfChanged(ctx, gw, linkHashAnnotation, buildLinkDaemonSet(gw, r.Config, ident), &appsv1.DaemonSet{}, force)
		return err
	}

	if _, err := r.applyObjectIfChanged(ctx, gw, linkHashAnnotation, buildLinkNetworkPolicy(gw, backends), &networkingv1.NetworkPolicy{}, force); err != nil {
		return err
	}
	if _, err := r.applyObjectIfChanged(ctx, gw, linkHashAnnotation, buildLinkDeployment(gw, r.Config), &appsv1.Deployment{}, force); err != nil {
		return err
	}

	if effectiveLinkReplicas(gw) > 1 {
		_, err := r.applyObjectIfChanged(ctx, gw, linkHashAnnotation, buildLinkPodDisruptionBudget(gw), &policyv1.PodDisruptionBudget{}, force)
		return err
	}
	// A scale-down to one replica must not leave a PDB behind to block node drains.
	pdb := &policyv1.PodDisruptionBudget{}
	found, err := r.objectExists(ctx, gw.Namespace, linkComponentName(gw), pdb)
	if err != nil {
		return err
	}
	if !found || pdb.GetDeletionTimestamp() != nil {
		return nil
	}
	return r.deleteIfPresent(ctx, pdb)
}

// ensureLinkID records the Local link id in status and in linkIDAnnotation, which outlives a
// restore that drops status. A status id wins: it names node state a restarting link reclaims.
func (r *GatewayReconciler) ensureLinkID(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	if !isLocal(gw) {
		return nil
	}
	if gw.Status.Link.ID > 0 {
		return r.persistLinkIDAnnotation(ctx, gw, gw.Status.Link.ID)
	}

	var gateways wgnetv1alpha1.GatewayList
	if err := r.APIReader.List(ctx, &gateways); err != nil {
		return fmt.Errorf("list gateways for link id allocation: %w", err)
	}
	self := client.ObjectKeyFromObject(gw)

	id, ok := r.adoptableLinkID(ctx, gw, gateways.Items, self)
	if !ok {
		if id, ok = lowestFreeLinkID(gateways.Items, self); !ok {
			return errNoFreeLinkID
		}
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for link id update: %w", err)
		}
		if fresh.Status.Link.ID > 0 {
			id = fresh.Status.Link.ID
			return nil
		}
		fresh.Status.Link.ID = id
		if err := r.Status().Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway link id: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	gw.Status.Link.ID = id
	return r.persistLinkIDAnnotation(ctx, gw, id)
}

// adoptableLinkID reports the id gw's annotation claims when well-formed and unheld elsewhere.
// Rejections are logged: the Gateway then takes an id its node state is not named after.
func (r *GatewayReconciler) adoptableLinkID(ctx context.Context, gw *wgnetv1alpha1.Gateway, gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) (int32, bool) {
	raw, present := gw.Annotations[linkIDAnnotation]
	if !present {
		return 0, false
	}
	logger := log.FromContext(ctx)
	claimed, err := parseLinkID(raw)
	if err != nil {
		logger.Info("ignoring link id annotation, allocating a fresh id",
			"gateway", self.String(), "annotation", raw, "reason", err.Error())
		return 0, false
	}
	if holder, taken := linkIDHolders(gateways, self)[claimed]; taken {
		logger.Info("ignoring link id annotation, allocating a fresh id",
			"gateway", self.String(), "annotation", raw, "reason", "held by "+holder.String())
		return 0, false
	}
	return claimed, true
}

// persistLinkIDAnnotation records id in gw's linkIDAnnotation, both on the server and on
// the in-memory copy. It is a no-op when the annotation already matches.
func (r *GatewayReconciler) persistLinkIDAnnotation(ctx context.Context, gw *wgnetv1alpha1.Gateway, id int32) error {
	want := strconv.FormatInt(int64(id), 10)
	if gw.Annotations[linkIDAnnotation] == want {
		return nil
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for link id annotation update: %w", err)
		}
		if fresh.Annotations[linkIDAnnotation] == want {
			return nil
		}
		if fresh.Annotations == nil {
			fresh.Annotations = make(map[string]string, 1)
		}
		fresh.Annotations[linkIDAnnotation] = want
		if err := r.Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway link id annotation: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if gw.Annotations == nil {
		gw.Annotations = make(map[string]string, 1)
	}
	gw.Annotations[linkIDAnnotation] = want
	return nil
}

// parseLinkID reads an annotated id, rejecting anything outside 1..link.MaxLinkID.
func parseLinkID(raw string) (int32, error) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("malformed link id annotation %q", raw)
	}
	if parsed < 1 || parsed > link.MaxLinkID {
		return 0, fmt.Errorf("link id annotation %q out of range 1..%d", raw, link.MaxLinkID)
	}
	return int32(parsed), nil
}

// linkIDHolders maps each held id to its Gateway, skipping self. Status id and annotated id both
// reserve: reallocating an annotated id would hand two links the same node-global names.
func linkIDHolders(gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) map[int32]client.ObjectKey {
	holders := make(map[int32]client.ObjectKey, len(gateways))
	for i := range gateways {
		g := &gateways[i]
		key := client.ObjectKeyFromObject(g)
		if key == self {
			continue
		}
		if g.Status.Link.ID > 0 {
			holders[g.Status.Link.ID] = key
		}
		if raw, ok := g.Annotations[linkIDAnnotation]; ok {
			if id, err := parseLinkID(raw); err == nil {
				holders[id] = key
			}
		}
	}
	return holders
}

// lowestFreeLinkID returns the lowest id in 1..link.MaxLinkID held by no Gateway,
// skipping self. A single active operator serialises the allocation.
func lowestFreeLinkID(gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) (int32, bool) {
	taken := linkIDHolders(gateways, self)
	for id := int32(1); id <= link.MaxLinkID; id++ {
		if _, ok := taken[id]; !ok {
			return id, true
		}
	}
	return 0, false
}

// deleteLinkLease removes the leader-election Lease the link pods create. It must run
// only once no link pod is left, or a live elector re-creates it.
func (r *GatewayReconciler) deleteLinkLease(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: linkComponentName(gw)},
	}
	if err := r.Delete(ctx, lease); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link lease %s/%s: %w", lease.Namespace, lease.Name, err)
	}
	return nil
}

// readGatewayKeys reads the key material ensureSecrets generated once: the VM's own private
// key and the link's public key, both from the Gateway's bundle Secret.
func (r *GatewayReconciler) readGatewayKeys(ctx context.Context, gw *wgnetv1alpha1.Gateway) (gatewayPrivateKey, linkPublicKey string, err error) {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: gw.Namespace, Name: bundleSecretName(gw)}
	if err := r.Get(ctx, key, &secret); err != nil {
		return "", "", fmt.Errorf("get bundle secret %s: %w", key, err)
	}
	gatewayPrivateKey, rest, _ := strings.Cut(string(secret.Data[wg.BundleKey]), "\n")
	linkPublicKey, _, _ = strings.Cut(rest, "\n")
	if gatewayPrivateKey == "" || linkPublicKey == "" {
		return "", "", fmt.Errorf("bundle secret %s carries no gateway key pair", key)
	}
	return gatewayPrivateKey, linkPublicKey, nil
}

// readLinkPeerPublicKey reads the single-instance peer key from the link Secret.
func (r *GatewayReconciler) readLinkPeerPublicKey(ctx context.Context, gw *wgnetv1alpha1.Gateway) (string, error) {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: gw.Namespace, Name: linkSecretName(gw)}
	if err := r.Get(ctx, key, &secret); err != nil {
		return "", fmt.Errorf("get link secret %s for peer public key: %w", key, err)
	}
	return string(secret.Data[wg.LinkPeerPublicKey]), nil
}

// appliedLinkPeers reads the peer list already applied to the link ConfigMap, nil when there is
// no ConfigMap yet. It is the last usable pass's membership, which an unusable pass keeps.
func (r *GatewayReconciler) appliedLinkPeers(ctx context.Context, gw *wgnetv1alpha1.Gateway) ([]link.Peer, error) {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	if err := r.Get(ctx, key, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get link configmap %s: %w", key, err)
	}
	var rc link.RuntimeConfig
	if err := json.Unmarshal([]byte(cm.Data[linkConfigKey]), &rc); err != nil {
		return nil, fmt.Errorf("decode link runtime config %s: %w", key, err)
	}
	return rc.WireGuard.Peers, nil
}

// rejectReservedHealthPort rejects a Local Gateway's TCP forward colliding with its own health
// port (27000 + link id, unknown at admission); Cluster's admission CEL rule catches this already.
func rejectReservedHealthPort(gw *wgnetv1alpha1.Gateway, valid []forwardBackend, invalid []invalidForward) ([]forwardBackend, []invalidForward, []wgnetv1alpha1.Forward) {
	if !isLocal(gw) {
		return valid, invalid, nil
	}
	healthPort := effectiveHealthPort(gw)
	var rejected []wgnetv1alpha1.Forward
	stillValid := make([]forwardBackend, 0, len(valid))
	for _, b := range valid {
		if b.Forward.Protocol == wgnetv1alpha1.ProtocolTCP && int(b.Forward.Port) == healthPort {
			invalid = append(invalid, invalidForward{reasonReservedHealthPort,
				fmt.Sprintf("forward TCP port %d collides with this gateway's own health port", healthPort)})
			rejected = append(rejected, b.Forward)
			continue
		}
		stillValid = append(stillValid, b)
	}
	return stillValid, invalid, rejected
}

// partitionTerminatingLinkPods splits link pods into those teardown waits for and those deleted
// longer ago than their grace period plus linkTeardownSlack. Sorted, so messages stay stable.
func partitionTerminatingLinkPods(pods []corev1.Pod) (holding, stuck []string) {
	for i := range pods {
		pod := &pods[i]
		deletedAt := pod.DeletionTimestamp
		grace := int64(corev1.DefaultTerminationGracePeriodSeconds)
		if pod.Spec.TerminationGracePeriodSeconds != nil {
			grace = *pod.Spec.TerminationGracePeriodSeconds
		}
		if deletedAt.IsZero() || time.Since(deletedAt.Time) <= time.Duration(grace)*time.Second+linkTeardownSlack {
			holding = append(holding, pod.Name)
			continue
		}
		stuck = append(stuck, pod.Name)
	}
	slices.Sort(holding)
	slices.Sort(stuck)
	return holding, stuck
}

// markTerminatingOnLinkPods publishes why the delete is still held, so a Gateway waiting
// on its link pods names them rather than showing a stale condition from before the delete.
func (r *GatewayReconciler) markTerminatingOnLinkPods(ctx context.Context, gw *wgnetv1alpha1.Gateway, pods []string) error {
	if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonTerminating,
		Message:            "waiting for link pods to exit: " + strings.Join(pods, ", "),
		ObservedGeneration: gw.Generation,
	}); changed {
		if err := r.Status().Update(ctx, gw); err != nil {
			return fmt.Errorf("update gateway status: %w", err)
		}
	}
	return nil
}

// linkStatusOf reports the Lease holder's readiness, node and fault; a missing holder is a zero
// value, not an error. It reads the holder, not the expiry, which fail-static leaves stale.
func (r *GatewayReconciler) linkStatusOf(ctx context.Context, gw *wgnetv1alpha1.Gateway) (linkStatus, error) {
	var lease coordinationv1.Lease
	leaseKey := client.ObjectKey{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	if err := r.APIReader.Get(ctx, leaseKey, &lease); err != nil {
		if apierrors.IsNotFound(err) {
			return linkStatus{}, nil
		}
		return linkStatus{}, fmt.Errorf("get link lease %s: %w", leaseKey, err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return linkStatus{}, nil
	}

	var ls linkStatus
	if reason := lease.Annotations[link.LeaseFaultAnnotation]; knownLinkFaults[reason] {
		ls.FaultReason = reason
		ls.FaultMessage = truncateFaultMessage(lease.Annotations[link.LeaseFaultMessageAnnotation])
		if ls.FaultMessage == "" {
			ls.FaultMessage = fmt.Sprintf("link reported %s", reason)
		}
	}

	var holder corev1.Pod
	holderKey := client.ObjectKey{Namespace: gw.Namespace, Name: *lease.Spec.HolderIdentity}
	if err := r.APIReader.Get(ctx, holderKey, &holder); err != nil {
		if apierrors.IsNotFound(err) {
			return ls, nil
		}
		return linkStatus{}, fmt.Errorf("get link lease holder pod %s: %w", holderKey, err)
	}
	ls.Node = holder.Spec.NodeName
	ls.PodReady = podReady(&holder)
	ls.Active = ls.PodReady && lease.Annotations[link.LeaseTunnelReadyAnnotation] == "true"
	return ls, nil
}

// warnReservedHealthPort emits one Warning per forward rejected for taking the link's own health
// port, while the rejected set is unchanged, mirroring warnUnresolvedBackendPorts.
func (r *GatewayReconciler) warnReservedHealthPort(gw *wgnetv1alpha1.Gateway, rejected []wgnetv1alpha1.Forward) {
	if r.Recorder == nil {
		return
	}
	key := reservedHealthPortWarnKeyPrefix + unresolvedWarnKey(gw)
	if len(rejected) == 0 {
		r.unresolvedWarned.Delete(key)
		return
	}
	signature := fmt.Sprintf("%v", rejected)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
		return
	}
	r.unresolvedWarned.Store(key, signature)
	for _, f := range rejected {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonReservedHealthPort, actionReconcile,
			"forward %s port %d to Service %q collides with this gateway's own health port",
			strings.ToLower(string(f.Protocol)), f.Port, f.Service)
	}
}

// warnInvalidTunnelAddresses emits one Warning per distinct invalid-tunnel-address reason,
// suppressing a repeat while the reason stays unchanged, mirroring warnUnresolvedBackendPorts.
func (r *GatewayReconciler) warnInvalidTunnelAddresses(gw *wgnetv1alpha1.Gateway, reason string) {
	if r.Recorder == nil {
		return
	}
	key := invalidTunnelWarnKeyPrefix + unresolvedWarnKey(gw)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == reason {
		return
	}
	r.unresolvedWarned.Store(key, reason)
	r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonInvalidTunnelAddresses, actionReconcile, "%s", reason)
}

// warnInsufficientTunnelAddresses emits one Warning while the capacity message is unchanged,
// mirroring warnInvalidTunnelAddresses.
func (r *GatewayReconciler) warnInsufficientTunnelAddresses(gw *wgnetv1alpha1.Gateway, message string) {
	if r.Recorder == nil {
		return
	}
	key := capacityWarnKeyPrefix + unresolvedWarnKey(gw)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == message {
		return
	}
	r.unresolvedWarned.Store(key, message)
	r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonInsufficientTunnelAddresses, actionReconcile, "%s", message)
}
