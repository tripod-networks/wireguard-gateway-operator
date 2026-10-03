package controller

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
	hk8s "github.com/tripod-networks/wireguard-gateway-operator/test/harness/k8s"
)

// clusterBackends is the shape classifyForwards produces for a Cluster-mode Gateway whose
// Services publish numeric targetPorts: a resolved backend port and an unnamed Service port.
func clusterBackends(forwards []wgnetv1alpha1.Forward) []forwardBackend {
	backends := make([]forwardBackend, 0, len(forwards))
	for _, f := range forwards {
		backends = append(backends, forwardBackend{Forward: f, BackendPort: effectiveServicePort(f)})
	}
	return backends
}

func TestBuildBundleSecret(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	sec := buildBundleSecret(gw, "GATEWAY_PRIV", "LINK_PUB")

	if sec.Name != "edge-bundle" {
		t.Errorf("bundle secret name = %q, want edge-bundle", sec.Name)
	}
	if sec.Namespace != "wg-system" {
		t.Errorf("bundle secret namespace = %q, want wg-system", sec.Namespace)
	}
	if sec.Type != corev1.SecretTypeOpaque {
		t.Errorf("bundle secret type = %q, want Opaque", sec.Type)
	}
	got := string(sec.Data[wg.BundleKey])
	want := "GATEWAY_PRIV\nLINK_PUB\n"
	if got != want {
		t.Errorf("bundle data[%q] = %q, want %q", wg.BundleKey, got, want)
	}
	if len(sec.Data) != 1 {
		t.Errorf("bundle data keys = %d, want 1", len(sec.Data))
	}
}

func TestBuildLinkSecret(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	sec := buildLinkSecret(gw, "LINK_PRIV", "GATEWAY_PUB")

	if sec.Name != "edge-link" {
		t.Errorf("link secret name = %q, want edge-link", sec.Name)
	}
	if got := string(sec.Data[wg.LinkPrivateKey]); got != "LINK_PRIV" {
		t.Errorf("link data[%q] = %q, want LINK_PRIV", wg.LinkPrivateKey, got)
	}
	if got := string(sec.Data[wg.LinkPeerPublicKey]); got != "GATEWAY_PUB" {
		t.Errorf("link data[%q] = %q, want GATEWAY_PUB", wg.LinkPeerPublicKey, got)
	}
}

func TestBuildLinkConfigMap(t *testing.T) {
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		}, nil)

	cm, err := buildLinkConfigMap(gw, "", clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort, nil, "")
	if err != nil {
		t.Fatalf("buildLinkConfigMap: %v", err)
	}
	if cm.Name != "edge-link" {
		t.Errorf("link configmap name = %q, want edge-link", cm.Name)
	}

	raw, ok := cm.Data[linkConfigKey]
	if !ok {
		t.Fatalf("configmap missing %q", linkConfigKey)
	}
	var rc link.RuntimeConfig
	decodeJSON(t, raw, &rc)

	if rc.WireGuard.Address != "10.99.0.2/29" {
		t.Errorf("wireguard.address = %q, want 10.99.0.2/29", rc.WireGuard.Address)
	}
	wantMTU := int(effectiveWGMTU(gw))
	if rc.WireGuard.MTU != wantMTU {
		t.Errorf("wireguard.mtu = %d, want %d", rc.WireGuard.MTU, wantMTU)
	}
	wantKeepalive := int(effectiveWGKeepalive(gw))
	if rc.WireGuard.Peers[0].PersistentKeepalive != wantKeepalive {
		t.Errorf("peer.persistentKeepalive = %d, want %d", rc.WireGuard.Peers[0].PersistentKeepalive, wantKeepalive)
	}
	wantSubnet := effectiveWGSubnet(gw)
	if len(rc.WireGuard.Peers[0].AllowedIPs) != 1 || rc.WireGuard.Peers[0].AllowedIPs[0] != wantSubnet {
		t.Errorf("peer.allowedIPs = %v, want [%s]", rc.WireGuard.Peers[0].AllowedIPs, wantSubnet)
	}

	if rc.WireGuard.Peers[0].Endpoint != "" {
		t.Errorf("peer.endpoint = %q, want empty when address is unknown", rc.WireGuard.Peers[0].Endpoint)
	}

	wantForwards := []link.Forward{
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Service: "web.wg-system.svc.cluster.local", TargetPort: 8443},
		{Name: "udp-1194", PublicPort: 1194, Protocol: "udp", Service: "vpn.wg-system.svc.cluster.local", TargetPort: 1194},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}
}

// TestBuildLinkConfigMapHealthPort pins that the healthPort argument flows verbatim onto
// the RuntimeConfig's HealthPort field.
func TestBuildLinkConfigMapHealthPort(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)

	cm, err := buildLinkConfigMap(gw, "", nil, nil, "GATEWAY_PUB_TEST", nil, 8181, nil, "")
	if err != nil {
		t.Fatalf("buildLinkConfigMap: %v", err)
	}
	var rc link.RuntimeConfig
	decodeJSON(t, cm.Data[linkConfigKey], &rc)

	if rc.HealthPort != 8181 {
		t.Errorf("healthPort = %d, want 8181", rc.HealthPort)
	}
}

// TestBuildLinkConfigMapEndpoint pins the address passed in as publicAddress in every traffic
// policy, and the peer endpoints: host:port for a single instance, the members' own otherwise.
func TestBuildLinkConfigMapEndpoint(t *testing.T) {
	fleetPeers := []link.Peer{
		{Slot: 0, PublicKey: "MEMBER0=", Endpoint: "198.51.100.1:51820", AllowedIPs: []string{"0.0.0.0/0"}},
		{Slot: 1, PublicKey: "MEMBER1=", Endpoint: "198.51.100.2:51820", AllowedIPs: []string{"0.0.0.0/0"}},
	}
	tests := []struct {
		name              string
		local             bool
		loadBalancer      bool
		address           string
		wantEndpoints     []string
		wantPublicAddress string
	}{
		{
			name:              "cluster single instance with an address",
			address:           "203.0.113.5",
			wantEndpoints:     []string{"203.0.113.5:51820"},
			wantPublicAddress: "203.0.113.5",
		},
		{
			name:          "cluster single instance without an address",
			wantEndpoints: []string{""},
		},
		{
			name:              "cluster load balancer with an address",
			loadBalancer:      true,
			address:           "203.0.113.9",
			wantEndpoints:     []string{"198.51.100.1:51820", "198.51.100.2:51820"},
			wantPublicAddress: "203.0.113.9",
		},
		{
			name:          "cluster load balancer without an address",
			loadBalancer:  true,
			wantEndpoints: []string{"198.51.100.1:51820", "198.51.100.2:51820"},
		},
		{
			name:              "local single instance with an address",
			local:             true,
			address:           "203.0.113.5",
			wantEndpoints:     []string{"203.0.113.5:51820"},
			wantPublicAddress: "203.0.113.5",
		},
		{
			name:          "local single instance without an address",
			local:         true,
			wantEndpoints: []string{""},
		},
		{
			name:              "local load balancer with an address",
			local:             true,
			loadBalancer:      true,
			address:           "203.0.113.9",
			wantEndpoints:     []string{"198.51.100.1:51820", "198.51.100.2:51820"},
			wantPublicAddress: "203.0.113.9",
		},
		{
			name:          "local load balancer without an address",
			local:         true,
			loadBalancer:  true,
			wantEndpoints: []string{"198.51.100.1:51820", "198.51.100.2:51820"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system",
				[]wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}, nil)
			var peers []link.Peer
			if tt.local {
				gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
				gw.Status.Link.ID = 3
			}
			if tt.loadBalancer {
				gw.Spec.GCP.LoadBalancer = &wgnetv1alpha1.GatewayGCPLoadBalancerSpec{SessionAffinity: "NONE"}
				peers = fleetPeers
			}

			cm, err := buildLinkConfigMap(gw, tt.address, clusterBackends(gw.Spec.Forwards), linkIdentityOf(gw), "GATEWAY_PUB_TEST", peers, effectiveHealthPort(gw), nil, "")
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}
			rc := loadLinkConfig(t, cm)

			if rc.PublicAddress != tt.wantPublicAddress {
				t.Errorf("publicAddress = %q, want %q", rc.PublicAddress, tt.wantPublicAddress)
			}
			endpoints := make([]string, 0, len(rc.WireGuard.Peers))
			for _, p := range rc.WireGuard.Peers {
				endpoints = append(endpoints, p.Endpoint)
			}
			if !slices.Equal(endpoints, tt.wantEndpoints) {
				t.Errorf("peer endpoints = %v, want %v", endpoints, tt.wantEndpoints)
			}
		})
	}
}

// loadLinkConfig loads cm's config through the link daemon's own parse-and-validate path.
func loadLinkConfig(t *testing.T, cm *corev1.ConfigMap) link.RuntimeConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), linkConfigKey)
	if err := os.WriteFile(path, []byte(cm.Data[linkConfigKey]), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	rc, err := link.LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("link.LoadRuntimeConfig: %v", err)
	}
	return rc
}

// TestBuildLinkConfigMapTargetPortDefault covers the target-port defaulting rule:
// an unset TargetPort mirrors Port, while a set one is preserved verbatim.
func TestBuildLinkConfigMapTargetPortDefault(t *testing.T) {
	tests := []struct {
		name           string
		targetPort     int32
		wantTargetPort int
	}{
		{"zero defaults to port", 0, 443},
		{"set distinct from port preserved", 8443, 8443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system",
				[]wgnetv1alpha1.Forward{
					{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: tt.targetPort},
				}, nil)

			cm, err := buildLinkConfigMap(gw, "", clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort, nil, "")
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}
			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)

			if len(rc.Forwards) != 1 {
				t.Fatalf("forwards = %d, want 1", len(rc.Forwards))
			}
			if got := rc.Forwards[0].TargetPort; got != tt.wantTargetPort {
				t.Errorf("targetPort = %d, want %d", got, tt.wantTargetPort)
			}
		})
	}
}

// TestBuildLinkConfigMapRoundTrip guards that the ConfigMap the operator writes is one the
// link daemon accepts, by loading the emitted JSON through the real parse-and-validate path.
func TestBuildLinkConfigMapRoundTrip(t *testing.T) {
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443},
			{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"},
		}, nil)

	cm, err := buildLinkConfigMap(gw, "", clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort, nil, "")
	if err != nil {
		t.Fatalf("buildLinkConfigMap: %v", err)
	}

	rc := loadLinkConfig(t, cm)

	wantForwards := []link.Forward{
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Service: "web.wg-system.svc.cluster.local", TargetPort: 8443},
		{Name: "udp-1194", PublicPort: 1194, Protocol: "udp", Service: "vpn.wg-system.svc.cluster.local", TargetPort: 1194},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("loaded forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}
}

// TestBuildLinkConfigMapServiceFQDN pins that the runtime config carries a fully-qualified
// Service name, so resolution does not depend on the pod's resolv.conf ndots.
func TestBuildLinkConfigMapServiceFQDN(t *testing.T) {
	tests := []struct {
		name        string
		forward     wgnetv1alpha1.Forward
		wantService string
	}{
		{
			name:        "same namespace defaults to gateway namespace",
			forward:     wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			wantService: "web.wg-system.svc.cluster.local",
		},
		{
			name:        "explicit cross namespace",
			forward:     wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "db", Namespace: "prod"},
			wantService: "db.prod.svc.cluster.local",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", []wgnetv1alpha1.Forward{tt.forward}, nil)
			cm, err := buildLinkConfigMap(gw, "", clusterBackends(gw.Spec.Forwards), nil, "GATEWAY_PUB_TEST", nil, clusterHealthPort, nil, "")
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}
			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)
			if len(rc.Forwards) != 1 {
				t.Fatalf("forwards = %d, want 1", len(rc.Forwards))
			}
			if got := rc.Forwards[0].Service; got != tt.wantService {
				t.Errorf("forward service = %q, want %q", got, tt.wantService)
			}
		})
	}
}

// hasNoPeerEgressPort matches a rule with no `to` peer, as the apiserver rule is, since
// in-cluster apiserver addressing varies by environment.
func hasNoPeerEgressPort(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol, port int32) bool {
	for _, r := range rules {
		if len(r.To) != 0 {
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

func hasDNSEgress(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol) bool {
	for _, r := range rules {
		dns := false
		for _, peer := range r.To {
			if peer.NamespaceSelector == nil || peer.PodSelector == nil {
				continue
			}
			if peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "kube-system" &&
				peer.PodSelector.MatchLabels["k8s-app"] == "kube-dns" {
				dns = true
				break
			}
		}
		if !dns {
			continue
		}
		for _, p := range r.Ports {
			if p.Protocol != nil && *p.Protocol == proto && p.Port != nil && p.Port.IntVal == 53 {
				return true
			}
		}
	}
	return false
}

// hasResponderEgress reports whether an egress rule permits proto/port to a single 0.0.0.0/0
// peer with no pod selector: the shape needed for the DNAT-rewritten health probe.
func hasResponderEgress(rules []networkingv1.NetworkPolicyEgressRule, proto corev1.Protocol, port int32) bool {
	for _, r := range rules {
		if len(r.To) != 1 || r.To[0].IPBlock == nil || r.To[0].IPBlock.CIDR != "0.0.0.0/0" || r.To[0].PodSelector != nil {
			continue
		}
		if len(r.Ports) != 1 {
			continue
		}
		p := r.Ports[0]
		if p.Protocol != nil && *p.Protocol == proto && p.Port != nil && p.Port.IntVal == port {
			return true
		}
	}
	return false
}

// fixedEgressRules is the count of egress rules buildLinkNetworkPolicy emits before the
// per-forward ones: kube-dns, the WireGuard underlay, the apiserver, and the responder Service.
const fixedEgressRules = 4

// TestBuildLinkNetworkPolicy pins each forward's rule to the Service port plus the pod-side
// port it DNATs to, since CNIs evaluate egress before or after kube-proxy rewrites it.
func TestBuildLinkNetworkPolicy(t *testing.T) {
	// port 0 means the entry must carry no port at all, allowing the whole protocol.
	type wantPort struct {
		proto corev1.Protocol
		port  int32
	}

	tests := []struct {
		name     string
		backends []forwardBackend
		// wantRules are the per-forward egress rules, in order, each holding the
		// exact port entries that rule must carry.
		wantRules [][]wantPort
	}{
		{
			name: "tcp and udp forwards whose service port is the pod port",
			backends: []forwardBackend{
				{Forward: wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web", TargetPort: 8443}, BackendPort: 8443},
				{Forward: wgnetv1alpha1.Forward{Port: 1194, Protocol: wgnetv1alpha1.ProtocolUDP, Service: "vpn"}, BackendPort: 1194},
			},
			wantRules: [][]wantPort{
				{{corev1.ProtocolTCP, 8443}},
				{{corev1.ProtocolUDP, 1194}},
			},
		},
		{
			name: "service target ports differing from the service port are allowed too",
			backends: []forwardBackend{
				{Forward: wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}, BackendPort: 10443},
				{Forward: wgnetv1alpha1.Forward{Port: 80, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}, BackendPort: 10080},
			},
			wantRules: [][]wantPort{
				{{corev1.ProtocolTCP, 443}, {corev1.ProtocolTCP, 10443}},
				{{corev1.ProtocolTCP, 80}, {corev1.ProtocolTCP, 10080}},
			},
		},
		{
			// A named Service targetPort resolves to 0: the pod port is unknown, so the rule
			// drops its ports rather than name one the pod never listens on; nftables remains.
			name: "unresolved backend port allows the whole protocol",
			backends: []forwardBackend{
				{Forward: wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}},
			},
			wantRules: [][]wantPort{{{corev1.ProtocolTCP, 0}}},
		},
		{
			name:     "no forwards still permits control-plane egress",
			backends: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", forwardSpecs(tt.backends), nil)

			np := buildLinkNetworkPolicy(gw, tt.backends)

			if np.Name != "edge-link" {
				t.Errorf("networkpolicy name = %q, want edge-link", np.Name)
			}
			if !slices.Equal(np.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}) {
				t.Errorf("policyTypes = %v, want [Egress]", np.Spec.PolicyTypes)
			}

			egress := np.Spec.Egress
			if !hasDNSEgress(egress, corev1.ProtocolUDP) || !hasDNSEgress(egress, corev1.ProtocolTCP) {
				t.Errorf("egress missing kube-dns UDP/TCP 53 rules: %+v", egress)
			}
			wgPort := effectiveWireguardPort(gw)
			if !hasOpenEgressPort(egress, corev1.ProtocolUDP, wgPort) {
				t.Errorf("egress missing WireGuard UDP %d rule: %+v", wgPort, egress)
			}
			if !hasNoPeerEgressPort(egress, corev1.ProtocolTCP, 443) {
				t.Errorf("egress missing apiserver TCP 443 rule (Lease leader election): %+v", egress)
			}
			if !hasNoPeerEgressPort(egress, corev1.ProtocolTCP, 6443) {
				t.Errorf("egress missing apiserver TCP 6443 rule (Lease leader election): %+v", egress)
			}
			if !hasResponderEgress(egress, corev1.ProtocolTCP, effectiveResponderPort(gw)) {
				t.Errorf("egress missing responder TCP %d rule: %+v", effectiveResponderPort(gw), egress)
			}

			if len(egress) != fixedEgressRules+len(tt.wantRules) {
				t.Fatalf("egress rules = %d, want %d: %+v", len(egress), fixedEgressRules+len(tt.wantRules), egress)
			}
			for i, want := range tt.wantRules {
				rule := egress[fixedEgressRules+i]
				if len(rule.To) != 1 || rule.To[0].IPBlock == nil || rule.To[0].IPBlock.CIDR != "0.0.0.0/0" {
					t.Errorf("forward rule %d peer = %+v, want a single 0.0.0.0/0 IPBlock", i, rule.To)
				}
				if len(rule.Ports) != len(want) {
					t.Errorf("forward rule %d ports = %+v, want %d entries", i, rule.Ports, len(want))
					continue
				}
				for j, w := range want {
					got := rule.Ports[j]
					if got.Protocol == nil || *got.Protocol != w.proto {
						t.Errorf("forward rule %d port %d protocol = %v, want %s", i, j, got.Protocol, w.proto)
					}
					switch {
					case w.port == 0 && got.Port != nil:
						t.Errorf("forward rule %d port %d = %v, want no port", i, j, got.Port)
					case w.port != 0 && (got.Port == nil || got.Port.IntVal != w.port):
						t.Errorf("forward rule %d port %d = %v, want %d", i, j, got.Port, w.port)
					}
				}
			}
		})
	}
}

func TestBuildLinkDeployment(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Wireguard.ReconcileInterval = "10s"

	dep := buildLinkDeployment(gw, cfg)

	if dep.Name != "edge-link" {
		t.Errorf("deployment name = %q, want edge-link", dep.Name)
	}
	if got := *dep.Spec.Replicas; got != 1 {
		t.Errorf("replicas = %d, want 1 (default)", got)
	}

	// The link is leader-elected, so it rolls (maxSurge=1, maxUnavailable=0) rather
	// than using Recreate: the lease, not the rollout, keeps a single pod active.
	if dep.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		t.Errorf("strategy = %q, want RollingUpdate", dep.Spec.Strategy.Type)
	}
	if ru := dep.Spec.Strategy.RollingUpdate; ru == nil {
		t.Error("strategy.rollingUpdate = nil, want maxSurge=1/maxUnavailable=0")
	} else {
		if ru.MaxSurge == nil || ru.MaxSurge.IntVal != 1 {
			t.Errorf("strategy.rollingUpdate.maxSurge = %+v, want 1", ru.MaxSurge)
		}
		if ru.MaxUnavailable == nil || ru.MaxUnavailable.IntVal != 0 {
			t.Errorf("strategy.rollingUpdate.maxUnavailable = %+v, want 0", ru.MaxUnavailable)
		}
	}

	podSpec := dep.Spec.Template.Spec

	// IP forwarding is enabled by a privileged init container writing the shared pod
	// netns, not a kubelet-allowlisted pod sysctl.
	if len(podSpec.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want 1", len(podSpec.InitContainers))
	}
	ic := podSpec.InitContainers[0]
	if ic.Image != cfg.LinkImage {
		t.Errorf("init container image = %q, want %q", ic.Image, cfg.LinkImage)
	}
	if !strings.Contains(strings.Join(ic.Command, " "), "echo 1 > /proc/sys/net/ipv4/ip_forward") {
		t.Errorf("init container command = %v, want it to enable forwarding via echo 1 > /proc/sys/net/ipv4/ip_forward", ic.Command)
	}
	if ic.SecurityContext == nil || ic.SecurityContext.Privileged == nil || !*ic.SecurityContext.Privileged {
		t.Errorf("init container privileged = %+v, want true", ic.SecurityContext)
	}
	if ic.SecurityContext == nil || ic.SecurityContext.RunAsUser == nil || *ic.SecurityContext.RunAsUser != 0 {
		t.Errorf("init container runAsUser = %+v, want 0", ic.SecurityContext)
	}

	var sysctls, wantSysctls []corev1.Sysctl
	if podSpec.SecurityContext != nil {
		sysctls = podSpec.SecurityContext.Sysctls
	}
	if !slices.Equal(sysctls, wantSysctls) {
		t.Errorf("pod sysctls = %+v, want %+v", sysctls, wantSysctls)
	}

	for _, ctr := range podSpec.Containers {
		if ctr.SecurityContext != nil && ctr.SecurityContext.Privileged != nil && *ctr.SecurityContext.Privileged {
			t.Errorf("main container %q is privileged, want not privileged", ctr.Name)
		}
	}

	containers := podSpec.Containers
	if len(containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(containers))
	}
	c := containers[0]
	if c.Image != cfg.LinkImage {
		t.Errorf("image = %q, want %q", c.Image, cfg.LinkImage)
	}
	if len(c.Command) != 1 || c.Command[0] != "gateway-link" {
		t.Errorf("command = %v, want [gateway-link]", c.Command)
	}
	if c.SecurityContext == nil || c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser != 0 {
		t.Errorf("securityContext.runAsUser = %+v, want 0", c.SecurityContext)
	}
	if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		t.Errorf("securityContext.allowPrivilegeEscalation = %+v, want false", c.SecurityContext)
	}
	if c.SecurityContext == nil || len(c.SecurityContext.Capabilities.Add) != 1 || c.SecurityContext.Capabilities.Add[0] != "NET_ADMIN" {
		t.Errorf("capabilities = %+v, want add NET_ADMIN", c.SecurityContext)
	}

	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	wantEnv := map[string]string{
		"GATEWAY_RECONCILE_INTERVAL":  "10s",
		"GATEWAY_CONFIG_PATH":         "/etc/gateway/config/config.json",
		"GATEWAY_WG_KEY_PATH":         "/etc/gateway/wg/" + wg.LinkPrivateKey,
		"GATEWAY_WG_PEER_PUBKEY_PATH": "/etc/gateway/wg/" + wg.LinkPeerPublicKey,
	}
	for k, want := range wantEnv {
		if env[k] != want {
			t.Errorf("env[%q] = %q, want %q", k, env[k], want)
		}
	}

	// The config ConfigMap must mount as a live directory, never a subPath: a subPath mount
	// is copied once at start and never refreshed, defeating the link's in-place reload.
	mounts := map[string]corev1.VolumeMount{}
	for _, m := range c.VolumeMounts {
		mounts[m.Name] = m
	}
	configMount, ok := mounts["config"]
	if !ok {
		t.Fatal("config volume mount missing")
	}
	if configMount.MountPath != "/etc/gateway/config" {
		t.Errorf("config mount path = %q, want /etc/gateway/config", configMount.MountPath)
	}
	if configMount.SubPath != "" {
		t.Errorf("config mount has subPath %q, want none (subPath defeats in-place reload)", configMount.SubPath)
	}
	if env["GATEWAY_CONFIG_PATH"] != "/etc/gateway/config/config.json" {
		t.Errorf("GATEWAY_CONFIG_PATH = %q, want /etc/gateway/config/config.json", env["GATEWAY_CONFIG_PATH"])
	}

	// The link does not read the XGatewayGCP, so it carries no cluster-lookup env.
	envNames := make([]string, 0, len(c.Env))
	for _, e := range c.Env {
		envNames = append(envNames, e.Name)
	}
	slices.Sort(envNames)
	wantEnvNames := []string{
		"GATEWAY_CONFIG_PATH", "GATEWAY_HEALTH_ADDR", "GATEWAY_LEASE_NAME",
		"GATEWAY_RECONCILE_INTERVAL", "GATEWAY_WG_KEY_PATH", "GATEWAY_WG_PEER_PUBKEY_PATH",
		"POD_NAME", "POD_NAMESPACE",
	}
	if !reflect.DeepEqual(envNames, wantEnvNames) {
		t.Errorf("link container env names = %v, want %v", envNames, wantEnvNames)
	}

	// Leader election needs the projected ServiceAccount token, so the pod runs
	// under the link SA and automounts its token.
	if podSpec.ServiceAccountName != linkComponentName(gw) {
		t.Errorf("serviceAccountName = %q, want %q", podSpec.ServiceAccountName, linkComponentName(gw))
	}
	if podSpec.AutomountServiceAccountToken == nil || !*podSpec.AutomountServiceAccountToken {
		t.Errorf("automountServiceAccountToken = %v, want true (leader election needs the token)", podSpec.AutomountServiceAccountToken)
	}

	if podSpec.TerminationGracePeriodSeconds == nil || *podSpec.TerminationGracePeriodSeconds != 30 {
		t.Errorf("terminationGracePeriodSeconds = %v, want 30", podSpec.TerminationGracePeriodSeconds)
	}

	// GATEWAY_LEASE_NAME is the literal lease name; POD_NAMESPACE and POD_NAME come
	// from the downward API so each pod elects under its own identity.
	if env["GATEWAY_LEASE_NAME"] != linkComponentName(gw) {
		t.Errorf("env[GATEWAY_LEASE_NAME] = %q, want %q", env["GATEWAY_LEASE_NAME"], linkComponentName(gw))
	}
	assertFieldRefEnv(t, c.Env, "POD_NAMESPACE", "metadata.namespace")
	assertFieldRefEnv(t, c.Env, "POD_NAME", "metadata.name")

	assertHostnameAntiAffinity(t, podSpec.Affinity, linkSelectorLabels(gw))

	// In-place reload means no config-checksum roll trigger.
	var wantAnnotations map[string]string
	if got := dep.Spec.Template.Annotations; !maps.Equal(got, wantAnnotations) {
		t.Errorf("pod template annotations = %v, want %v", got, wantAnnotations)
	}
}

func assertFieldRefEnv(t *testing.T, env []corev1.EnvVar, name, fieldPath string) {
	t.Helper()
	for _, e := range env {
		if e.Name != name {
			continue
		}
		if e.Value != "" {
			t.Errorf("env[%q] has literal value %q, want valueFrom fieldRef %q", name, e.Value, fieldPath)
		}
		if e.ValueFrom == nil || e.ValueFrom.FieldRef == nil {
			t.Fatalf("env[%q] = %+v, want valueFrom fieldRef %q", name, e, fieldPath)
		}
		if got := e.ValueFrom.FieldRef.FieldPath; got != fieldPath {
			t.Errorf("env[%q] fieldRef = %q, want %q", name, got, fieldPath)
		}
		return
	}
	t.Errorf("env missing %q (valueFrom fieldRef %q)", name, fieldPath)
}

// assertHostnameAntiAffinity checks the soft anti-affinity term keyed on node hostname,
// which is what spreads the link replicas across nodes.
func assertHostnameAntiAffinity(t *testing.T, affinity *corev1.Affinity, wantSelector map[string]string) {
	t.Helper()
	if affinity == nil || affinity.PodAntiAffinity == nil {
		t.Fatalf("affinity = %+v, want podAntiAffinity", affinity)
	}
	terms := affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution
	if len(terms) != 1 {
		t.Fatalf("preferred anti-affinity terms = %d, want 1", len(terms))
	}
	term := terms[0]
	if term.Weight != 100 {
		t.Errorf("anti-affinity weight = %d, want 100", term.Weight)
	}
	if term.PodAffinityTerm.TopologyKey != "kubernetes.io/hostname" {
		t.Errorf("anti-affinity topologyKey = %q, want kubernetes.io/hostname", term.PodAffinityTerm.TopologyKey)
	}
	sel := term.PodAffinityTerm.LabelSelector
	if sel == nil {
		t.Fatal("anti-affinity labelSelector = nil, want link selector")
	}
	if !maps.Equal(sel.MatchLabels, wantSelector) {
		t.Errorf("anti-affinity labelSelector = %v, want %v", sel.MatchLabels, wantSelector)
	}
}

// TestBuildLinkDeploymentReplicas pins that replicas default to 1 and honor an explicit
// value, which is what enables a hot-standby Gateway.
func TestBuildLinkDeploymentReplicas(t *testing.T) {
	cfg := testConfig()
	tests := []struct {
		name     string
		replicas int32
		want     int32
	}{
		{"unset defaults to 1", 0, 1},
		{"explicit 3 honored", 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.Link.Replicas = tt.replicas

			dep := buildLinkDeployment(gw, cfg)
			if dep.Spec.Replicas == nil || *dep.Spec.Replicas != tt.want {
				t.Errorf("replicas = %v, want %d", dep.Spec.Replicas, tt.want)
			}
		})
	}
}

// TestEffectiveLinkReplicas pins the replica-defaulting accessor: an unset value
// resolves to the CRD default of 1 and an explicit value passes through.
func TestEffectiveLinkReplicas(t *testing.T) {
	tests := []struct {
		name     string
		replicas int32
		want     int32
	}{
		{"zero defaults to 1", 0, 1},
		{"explicit 1", 1, 1},
		{"explicit 3", 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.Link.Replicas = tt.replicas
			if got := effectiveLinkReplicas(gw); got != tt.want {
				t.Errorf("effectiveLinkReplicas = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestBuildLinkServiceAccount pins the link ServiceAccount's name, namespace, and
// labels; its token is the credential the link presents for leader election.
func TestBuildLinkServiceAccount(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	sa := buildLinkServiceAccount(gw)

	if sa.Name != "edge-link" {
		t.Errorf("serviceaccount name = %q, want edge-link", sa.Name)
	}
	if sa.Namespace != "wg-system" {
		t.Errorf("serviceaccount namespace = %q, want wg-system", sa.Namespace)
	}
	if got := sa.Labels["app.kubernetes.io/component"]; got != componentLink {
		t.Errorf("serviceaccount component label = %q, want %q", got, componentLink)
	}
}

// TestBuildLinkRole pins the Cluster-mode Role to exactly the verbs leader election needs
// on leases and nothing else, because a Cluster link never watches pods.
func TestBuildLinkRole(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	role := buildLinkRole(gw)

	if role.Name != "edge-link" {
		t.Errorf("role name = %q, want edge-link", role.Name)
	}
	if role.Namespace != "wg-system" {
		t.Errorf("role namespace = %q, want wg-system", role.Namespace)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("role rules = %d, want 1", len(role.Rules))
	}
	rule := role.Rules[0]
	if !slices.Equal(rule.APIGroups, []string{"coordination.k8s.io"}) {
		t.Errorf("rule apiGroups = %v, want [coordination.k8s.io]", rule.APIGroups)
	}
	if !slices.Equal(rule.Resources, []string{"leases"}) {
		t.Errorf("rule resources = %v, want [leases]", rule.Resources)
	}
	wantVerbs := []string{"get", "list", "watch", "create", "update"}
	if !slices.Equal(rule.Verbs, wantVerbs) {
		t.Errorf("rule verbs = %v, want %v", rule.Verbs, wantVerbs)
	}
}

// TestBuildLinkRoleBinding pins the binding of the link Role to the link ServiceAccount,
// the grant that lets the link pods elect.
func TestBuildLinkRoleBinding(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	rb := buildLinkRoleBinding(gw)

	if rb.Name != "edge-link" {
		t.Errorf("rolebinding name = %q, want edge-link", rb.Name)
	}
	if rb.Namespace != "wg-system" {
		t.Errorf("rolebinding namespace = %q, want wg-system", rb.Namespace)
	}
	if rb.RoleRef.APIGroup != rbacv1.GroupName || rb.RoleRef.Kind != "Role" || rb.RoleRef.Name != "edge-link" {
		t.Errorf("roleRef = %+v, want rbac.authorization.k8s.io/Role/edge-link", rb.RoleRef)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("rolebinding subjects = %d, want 1", len(rb.Subjects))
	}
	sub := rb.Subjects[0]
	if sub.Kind != rbacv1.ServiceAccountKind || sub.Name != "edge-link" || sub.Namespace != "wg-system" {
		t.Errorf("subject = %+v, want ServiceAccount edge-link in wg-system", sub)
	}
}

// TestBuildLinkPodDisruptionBudget pins minAvailable 1 so a drain cannot take the active and
// the standby at once, and AlwaysAllow so an unhealthy pod is still evictable at the limit.
func TestBuildLinkPodDisruptionBudget(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	pdb := buildLinkPodDisruptionBudget(gw)

	if pdb.Name != "edge-link" {
		t.Errorf("pdb name = %q, want edge-link", pdb.Name)
	}
	if pdb.Namespace != "wg-system" {
		t.Errorf("pdb namespace = %q, want wg-system", pdb.Namespace)
	}
	if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntVal != 1 {
		t.Errorf("pdb minAvailable = %+v, want 1", pdb.Spec.MinAvailable)
	}
	if pdb.Spec.Selector == nil || !maps.Equal(pdb.Spec.Selector.MatchLabels, linkSelectorLabels(gw)) {
		t.Errorf("pdb selector = %+v, want link selector %v", pdb.Spec.Selector, linkSelectorLabels(gw))
	}
	if pdb.Spec.UnhealthyPodEvictionPolicy == nil || *pdb.Spec.UnhealthyPodEvictionPolicy != policyv1.AlwaysAllow {
		t.Errorf("pdb unhealthyPodEvictionPolicy = %v, want AlwaysAllow", pdb.Spec.UnhealthyPodEvictionPolicy)
	}
}

// TestEffectiveTrafficPolicy pins that an empty value reads as Cluster, so a Gateway that
// bypassed CRD defaulting still builds a Cluster data path.
func TestEffectiveTrafficPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		want   wgnetv1alpha1.TrafficPolicy
	}{
		{"unset defaults to Cluster", "", wgnetv1alpha1.TrafficPolicyCluster},
		{"explicit Cluster", wgnetv1alpha1.TrafficPolicyCluster, wgnetv1alpha1.TrafficPolicyCluster},
		{"explicit Local", wgnetv1alpha1.TrafficPolicyLocal, wgnetv1alpha1.TrafficPolicyLocal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			if got := effectiveTrafficPolicy(gw); got != tt.want {
				t.Errorf("effectiveTrafficPolicy = %q, want %q", got, tt.want)
			}
			if got, want := isLocal(gw), tt.want == wgnetv1alpha1.TrafficPolicyLocal; got != want {
				t.Errorf("isLocal = %v, want %v", got, want)
			}
		})
	}
}

// TestLinkIdentityOf pins that an identity exists only once a Local Gateway's id is
// allocated, so no Local workload is built before that id is persisted.
func TestLinkIdentityOf(t *testing.T) {
	ident3 := link.NewGatewayIdentity(3)
	tests := []struct {
		name   string
		policy wgnetv1alpha1.TrafficPolicy
		id     int32
		want   *link.GatewayIdentity
	}{
		{"cluster has no identity", wgnetv1alpha1.TrafficPolicyCluster, 0, nil},
		{"cluster ignores a stale id", wgnetv1alpha1.TrafficPolicyCluster, 3, nil},
		{"local without an id yet", wgnetv1alpha1.TrafficPolicyLocal, 0, nil},
		{"local with an allocated id", wgnetv1alpha1.TrafficPolicyLocal, 3, &ident3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			gw.Status.Link.ID = tt.id

			got := linkIdentityOf(gw)
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("linkIdentityOf = %+v, want nil", got)
			case tt.want != nil && got == nil:
				t.Fatalf("linkIdentityOf = nil, want %+v", *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Errorf("linkIdentityOf = %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

// TestBuildLinkConfigMapLocal pins the Local-mode RuntimeConfig: the derived identity, the
// widened allowed IPs and EndpointSlice-resolvable forwards instead of Service FQDNs.
func TestBuildLinkConfigMapLocal(t *testing.T) {
	gw := newGateway("edge", "wg-system",
		[]wgnetv1alpha1.Forward{
			{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			{Port: 5432, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "db", Namespace: "prod"},
		}, nil)
	gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	gw.Status.Link.ID = 3

	backends := []forwardBackend{
		{Forward: gw.Spec.Forwards[0], BackendPort: 8443},
		{Forward: gw.Spec.Forwards[1], BackendPort: 5432, ServicePortName: "postgres"},
	}

	responders := map[string]string{"node-a": "10.244.9.9"}
	cm, err := buildLinkConfigMap(gw, "203.0.113.5", backends, linkIdentityOf(gw), "GATEWAY_PUB_TEST", nil, effectiveHealthPort(gw), responders, "")
	if err != nil {
		t.Fatalf("buildLinkConfigMap: %v", err)
	}

	rc := loadLinkConfig(t, cm)

	if rc.TrafficPolicy != link.TrafficPolicyLocal {
		t.Errorf("trafficPolicy = %q, want %q", rc.TrafficPolicy, link.TrafficPolicyLocal)
	}
	if rc.Identity == nil {
		t.Fatal("identity = nil, want the identity derived from id 3")
	}
	if want := link.NewGatewayIdentity(3); *rc.Identity != want {
		t.Errorf("identity = %+v, want %+v", *rc.Identity, want)
	}
	if !slices.Equal(rc.WireGuard.Peers[0].AllowedIPs, []string{"0.0.0.0/0"}) {
		t.Errorf("peer.allowedIPs = %v, want [0.0.0.0/0]", rc.WireGuard.Peers[0].AllowedIPs)
	}
	if !maps.Equal(rc.PodSelector, linkSelectorLabels(gw)) {
		t.Errorf("podSelector = %v, want %v", rc.PodSelector, linkSelectorLabels(gw))
	}

	wantForwards := []link.Forward{
		{Name: "tcp-443", PublicPort: 443, Protocol: "tcp", Namespace: "wg-system", ServiceName: "web"},
		{Name: "tcp-5432", PublicPort: 5432, Protocol: "tcp", Namespace: "prod", ServiceName: "db", ServicePortName: "postgres"},
	}
	if !slices.Equal(rc.Forwards, wantForwards) {
		t.Errorf("forwards = %+v, want %+v", rc.Forwards, wantForwards)
	}

	if !maps.Equal(rc.Responders, responders) {
		t.Errorf("responders = %v, want %v", rc.Responders, responders)
	}
	if rc.ResponderPort != 27000 {
		t.Errorf("responderPort = %d, want %d", rc.ResponderPort, 27000)
	}
}

// TestBuildLinkConfigMapPodSelector pins that the pod selector is Local-only: the
// Cluster-mode link runs no pod watch, so the rendered config omits the key.
func TestBuildLinkConfigMapPodSelector(t *testing.T) {
	tests := []struct {
		name   string
		local  bool
		want   map[string]string
		wantID bool
	}{
		{name: "renders no pod selector or identity for cluster traffic"},
		{name: "renders the pod selector and identity for local traffic", local: true, wantID: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system",
				[]wgnetv1alpha1.Forward{{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"}}, nil)
			endpoint := ""
			if tt.local {
				gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
				gw.Status.Link.ID = 3
				endpoint = "203.0.113.5"
			}

			cm, err := buildLinkConfigMap(gw, endpoint, clusterBackends(gw.Spec.Forwards), linkIdentityOf(gw), "GATEWAY_PUB_TEST", nil, effectiveHealthPort(gw), nil, "")
			if err != nil {
				t.Fatalf("buildLinkConfigMap: %v", err)
			}

			var rc link.RuntimeConfig
			decodeJSON(t, cm.Data[linkConfigKey], &rc)
			want := map[string]string(nil)
			if tt.local {
				want = linkSelectorLabels(gw)
			}
			if !maps.Equal(rc.PodSelector, want) {
				t.Errorf("podSelector = %v, want %v", rc.PodSelector, want)
			}
			if (rc.Identity != nil) != tt.wantID {
				t.Errorf("identity = %+v, want non-nil %t", rc.Identity, tt.wantID)
			}

			var raw map[string]any
			decodeJSON(t, cm.Data[linkConfigKey], &raw)
			if _, ok := raw["podSelector"]; ok != tt.local {
				t.Errorf("rendered podSelector key present = %t, want %t", ok, tt.local)
			}
		})
	}
}

// TestBuildLinkDaemonSet pins the Local-mode host-network shape: no init container or
// anti-affinity, a loopback probe on the id-derived port, a writable host /proc/sys/net.
func TestBuildLinkDaemonSet(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	gw.Status.Link.ID = 3

	ds := buildLinkDaemonSet(gw, testConfig(), linkIdentityOf(gw))
	if ds.Name != "edge-link" || ds.Namespace != "wg-system" {
		t.Errorf("daemonset = %s/%s, want wg-system/edge-link", ds.Namespace, ds.Name)
	}

	podSpec := ds.Spec.Template.Spec
	c := podSpec.Containers[0]
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	mounts := map[string]corev1.VolumeMount{}
	for _, m := range c.VolumeMounts {
		mounts[m.Name] = m
	}
	volumes := map[string]corev1.Volume{}
	for _, v := range podSpec.Volumes {
		volumes[v.Name] = v
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"hostNetwork", podSpec.HostNetwork, true},
		{"dnsPolicy", podSpec.DNSPolicy, corev1.DNSClusterFirstWithHostNet},
		{"init containers", len(podSpec.InitContainers), 0},
		{"container ports", len(c.Ports), 0},
		{"probe host", c.ReadinessProbe.HTTPGet.Host, "127.0.0.1"},
		{"probe port", c.ReadinessProbe.HTTPGet.Port, intstr.FromInt32(27003)},
		{"health addr", env["GATEWAY_HEALTH_ADDR"], "127.0.0.1:27003"},
		{"host proc mount path", mounts["host-proc-sys-net"].MountPath, link.HostProcSysNetPath},
		{"host proc mount writable", mounts["host-proc-sys-net"].ReadOnly, false},
		{"host proc hostPath", volumes["host-proc-sys-net"].HostPath.Path, "/proc/sys/net"},
		{"termination grace period", *podSpec.TerminationGracePeriodSeconds, int64(30)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}

	if podSpec.Affinity != nil {
		t.Errorf("affinity = %+v, want nil (a DaemonSet is already one pod per node)", podSpec.Affinity)
	}
	if hp := volumes["host-proc-sys-net"].HostPath; hp == nil || hp.Type == nil || *hp.Type != corev1.HostPathDirectory {
		t.Errorf("host-proc-sys-net hostPath = %+v, want type Directory", hp)
	}
	assertFieldRefEnv(t, c.Env, "NODE_NAME", "spec.nodeName")

	sc := c.SecurityContext
	if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != 0 {
		t.Errorf("securityContext.runAsUser = %+v, want 0", sc)
	}
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Errorf("securityContext.allowPrivilegeEscalation = %+v, want false", sc)
	}
	if sc == nil || !slices.Equal(sc.Capabilities.Add, []corev1.Capability{"NET_ADMIN"}) {
		t.Errorf("capabilities = %+v, want add NET_ADMIN", sc)
	}
}

// TestBuildLinkDeploymentUnchangedInClusterMode guards that sharing a pod spec with the
// DaemonSet did not leak any Local-mode shape into the Cluster workload.
func TestBuildLinkDeploymentUnchangedInClusterMode(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	dep := buildLinkDeployment(gw, testConfig())

	podSpec := dep.Spec.Template.Spec
	c := podSpec.Containers[0]
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}

	if podSpec.HostNetwork {
		t.Error("hostNetwork = true, want false in Cluster mode")
	}
	if podSpec.DNSPolicy != "" {
		t.Errorf("dnsPolicy = %q, want unset in Cluster mode", podSpec.DNSPolicy)
	}
	if len(podSpec.InitContainers) != 1 {
		t.Errorf("init containers = %d, want 1", len(podSpec.InitContainers))
	}
	assertHostnameAntiAffinity(t, podSpec.Affinity, linkSelectorLabels(gw))
	if len(c.Ports) != 1 || c.Ports[0].Name != "health" || c.Ports[0].ContainerPort != 27000 {
		t.Errorf("container ports = %+v, want a single health port 27000", c.Ports)
	}
	if got := c.ReadinessProbe.HTTPGet; got.Host != "" || got.Port != intstr.FromString("health") {
		t.Errorf("readiness probe = %+v, want the named health port with no host", got)
	}
	if env["GATEWAY_HEALTH_ADDR"] != ":27000" {
		t.Errorf("GATEWAY_HEALTH_ADDR = %q, want :27000", env["GATEWAY_HEALTH_ADDR"])
	}
	envNames := make([]string, 0, len(c.Env))
	for _, e := range c.Env {
		envNames = append(envNames, e.Name)
	}
	slices.Sort(envNames)
	wantEnvNames := []string{
		"GATEWAY_CONFIG_PATH", "GATEWAY_HEALTH_ADDR", "GATEWAY_LEASE_NAME",
		"GATEWAY_RECONCILE_INTERVAL", "GATEWAY_WG_KEY_PATH", "GATEWAY_WG_PEER_PUBKEY_PATH",
		"POD_NAME", "POD_NAMESPACE",
	}
	if !reflect.DeepEqual(envNames, wantEnvNames) {
		t.Errorf("Cluster link container env names = %v, want %v", envNames, wantEnvNames)
	}
	volumeNames := make([]string, 0, len(podSpec.Volumes))
	for _, v := range podSpec.Volumes {
		volumeNames = append(volumeNames, v.Name)
	}
	slices.Sort(volumeNames)
	wantVolumeNames := []string{"config", "wg-keys"}
	if !reflect.DeepEqual(volumeNames, wantVolumeNames) {
		t.Errorf("Cluster link pod volume names = %v, want %v", volumeNames, wantVolumeNames)
	}
}

// TestLinkPodSpecNodeSelector pins that spec.link.nodeSelector reaches both workloads'
// pod templates, which is how an operator confines the link to a node pool.
func TestLinkPodSpecNodeSelector(t *testing.T) {
	selector := map[string]string{"wgnet.dev/pool": "edge"}

	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.Link.NodeSelector = selector
	dep := buildLinkDeployment(gw, testConfig())

	local := newGateway("edge", "wg-system", nil, nil)
	local.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	local.Spec.Link.NodeSelector = selector
	local.Status.Link.ID = 3
	ds := buildLinkDaemonSet(local, testConfig(), linkIdentityOf(local))

	tests := []struct {
		name string
		got  map[string]string
	}{
		{"deployment", dep.Spec.Template.Spec.NodeSelector},
		{"daemonset", ds.Spec.Template.Spec.NodeSelector},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !maps.Equal(tt.got, selector) {
				t.Errorf("nodeSelector = %v, want %v", tt.got, selector)
			}
		})
	}
}

// TestBuildLinkRolePods pins the Local-mode link Role's pod rule, the liveness input of
// the election, on top of the Lease rule both modes get.
func TestBuildLinkRolePods(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	role := buildLinkRole(gw)
	if len(role.Rules) != 2 {
		t.Fatalf("role rules = %d, want 2", len(role.Rules))
	}
	if got := role.Rules[0].Resources; !slices.Equal(got, []string{"leases"}) {
		t.Errorf("first rule resources = %v, want [leases]", got)
	}
	rule := role.Rules[1]
	if !slices.Equal(rule.APIGroups, []string{""}) {
		t.Errorf("rule apiGroups = %v, want [\"\"]", rule.APIGroups)
	}
	if !slices.Equal(rule.Resources, []string{"pods"}) {
		t.Errorf("rule resources = %v, want [pods]", rule.Resources)
	}
	if want := []string{"get", "list", "watch"}; !slices.Equal(rule.Verbs, want) {
		t.Errorf("rule verbs = %v, want %v", rule.Verbs, want)
	}
}

// TestBuildLinkClusterRoleBinding pins the EndpointSlice grant a Local link needs, with the
// owner labels the delete path has to find it by, having no ownerReference.
func TestBuildLinkClusterRoleBinding(t *testing.T) {
	gw := newGateway("edge", "wg-system", nil, nil)
	crb := buildLinkClusterRoleBinding(gw)

	if want := linkClusterRoleBindingName(gw); crb.Name != want {
		t.Errorf("clusterrolebinding name = %q, want %q", crb.Name, want)
	}
	if crb.Namespace != "" {
		t.Errorf("clusterrolebinding namespace = %q, want cluster-scoped", crb.Namespace)
	}
	if crb.RoleRef.APIGroup != rbacv1.GroupName || crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != linkEndpointSliceClusterRole {
		t.Errorf("roleRef = %+v, want ClusterRole/%s", crb.RoleRef, linkEndpointSliceClusterRole)
	}
	if len(crb.Subjects) != 1 {
		t.Fatalf("subjects = %d, want 1", len(crb.Subjects))
	}
	sub := crb.Subjects[0]
	if sub.Kind != rbacv1.ServiceAccountKind || sub.Name != "edge-link" || sub.Namespace != "wg-system" {
		t.Errorf("subject = %+v, want ServiceAccount edge-link in wg-system", sub)
	}

	want := commonLabels(gw, componentLink)
	want[ownerNamespaceLabel] = "wg-system"
	want[ownerNameLabel] = "edge"
	if !maps.Equal(crb.Labels, want) {
		t.Errorf("labels = %v, want %v", crb.Labels, want)
	}
}

// TestLinkClusterRoleBindingNameDistinctAcrossNamespaces pins that the hash separates a pair
// "<namespace>-<name>" would collide, and is stable so the apply targets one object.
func TestLinkClusterRoleBindingNameDistinctAcrossNamespaces(t *testing.T) {
	a := newGateway("c", "a-b", nil, nil)
	b := newGateway("b-c", "a", nil, nil)

	nameA := linkClusterRoleBindingName(a)
	nameB := linkClusterRoleBindingName(b)

	if nameA == nameB {
		t.Errorf("clusterrolebinding names collide: both %q", nameA)
	}
	if got := linkClusterRoleBindingName(a); got != nameA {
		t.Errorf("clusterrolebinding name = %q on the second call, want the stable %q", got, nameA)
	}
	for _, name := range []string{nameA, nameB} {
		if !strings.HasPrefix(name, linkClusterRoleBindingPrefix) {
			t.Errorf("clusterrolebinding name = %q, want the %q prefix", name, linkClusterRoleBindingPrefix)
		}
	}
}

// TestLinkPodSpecHealthAddr pins GATEWAY_HEALTH_ADDR per mode, looked up by env name so
// a reordered env slice cannot silently move the override onto another variable.
func TestLinkPodSpecHealthAddr(t *testing.T) {
	tests := []struct {
		name       string
		policy     wgnetv1alpha1.TrafficPolicy
		id         int32
		healthPort int32
		want       string
		wantPorts  []corev1.ContainerPort
	}{
		{"cluster", wgnetv1alpha1.TrafficPolicyCluster, 0, 0, ":27000",
			[]corev1.ContainerPort{{Name: "health", ContainerPort: 27000, Protocol: corev1.ProtocolTCP}}},
		{"cluster custom health port", wgnetv1alpha1.TrafficPolicyCluster, 0, 8181, ":8181",
			[]corev1.ContainerPort{{Name: "health", ContainerPort: 8181, Protocol: corev1.ProtocolTCP}}},
		{"local id 1", wgnetv1alpha1.TrafficPolicyLocal, 1, 0, "127.0.0.1:27001", nil},
		{"local id 7", wgnetv1alpha1.TrafficPolicyLocal, 7, 0, "127.0.0.1:27007", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			gw.Spec.Link.HealthPort = tt.healthPort
			gw.Status.Link.ID = tt.id

			spec := linkPodSpec(gw, testConfig(), linkIdentityOf(gw))
			var got string
			var found bool
			for _, e := range spec.Containers[0].Env {
				if e.Name == "GATEWAY_HEALTH_ADDR" {
					got, found = e.Value, true
				}
			}
			if !found {
				t.Fatal("GATEWAY_HEALTH_ADDR absent from container env")
			}
			if got != tt.want {
				t.Errorf("GATEWAY_HEALTH_ADDR = %q, want %q", got, tt.want)
			}

			if ports := spec.Containers[0].Ports; !slices.Equal(ports, tt.wantPorts) {
				t.Errorf("container ports = %+v, want %+v", ports, tt.wantPorts)
			}
		})
	}
}

// TestEffectiveHealthPort pins effectiveHealthPort's precedence: Local always uses its
// identity port; Cluster uses spec.link.healthPort when set, else the 27000 default.
func TestEffectiveHealthPort(t *testing.T) {
	tests := []struct {
		name       string
		policy     wgnetv1alpha1.TrafficPolicy
		id         int32
		healthPort int32
		want       int
	}{
		{"cluster unset", wgnetv1alpha1.TrafficPolicyCluster, 0, 0, 27000},
		{"cluster set 8181", wgnetv1alpha1.TrafficPolicyCluster, 0, 8181, 8181},
		{"local ignores healthPort", wgnetv1alpha1.TrafficPolicyLocal, 3, 8181, 27003},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGateway("edge", "wg-system", nil, nil)
			gw.Spec.TrafficPolicy = tt.policy
			gw.Spec.Link.HealthPort = tt.healthPort
			gw.Status.Link.ID = tt.id

			if got := effectiveHealthPort(gw); got != tt.want {
				t.Errorf("effectiveHealthPort = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestMaxLinkIDMatchesCRDBound pins link.MaxLinkID to the kubebuilder Maximum marker on
// GatewayLinkStatus.ID, which the CRD bound comes from and cannot reference the constant.
func TestMaxLinkIDMatchesCRDBound(t *testing.T) {
	const crdMaximum = 250
	if link.MaxLinkID != crdMaximum {
		t.Errorf("link.MaxLinkID = %d, want %d to match the CRD Maximum marker", link.MaxLinkID, crdMaximum)
	}
}

// TestLinkShutdownBudgetFitsGracePeriod guards two independent exit deadlines: a grace
// period at or below link.ShutdownBudget kills the link mid-release, stranding the Lease.
func TestLinkShutdownBudgetFitsGracePeriod(t *testing.T) {
	cluster := newGateway("edge", "wg-system", nil, nil)

	local := newGateway("edge", "wg-system", nil, nil)
	local.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	local.Status.Link.ID = 3

	tests := []struct {
		name  string
		grace *int64
	}{
		{"deployment", buildLinkDeployment(cluster, testConfig()).Spec.Template.Spec.TerminationGracePeriodSeconds},
		{"daemonset", buildLinkDaemonSet(local, testConfig(), linkIdentityOf(local)).Spec.Template.Spec.TerminationGracePeriodSeconds},
	}
	budget := int64(link.ShutdownBudget / time.Second)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.grace == nil {
				t.Fatalf("terminationGracePeriodSeconds unset, want more than the %ds shutdown budget", budget)
			}
			if *tt.grace <= budget {
				t.Errorf("terminationGracePeriodSeconds = %ds, want more than link.ShutdownBudget (%ds)", *tt.grace, budget)
			}
		})
	}
}

// TestTrafficPolicyConstantsMatch guards three independent declarations of the policy
// values: operator, link RuntimeConfig, e2e harness. Drift breaks the data path or the suite.
func TestTrafficPolicyConstantsMatch(t *testing.T) {
	tests := []struct {
		name    string
		api     wgnetv1alpha1.TrafficPolicy
		link    string
		harness string
	}{
		{"cluster", wgnetv1alpha1.TrafficPolicyCluster, link.TrafficPolicyCluster, hk8s.TrafficPolicyCluster},
		{"local", wgnetv1alpha1.TrafficPolicyLocal, link.TrafficPolicyLocal, hk8s.TrafficPolicyLocal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.api) != tt.link {
				t.Errorf("api value %q != link value %q", tt.api, tt.link)
			}
			if string(tt.api) != tt.harness {
				t.Errorf("api value %q != harness value %q", tt.api, tt.harness)
			}
		})
	}
}

// TestClusterHealthPortMatchesLinkDefault guards clusterHealthPort against the link's own
// envconfig default, which applies when GATEWAY_HEALTH_ADDR is absent; drift breaks the probe.
func TestClusterHealthPortMatchesLinkDefault(t *testing.T) {
	field, ok := reflect.TypeFor[link.Config]().FieldByName("HealthAddr")
	if !ok {
		t.Fatal("link.Config has no HealthAddr field")
	}
	def := field.Tag.Get("default")
	wantPort, err := strconv.Atoi(strings.TrimPrefix(def, ":"))
	if err != nil {
		t.Fatalf("parse link HealthAddr default %q: %v", def, err)
	}
	if clusterHealthPort != wantPort {
		t.Errorf("clusterHealthPort = %d, want %d from link.Config's HealthAddr default", clusterHealthPort, wantPort)
	}
}

// TestReconcileLinkPodDisruptionBudget asserts the PDB tracks the link replica count: absent at
// one replica, present above it, removed on scale-back so a stale PDB cannot strand a drain.
func TestReconcileLinkPodDisruptionBudget(t *testing.T) {
	ctx := context.Background()
	te, r, gw, key, _ := reconcileFixture(ctx, t)
	cl := te.client
	pdbKey := client.ObjectKey{Namespace: key.Namespace, Name: linkComponentName(gw)}

	// Default single replica: the link provisions but carries no PDB.
	drainReconcile(ctx, t, r, key)
	if err := cl.Get(ctx, pdbKey, &policyv1.PodDisruptionBudget{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pdb get at one replica = %v, want NotFound", err)
	}

	// Scaling to >1 must create the PDB, owner-ref'd for GC.
	setLinkReplicas(ctx, t, cl, key, 3)
	drainReconcile(ctx, t, r, key)
	var pdb policyv1.PodDisruptionBudget
	mustGet(ctx, t, cl, pdbKey, &pdb)
	assertOwnedByGateway(t, &pdb, gw)
	if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntVal != 1 {
		t.Errorf("pdb minAvailable = %+v, want 1", pdb.Spec.MinAvailable)
	}

	// Scaling back to one must delete the PDB so it cannot block a drain.
	setLinkReplicas(ctx, t, cl, key, 1)
	drainReconcile(ctx, t, r, key)
	if err := cl.Get(ctx, pdbKey, &policyv1.PodDisruptionBudget{}); !apierrors.IsNotFound(err) {
		t.Errorf("pdb get after scaling 3->1 = %v, want NotFound (deleted)", err)
	}
}

// setLinkReplicas sets spec.link.replicas on the live Gateway at key via a
// read-modify-write, so the reconciler reads the updated count.
func setLinkReplicas(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, replicas int32) {
	t.Helper()
	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)
	gw.Spec.Link.Replicas = replicas
	if err := cl.Update(ctx, &gw); err != nil {
		t.Fatalf("set link replicas to %d: %v", replicas, err)
	}
}

// TestRejectReservedHealthPort covers rejectReservedHealthPort: a Local health-port forward is
// rejected, another port stays valid, a Cluster forward is untouched: admission rejects it already.
func TestRejectReservedHealthPort(t *testing.T) {
	const localID = 7
	localHealthPort := int32(link.NewGatewayIdentity(localID).HealthPort)

	localGateway := func() *wgnetv1alpha1.Gateway {
		gw := newGateway("gw", "ns", nil, nil)
		gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
		gw.Status.Link.ID = localID
		return gw
	}

	tests := []struct {
		name         string
		gw           *wgnetv1alpha1.Gateway
		forward      wgnetv1alpha1.Forward
		wantRejected bool
	}{
		{
			name:         "local forward on its health port rejected",
			gw:           localGateway(),
			forward:      wgnetv1alpha1.Forward{Port: localHealthPort, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			wantRejected: true,
		},
		{
			name:         "local forward on another port accepted",
			gw:           localGateway(),
			forward:      wgnetv1alpha1.Forward{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			wantRejected: false,
		},
		{
			name:         "cluster forward on its own effective health port left valid unchanged",
			gw:           newGateway("gw", "ns", nil, nil),
			forward:      wgnetv1alpha1.Forward{Port: int32(clusterHealthPort), Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
			wantRejected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := forwardBackend{Forward: tt.forward}
			stillValid, invalid, rejected := rejectReservedHealthPort(tt.gw, []forwardBackend{backend}, nil)

			if tt.wantRejected {
				if len(stillValid) != 0 {
					t.Errorf("stillValid = %v, want empty", stillValid)
				}
				if len(invalid) != 1 || invalid[0].reason != reasonReservedHealthPort {
					t.Errorf("invalid = %v, want one entry with reason %q", invalid, reasonReservedHealthPort)
				}
				if len(rejected) != 1 || rejected[0] != tt.forward {
					t.Errorf("rejected = %v, want [%v]", rejected, tt.forward)
				}
				return
			}
			if len(stillValid) != 1 || stillValid[0] != backend {
				t.Errorf("stillValid = %v, want [%v]", stillValid, backend)
			}
			if len(invalid) != 0 {
				t.Errorf("invalid = %v, want empty", invalid)
			}
			if len(rejected) != 0 {
				t.Errorf("rejected = %v, want empty", rejected)
			}
		})
	}
}

// TestLowestFreeLinkID pins the dense-range allocator: the lowest unused id, the caller's own id
// reused, and exhaustion reported rather than wrapped.
func TestLowestFreeLinkID(t *testing.T) {
	self := client.ObjectKey{Namespace: "wg-system", Name: "edge"}

	withIDs := func(ids ...int32) []wgnetv1alpha1.Gateway {
		gateways := make([]wgnetv1alpha1.Gateway, 0, len(ids))
		for i, id := range ids {
			gateways = append(gateways, wgnetv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Namespace: "wg-system", Name: fmt.Sprintf("other-%d", i)},
				Status:     wgnetv1alpha1.GatewayStatus{Link: wgnetv1alpha1.GatewayLinkStatus{ID: id}},
			})
		}
		return gateways
	}

	all := make([]wgnetv1alpha1.Gateway, 0, link.MaxLinkID)
	for id := int32(1); id <= link.MaxLinkID; id++ {
		all = append(all, wgnetv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "wg-system", Name: fmt.Sprintf("g-%d", id)},
			Status:     wgnetv1alpha1.GatewayStatus{Link: wgnetv1alpha1.GatewayLinkStatus{ID: id}},
		})
	}

	tests := []struct {
		name     string
		gateways []wgnetv1alpha1.Gateway
		want     int32
		wantOK   bool
	}{
		{"empty list allocates 1", nil, 1, true},
		{"lowest gap taken", withIDs(1, 3), 2, true},
		{"cluster gateways holding no id are ignored", withIDs(0, 0), 1, true},
		{"whole range taken reports exhaustion", all, 0, false},
		{
			name: "annotated id reserves it even with status empty",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "wg-system",
					Name:        "restored",
					Annotations: map[string]string{linkIDAnnotation: "1"},
				},
			}},
			want:   2,
			wantOK: true,
		},
		{
			name: "malformed annotation reserves nothing",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "wg-system",
					Name:        "broken",
					Annotations: map[string]string{linkIDAnnotation: "not-a-number"},
				},
			}},
			want:   1,
			wantOK: true,
		},
		{
			name: "out-of-range annotation reserves nothing",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "wg-system",
					Name:        "over",
					Annotations: map[string]string{linkIDAnnotation: fmt.Sprint(link.MaxLinkID + 1)},
				},
			}},
			want:   1,
			wantOK: true,
		},
		{
			name: "own annotation is reusable",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   self.Namespace,
					Name:        self.Name,
					Annotations: map[string]string{linkIDAnnotation: "1"},
				},
			}},
			want:   1,
			wantOK: true,
		},
		{
			name: "own id is reusable",
			gateways: []wgnetv1alpha1.Gateway{{
				ObjectMeta: metav1.ObjectMeta{Namespace: self.Namespace, Name: self.Name},
				Status:     wgnetv1alpha1.GatewayStatus{Link: wgnetv1alpha1.GatewayLinkStatus{ID: 1}},
			}},
			want:   1,
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := lowestFreeLinkID(tt.gateways, self)
			if ok != tt.wantOK {
				t.Fatalf("lowestFreeLinkID ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("lowestFreeLinkID = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestEnsureLinkIDIsAuthoritative pins that a persisted id is read, never recomputed even once a
// lower id frees up: the names derived from it are what a restarting link reclaims.
func TestEnsureLinkIDIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	// A squatter holds id 1 so the Gateway under test allocates 2, leaving a lower id
	// to free up.
	squatter := newGateway("squatter", "default", nil, nil)
	squatter.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	mustCreate(ctx, t, cl, squatter)
	squatter.Status.Link.ID = 1
	if err := cl.Status().Update(ctx, squatter); err != nil {
		t.Fatalf("seed squatter link id: %v", err)
	}

	r, key := localGatewayFixture(ctx, t, te, "lid-auth")
	drainReconcile(ctx, t, r, key)

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ID != 2 {
		t.Fatalf("status.link.id = %d, want 2 (1 is held by the squatter)", got.Status.Link.ID)
	}

	if err := cl.Delete(ctx, squatter); err != nil {
		t.Fatalf("delete squatter: %v", err)
	}
	drainReconcile(ctx, t, r, key)

	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ID != 2 {
		t.Errorf("status.link.id = %d after id 1 freed, want the authoritative 2", got.Status.Link.ID)
	}
}

// TestLinkConfigMapCarriesResponderInfo pins the RuntimeConfig keys each shape's link ConfigMap
// carries: Cluster gets responderTarget/responderPort with no responders map; Local gets both.
func TestLinkConfigMapCarriesResponderInfo(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	t.Run("cluster", func(t *testing.T) {
		const ns = "responder-cfg-cluster"
		r, key := linkGatewayFixture(ctx, t, te, ns, wgnetv1alpha1.TrafficPolicyCluster)
		drainReconcile(ctx, t, r, key)

		var gw wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &gw)

		var svc corev1.Service
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: responderComponentName(&gw)}, &svc)
		var linkSecret corev1.Secret
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: linkSecretName(&gw)}, &linkSecret)

		var cm corev1.ConfigMap
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm)
		var rc link.RuntimeConfig
		decodeJSON(t, cm.Data[linkConfigKey], &rc)

		want := link.RuntimeConfig{
			TrafficPolicy:   string(wgnetv1alpha1.TrafficPolicyCluster),
			HealthPort:      clusterHealthPort,
			ResponderPort:   27000,
			ResponderTarget: svc.Spec.ClusterIP,
			WireGuard: link.WireGuard{
				Address: effectiveWGLinkAddress(&gw) + "/29",
				MTU:     int(effectiveWGMTU(&gw)),
				Peers: []link.Peer{{
					Slot:                0,
					PublicKey:           string(linkSecret.Data[wg.LinkPeerPublicKey]),
					AllowedIPs:          []string{effectiveWGSubnet(&gw)},
					PersistentKeepalive: int(effectiveWGKeepalive(&gw)),
				}},
			},
			Forwards: []link.Forward{{
				Name:       "tcp-443",
				PublicPort: 443,
				Protocol:   "tcp",
				Service:    forwardServiceFQDN(gw.Spec.Forwards[0], &gw),
				TargetPort: 443,
			}},
		}
		if !reflect.DeepEqual(rc, want) {
			t.Errorf("link runtime config = %#v, want %#v", rc, want)
		}
	})

	t.Run("local", func(t *testing.T) {
		const ns = "responder-cfg-local"
		r, key := localGatewayFixture(ctx, t, te, ns)
		drainReconcile(ctx, t, r, key)

		var gw wgnetv1alpha1.Gateway
		mustGet(ctx, t, cl, key, &gw)
		createLinkPod(ctx, t, cl, &gw, "gw-link-a", "node-a")
		createResponderPod(ctx, t, cl, gw.Namespace, "responder-a", "node-a", "10.10.0.9", responderSelectorLabels(&gw))
		drainReconcile(ctx, t, r, key)

		mustGet(ctx, t, cl, key, &gw)
		ident := linkIdentityOf(&gw)
		if ident == nil {
			t.Fatalf("linkIdentityOf(gw) = nil, want an allocated Local identity")
		}
		var linkSecret corev1.Secret
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: linkSecretName(&gw)}, &linkSecret)

		var cm corev1.ConfigMap
		mustGet(ctx, t, cl, client.ObjectKey{Namespace: ns, Name: "gw-link"}, &cm)
		var rc link.RuntimeConfig
		decodeJSON(t, cm.Data[linkConfigKey], &rc)

		want := link.RuntimeConfig{
			TrafficPolicy: string(wgnetv1alpha1.TrafficPolicyLocal),
			Identity:      ident,
			HealthPort:    ident.HealthPort,
			ResponderPort: 27000,
			PodSelector:   linkSelectorLabels(&gw),
			Responders:    map[string]string{"node-a": "10.10.0.9"},
			WireGuard: link.WireGuard{
				Address: effectiveWGLinkAddress(&gw) + "/29",
				MTU:     int(effectiveWGMTU(&gw)),
				Peers: []link.Peer{{
					Slot:                0,
					PublicKey:           string(linkSecret.Data[wg.LinkPeerPublicKey]),
					AllowedIPs:          []string{"0.0.0.0/0"},
					PersistentKeepalive: int(effectiveWGKeepalive(&gw)),
				}},
			},
			Forwards: []link.Forward{{
				Name:            "tcp-443",
				PublicPort:      443,
				Protocol:        "tcp",
				Namespace:       effectiveForwardNamespace(gw.Spec.Forwards[0], &gw),
				ServiceName:     gw.Spec.Forwards[0].Service,
				ServicePortName: "",
			}},
		}
		if !reflect.DeepEqual(rc, want) {
			t.Errorf("link runtime config = %#v, want %#v", rc, want)
		}
	})
}

// TestClusterLinkNetworkPolicyResponderEgress pins the Cluster link's egress rule to the
// Gateway's own responder pods, the path its health-port DNAT traffic takes.
func TestClusterLinkNetworkPolicyResponderEgress(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	r, key := linkGatewayFixture(ctx, t, te, "responder-netpol-cluster", wgnetv1alpha1.TrafficPolicyCluster)
	drainReconcile(ctx, t, r, key)

	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)

	var np networkingv1.NetworkPolicy
	mustGet(ctx, t, cl, client.ObjectKey{Namespace: "responder-netpol-cluster", Name: "gw-link"}, &np)
	if !hasResponderEgress(np.Spec.Egress, corev1.ProtocolTCP, effectiveResponderPort(&gw)) {
		t.Errorf("egress missing responder TCP %d rule: %+v", effectiveResponderPort(&gw), np.Spec.Egress)
	}
}

// seedLinkIDHolder creates a Local Gateway carrying the given status id and link id annotation,
// standing in for another Gateway that already holds an id.
func seedLinkIDHolder(ctx context.Context, t *testing.T, cl client.Client, ns, name string, statusID int32, annotation string) {
	t.Helper()
	holder := newGateway(name, ns, nil, nil)
	holder.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
	if annotation != "" {
		holder.Annotations = map[string]string{linkIDAnnotation: annotation}
	}
	mustCreate(ctx, t, cl, holder)
	if statusID == 0 {
		return
	}
	holder.Status.Link.ID = statusID
	if err := cl.Status().Update(ctx, holder); err != nil {
		t.Fatalf("seed link id %d on %s/%s: %v", statusID, ns, name, err)
	}
}

func setLinkIDAnnotation(ctx context.Context, t *testing.T, cl client.Client, key client.ObjectKey, value string) {
	t.Helper()
	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)
	if gw.Annotations == nil {
		gw.Annotations = map[string]string{}
	}
	gw.Annotations[linkIDAnnotation] = value
	if err := cl.Update(ctx, &gw); err != nil {
		t.Fatalf("set link id annotation on %s: %v", key, err)
	}
}

// TestEnsureLinkIDAnnotation pins the second record of the allocated id: an unheld annotated id
// is adopted, so a Gateway restored without status keeps the id its node state is named after.
func TestEnsureLinkIDAnnotation(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	tests := []struct {
		name string
		ns   string
		// seed runs on the created Gateway before the first reconcile.
		seed  func(key client.ObjectKey)
		check func(t *testing.T, got *wgnetv1alpha1.Gateway)
	}{
		{
			name: "restored gateway adopts its annotated id",
			ns:   "lid-restored",
			seed: func(key client.ObjectKey) { setLinkIDAnnotation(ctx, t, cl, key, "3") },
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				if got.Status.Link.ID != 3 {
					t.Errorf("status.link.id = %d, want the annotated 3", got.Status.Link.ID)
				}
				if ann := got.Annotations[linkIDAnnotation]; ann != "3" {
					t.Errorf("annotation = %q, want it left at \"3\"", ann)
				}
			},
		},
		{
			name: "fresh gateway is annotated with its allocated id",
			ns:   "lid-fresh",
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
		{
			name: "annotated id held in another status is not adopted",
			ns:   "lid-taken-status",
			seed: func(key client.ObjectKey) {
				seedLinkIDHolder(ctx, t, cl, key.Namespace, "status-holder", 40, "")
				setLinkIDAnnotation(ctx, t, cl, key, "40")
			},
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				if got.Status.Link.ID == 40 {
					t.Errorf("status.link.id = 40, want an id other than the one held in status")
				}
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
		{
			name: "an id another gateway only annotates is skipped",
			ns:   "lid-taken-annotation",
			seed: func(key client.ObjectKey) {
				seedLinkIDHolder(ctx, t, cl, key.Namespace, "annotation-holder", 0, "41")
			},
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				if got.Status.Link.ID == 41 {
					t.Errorf("status.link.id = 41, want an id another gateway does not annotate")
				}
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
		{
			name: "status wins over a differing annotation",
			ns:   "lid-status-wins",
			seed: func(key client.ObjectKey) {
				setLinkIDAnnotation(ctx, t, cl, key, "42")
				var gw wgnetv1alpha1.Gateway
				mustGet(ctx, t, cl, key, &gw)
				gw.Status.Link.ID = 43
				if err := cl.Status().Update(ctx, &gw); err != nil {
					t.Fatalf("seed status link id: %v", err)
				}
			},
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				if got.Status.Link.ID != 43 {
					t.Errorf("status.link.id = %d, want the authoritative 43", got.Status.Link.ID)
				}
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
		{
			name: "malformed annotation is replaced by a fresh allocation",
			ns:   "lid-malformed",
			seed: func(key client.ObjectKey) { setLinkIDAnnotation(ctx, t, cl, key, "not-a-number") },
			check: func(t *testing.T, got *wgnetv1alpha1.Gateway) {
				t.Helper()
				assertLinkIDAnnotationMatchesStatus(t, got)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, key := localGatewayFixture(ctx, t, te, tt.ns)
			if tt.seed != nil {
				tt.seed(key)
			}
			drainReconcile(ctx, t, r, key)

			var got wgnetv1alpha1.Gateway
			mustGet(ctx, t, cl, key, &got)
			tt.check(t, &got)
		})
	}
}

// assertLinkIDAnnotationMatchesStatus fails unless an id was allocated and the annotation
// records exactly it, which is what makes the annotation usable on a restore.
func assertLinkIDAnnotationMatchesStatus(t *testing.T, gw *wgnetv1alpha1.Gateway) {
	t.Helper()
	if gw.Status.Link.ID <= 0 {
		t.Fatalf("status.link.id = %d, want an allocated id", gw.Status.Link.ID)
	}
	want := strconv.FormatInt(int64(gw.Status.Link.ID), 10)
	if got := gw.Annotations[linkIDAnnotation]; got != want {
		t.Errorf("annotation = %q, want %q (status.link.id)", got, want)
	}
}

// TestEnsureLinkIDClusterConsumesNone pins that a Cluster Gateway allocates no id, so
// the dense range is not spent on Gateways whose data path derives nothing from it.
func TestEnsureLinkIDClusterConsumesNone(t *testing.T) {
	ctx := context.Background()
	te, r, _, key, _ := reconcileFixture(ctx, t)
	drainReconcile(ctx, t, r, key)

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, te.client, key, &got)
	if got.Status.Link.ID != 0 {
		t.Errorf("status.link.id = %d, want 0 in Cluster mode", got.Status.Link.ID)
	}
}

// TestEnsureLinkIDExhausted pins the exhaustion path: ReconcileFailed and a regular-interval
// requeue, rather than an error backoff or reusing an id another link is programming under.
func TestEnsureLinkIDExhausted(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	mustCreate(ctx, t, cl, namespaceWithLabels("lid-full", nil))
	for id := int32(1); id <= link.MaxLinkID; id++ {
		holder := newGateway(fmt.Sprintf("holder-%d", id), "lid-full", nil, nil)
		holder.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
		mustCreate(ctx, t, cl, holder)
		holder.Status.Link.ID = id
		if err := cl.Status().Update(ctx, holder); err != nil {
			t.Fatalf("seed holder link id %d: %v", id, err)
		}
	}

	r, key := localGatewayFixture(ctx, t, te, "lid-exhausted")
	// The shared fixture requeues immediately; a real interval makes the reported
	// (non-error) requeue observable.
	r.Config.RequeueInterval = 30 * time.Second
	req := ctrl.Request{NamespacedName: key}

	// The finalizer-add pass succeeds; the pass that reaches allocation reports the
	// exhaustion and requeues on the regular cadence instead of erroring.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile (finalizer pass): %v", err)
	}
	res, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile = %v, want nil error on exhaustion", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want the regular requeue interval", res.RequeueAfter)
	}

	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &got)
	cond := apimeta.FindStatusCondition(got.Status.Conditions, conditionReady)
	if cond == nil {
		t.Fatal("Ready condition absent")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != reasonReconcileFailed {
		t.Errorf("Ready = %s/%s, want False/%s", cond.Status, cond.Reason, reasonReconcileFailed)
	}
	if !strings.Contains(cond.Message, "no free link id") {
		t.Errorf("Ready message = %q, want it to name the exhaustion", cond.Message)
	}
	if got.Status.Link.ID != 0 {
		t.Errorf("status.link.id = %d, want 0 when allocation failed", got.Status.Link.ID)
	}
}

// TestReconcileLocalAppliesDaemonSetNotDeployment pins the Local-mode workload swap through the
// operator's own RBAC, including the cluster-scoped grant that must be reaped explicitly.
func TestReconcileLocalAppliesDaemonSetNotDeployment(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	r, key := localGatewayFixture(ctx, t, te, "local-ds")
	drainReconcile(ctx, t, r, key)

	var gw wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &gw)

	linkKey := client.ObjectKey{Namespace: key.Namespace, Name: key.Name + "-link"}
	if err := cl.Get(ctx, linkKey, &appsv1.DaemonSet{}); err != nil {
		t.Fatalf("get link daemonset %s: %v", linkKey, err)
	}
	for _, absent := range []struct {
		kind string
		obj  client.Object
	}{
		{"deployment", &appsv1.Deployment{}},
		{"networkpolicy", &networkingv1.NetworkPolicy{}},
		{"poddisruptionbudget", &policyv1.PodDisruptionBudget{}},
	} {
		if err := cl.Get(ctx, linkKey, absent.obj); !apierrors.IsNotFound(err) {
			t.Errorf("get link %s: err = %v, want NotFound in Local mode", absent.kind, err)
		}
	}

	crbKey := client.ObjectKey{Name: linkClusterRoleBindingName(&gw)}
	var crb rbacv1.ClusterRoleBinding
	if err := cl.Get(ctx, crbKey, &crb); err != nil {
		t.Fatalf("get link clusterrolebinding %s: %v", crbKey, err)
	}
	if crb.RoleRef.Name != linkEndpointSliceClusterRole {
		t.Errorf("roleRef = %q, want %q", crb.RoleRef.Name, linkEndpointSliceClusterRole)
	}

	if err := cl.Delete(ctx, &gw); err != nil {
		t.Fatalf("delete gateway: %v", err)
	}
	drainReconcile(ctx, t, r, key)

	if err := cl.Get(ctx, crbKey, &rbacv1.ClusterRoleBinding{}); !apierrors.IsNotFound(err) {
		t.Errorf("get link clusterrolebinding after delete: err = %v, want NotFound", err)
	}
}

// TestLinkStatusActiveNode pins that status.link.activeNode follows the Lease holder pod's node
// and clears once the holder is gone, so kubectl names the node carrying traffic.
func TestLinkStatusActiveNode(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtestRBAC(t)
	cl := te.client

	mustCreate(ctx, t, cl, namespaceWithLabels("active-node", nil))
	mustCreate(ctx, t, cl, portedClusterIPService("active-node", "web", 443, corev1.ProtocolTCP))

	gw := newGateway("gw", "active-node", []wgnetv1alpha1.Forward{
		{Port: 443, Protocol: wgnetv1alpha1.ProtocolTCP, Service: "web"},
	}, nil)
	mustCreate(ctx, t, cl, gw)
	key := client.ObjectKeyFromObject(gw)

	gen, _ := countingKeyGen()
	r := newOperatorReconciler(te, &GatewayReconciler{Config: reconcileConfig(), GenerateKey: gen})

	drainReconcile(ctx, t, r, key)
	setXGatewayGCPStatus(ctx, t, cl, key, "203.0.113.50", "sa@example.iam.gserviceaccount.com", "")
	setLinkLeaseActive(ctx, t, cl, key, "gw-link-0", true, "node-a")

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile with a holder on node-a: %v", err)
	}
	var got wgnetv1alpha1.Gateway
	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ActiveNode != "node-a" {
		t.Errorf("status.link.activeNode = %q, want node-a", got.Status.Link.ActiveNode)
	}

	holderKey := client.ObjectKey{Namespace: "active-node", Name: "gw-link-0"}
	// envtest runs no kubelet, so a graceful pod delete would hang in Terminating
	// forever; force it so the holder is genuinely gone.
	holder := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: holderKey.Namespace, Name: holderKey.Name}}
	if err := cl.Delete(ctx, holder, client.GracePeriodSeconds(0)); err != nil {
		t.Fatalf("delete holder pod: %v", err)
	}
	eventually(ctx, t, "holder pod gone", func() bool {
		return apierrors.IsNotFound(cl.Get(ctx, holderKey, &corev1.Pod{}))
	})

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile after the holder disappeared: %v", err)
	}
	mustGet(ctx, t, cl, key, &got)
	if got.Status.Link.ActiveNode != "" {
		t.Errorf("status.link.activeNode = %q, want it cleared once the holder is gone", got.Status.Link.ActiveNode)
	}
}

// TestEnsureSecretsWritesThePairWhole verifies either missing Secret rewrites both.
func TestEnsureSecretsWritesThePairWhole(t *testing.T) {
	ctx := context.Background()
	te := setupEnvtest(t)

	stalePriv, stalePub := testMemberKeypair(t)
	tests := []struct {
		name string
		// present is the half already in the namespace when the pass runs, holding key
		// material the other half never saw.
		present func(gw *wgnetv1alpha1.Gateway) *corev1.Secret
	}{
		{
			name: "bundle present, link secret missing",
			present: func(gw *wgnetv1alpha1.Gateway) *corev1.Secret {
				return buildBundleSecret(gw, stalePriv, stalePub)
			},
		},
		{
			name: "link secret present, bundle missing",
			present: func(gw *wgnetv1alpha1.Gateway) *corev1.Secret {
				return buildLinkSecret(gw, stalePriv, stalePub)
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := fmt.Sprintf("half-written-pair-%d", i)
			mustCreate(ctx, t, te.client, namespaceWithLabels(ns, nil))
			gw := newGateway(ns, ns, nil, nil)
			mustCreate(ctx, t, te.client, gw)
			mustGet(ctx, t, te.client, client.ObjectKeyFromObject(gw), gw)
			mustCreate(ctx, t, te.client, tt.present(gw))

			r := &GatewayReconciler{Client: te.client, APIReader: te.client, Scheme: te.scheme,
				Config: reconcileConfig(), Recorder: &fakeEventRecorder{}}
			if err := r.ensureSecrets(ctx, gw); err != nil {
				t.Fatalf("ensureSecrets: %v", err)
			}

			var bundle, linkSecret corev1.Secret
			mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: bundleSecretName(gw)}, &bundle)
			mustGet(ctx, t, te.client, client.ObjectKey{Namespace: ns, Name: linkSecretName(gw)}, &linkSecret)

			if got := slices.Sorted(maps.Keys(bundle.Data)); !slices.Equal(got, []string{wg.BundleKey}) {
				t.Fatalf("bundle Secret data keys = %v, want exactly %v", got, []string{wg.BundleKey})
			}
			wantLinkKeys := []string{wg.LinkPeerPublicKey, wg.LinkPrivateKey}
			slices.Sort(wantLinkKeys)
			if got := slices.Sorted(maps.Keys(linkSecret.Data)); !slices.Equal(got, wantLinkKeys) {
				t.Fatalf("link Secret data keys = %v, want exactly %v", got, wantLinkKeys)
			}

			gatewayPriv, rest, _ := strings.Cut(string(bundle.Data[wg.BundleKey]), "\n")
			linkPub, _, _ := strings.Cut(rest, "\n")
			linkPriv := string(linkSecret.Data[wg.LinkPrivateKey])
			gatewayPub := string(linkSecret.Data[wg.LinkPeerPublicKey])

			if got := publicKeyOf(t, gatewayPriv); got != gatewayPub {
				t.Errorf("public key of the bundle's private key = %q, want the link Secret's peer public key %q", got, gatewayPub)
			}
			if got := publicKeyOf(t, linkPriv); got != linkPub {
				t.Errorf("public key of the link Secret's private key = %q, want the bundle's peer public key %q", got, linkPub)
			}
		})
	}
}

// publicKeyOf derives a WireGuard public key from its private key, the relation each key
// Secret's peer public key must satisfy against the other Secret's private key.
func publicKeyOf(t *testing.T, privateKey string) string {
	t.Helper()
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		t.Fatalf("parse private key %q: %v", privateKey, err)
	}
	return key.PublicKey().String()
}

// TestLinkObjectHash table-tests the link gate hash: builder output hashes stably, every input
// that changes an object changes it, and a stale gate annotation on the input is ignored.
func TestLinkObjectHash(t *testing.T) {
	cfg := testConfig()
	gwWith := func(mutate func(gw *wgnetv1alpha1.Gateway)) *wgnetv1alpha1.Gateway {
		gw := newGateway("edge", "wg-system", nil, nil)
		if mutate != nil {
			mutate(gw)
		}
		return gw
	}
	configMap := func(gw *wgnetv1alpha1.Gateway, address string) client.Object {
		cm, err := buildLinkConfigMap(gw, address, nil, nil, "gateway-public-key", nil, clusterHealthPort, nil, "10.96.0.9")
		if err != nil {
			t.Fatalf("build link configmap: %v", err)
		}
		return cm
	}
	staleDeployment := func() client.Object {
		dep := buildLinkDeployment(gwWith(nil), cfg)
		dep.Annotations = map[string]string{linkHashAnnotation: "stale"}
		return dep
	}

	tests := []struct {
		name      string
		a, b      client.Object
		wantEqual bool
	}{
		{
			name:      "same deployment built twice",
			a:         buildLinkDeployment(gwWith(nil), cfg),
			b:         buildLinkDeployment(gwWith(nil), cfg),
			wantEqual: true,
		},
		{
			name:      "stale gate annotation is excluded",
			a:         staleDeployment(),
			b:         buildLinkDeployment(gwWith(nil), cfg),
			wantEqual: true,
		},
		{
			name: "replicas change",
			a:    buildLinkDeployment(gwWith(nil), cfg),
			b:    buildLinkDeployment(gwWith(func(gw *wgnetv1alpha1.Gateway) { gw.Spec.Link.Replicas = 3 }), cfg),
		},
		{
			name: "node selector change",
			a:    buildLinkDeployment(gwWith(nil), cfg),
			b: buildLinkDeployment(gwWith(func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.Link.NodeSelector = map[string]string{"role": "edge"}
			}), cfg),
		},
		{
			name: "configmap address change",
			a:    configMap(gwWith(nil), "203.0.113.10"),
			b:    configMap(gwWith(nil), "203.0.113.11"),
		},
		{
			name: "role rules change with the traffic policy",
			a:    buildLinkRole(gwWith(nil)),
			b: buildLinkRole(gwWith(func(gw *wgnetv1alpha1.Gateway) {
				gw.Spec.TrafficPolicy = wgnetv1alpha1.TrafficPolicyLocal
			})),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantAnnotations := maps.Clone(tt.a.GetAnnotations())

			hashA, err := objectHash(tt.a, linkHashAnnotation)
			if err != nil {
				t.Fatalf("hash a: %v", err)
			}
			hashB, err := objectHash(tt.b, linkHashAnnotation)
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

// TestLinkDirty table-tests the per-Gateway link dirty flag: an unseen key forces one apply, a
// mark forces the next pass only, and forgetting a key returns it to unseen.
func TestLinkDirty(t *testing.T) {
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
			setup: func(r *GatewayReconciler) { r.linkDirty.take(key) },
			want:  []bool{false, false},
		},
		{
			name: "marked after a take",
			setup: func(r *GatewayReconciler) {
				r.linkDirty.take(key)
				r.linkDirty.mark(key)
			},
			want: []bool{true, false},
		},
		{
			name: "forgotten after a take",
			setup: func(r *GatewayReconciler) {
				r.linkDirty.take(key)
				r.linkDirty.forget(key)
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
			got := []bool{r.linkDirty.take(key), r.linkDirty.take(key)}
			if !slices.Equal(got, tt.want) {
				t.Errorf("successive takes = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGatewaysForLinkObject table-tests the link-object mapper: a namespaced child resolves
// through its Gateway controller reference, the cluster-scoped binding through its owner labels.
func TestGatewaysForLinkObject(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
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
		Name:       "edge-link",
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
	deploymentWith := func(refs []metav1.OwnerReference) client.Object {
		dep := buildLinkDeployment(gw, cfg)
		dep.OwnerReferences = refs
		return dep
	}

	tests := []struct {
		name         string
		build        func() client.Object
		wantRequests []reconcile.Request
		wantDirty    bool
	}{
		{
			name:         "gateway controller reference",
			build:        func() client.Object { return deploymentWith([]metav1.OwnerReference{gatewayRef}) },
			wantRequests: []reconcile.Request{{NamespacedName: key}},
			wantDirty:    true,
		},
		{
			name:         "cluster-scoped binding carrying owner labels",
			build:        func() client.Object { return buildLinkClusterRoleBinding(gw) },
			wantRequests: []reconcile.Request{{NamespacedName: key}},
			wantDirty:    true,
		},
		{
			name:  "no owner reference",
			build: func() client.Object { return deploymentWith(nil) },
		},
		{
			name:  "controller reference of another kind",
			build: func() client.Object { return deploymentWith([]metav1.OwnerReference{daemonSetRef}) },
		},
		{
			name:  "gateway controller reference of another api group",
			build: func() client.Object { return deploymentWith([]metav1.OwnerReference{foreignGatewayRef}) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GatewayReconciler{}
			// Take once so the key is seen and clean: a mark by the mapper is then observable.
			r.linkDirty.take(key)

			got := r.gatewaysForLinkObject(context.Background(), tt.build())
			if !slices.Equal(got, tt.wantRequests) {
				t.Errorf("requests = %v, want exactly %v", got, tt.wantRequests)
			}
			if dirty := r.linkDirty.take(key); dirty != tt.wantDirty {
				t.Errorf("gateway %s dirty = %v, want %v", key, dirty, tt.wantDirty)
			}
		})
	}
}

// TestIsLinkObject table-tests the link-object predicate, including the drifted-label case:
// an edit that overwrites the component label must still reach the reconciler.
func TestIsLinkObject(t *testing.T) {
	cfg := testConfig()
	gw := newGateway("edge", "wg-system", nil, nil)
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
			name:  "link component label",
			build: func() client.Object { return buildLinkDeployment(gw, cfg) },
			want:  true,
		},
		{
			name:  "cluster-scoped binding",
			build: func() client.Object { return buildLinkClusterRoleBinding(gw) },
			want:  true,
		},
		{
			name: "label dropped from an owned link object",
			build: func() client.Object {
				dep := buildLinkDeployment(gw, cfg)
				dep.Labels = nil
				dep.OwnerReferences = []metav1.OwnerReference{gatewayRef}
				return dep
			},
			want: true,
		},
		{
			name:  "responder object of the same gateway",
			build: func() client.Object { return buildResponderDeployment(cfg, gw) },
		},
		{
			name: "unrelated object owned by the gateway under another name",
			build: func() client.Object {
				return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
					Namespace: gw.Namespace, Name: "other", OwnerReferences: []metav1.OwnerReference{gatewayRef},
				}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLinkObject(tt.build()); got != tt.want {
				t.Errorf("isLinkObject = %v, want %v", got, tt.want)
			}
		})
	}
}

// linkWriteLog counts the link-object writes a reconcile issues, keyed "<verb>/<kind>", so a
// test pins the exact set of calls instead of asserting one kind's absence.
type linkWriteLog struct {
	mu    sync.Mutex
	names map[string]bool
	calls map[string]int
}

// countedLinkKind names the kind obj is counted under, or "" for a kind the link write-gate
// tests do not count (the Gateway itself, its key Secrets, the GCP composites).
func countedLinkKind(obj client.Object) string {
	switch obj.(type) {
	case *corev1.ServiceAccount:
		return "ServiceAccount"
	case *rbacv1.Role:
		return "Role"
	case *rbacv1.RoleBinding:
		return "RoleBinding"
	case *rbacv1.ClusterRoleBinding:
		return "ClusterRoleBinding"
	case *corev1.ConfigMap:
		return "ConfigMap"
	case *appsv1.Deployment:
		return "Deployment"
	case *appsv1.DaemonSet:
		return "DaemonSet"
	case *networkingv1.NetworkPolicy:
		return "NetworkPolicy"
	case *policyv1.PodDisruptionBudget:
		return "PodDisruptionBudget"
	default:
		return ""
	}
}

func (l *linkWriteLog) record(verb string, obj client.Object) {
	kind := countedLinkKind(obj)
	if kind == "" || !l.names[obj.GetName()] {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls[verb+"/"+kind]++
}

func (l *linkWriteLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = map[string]int{}
}

// entries renders the recorded calls as sorted "<verb>/<kind>=<count>" strings.
func (l *linkWriteLog) entries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.calls))
	for call, n := range l.calls {
		out = append(out, fmt.Sprintf("%s=%d", call, n))
	}
	slices.Sort(out)
	return out
}

// countingLinkClient rewires r's client to the operator identity through an interceptor
// recording every Patch and Delete of a link object named in names.
func countingLinkClient(t *testing.T, te *testEnv, r *GatewayReconciler, names []string) *linkWriteLog {
	t.Helper()
	wc, err := client.NewWithWatch(te.operatorCfg, client.Options{Scheme: te.scheme})
	if err != nil {
		t.Fatalf("build watch client: %v", err)
	}
	writes := &linkWriteLog{names: map[string]bool{}, calls: map[string]int{}}
	for _, name := range names {
		writes.names[name] = true
	}
	r.Client = interceptor.NewClient(wc, interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
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

// linkObjectsPresent reports whether gw's common link objects, its mode-specific workload and,
// in the Local shape, its ClusterRoleBinding are all readable through cl.
func linkObjectsPresent(ctx context.Context, cl client.Client, ns, name, crbName string, local bool) bool {
	key := client.ObjectKey{Namespace: ns, Name: name}
	objs := []client.Object{
		&corev1.ServiceAccount{}, &rbacv1.Role{}, &rbacv1.RoleBinding{}, &corev1.ConfigMap{},
	}
	if local {
		objs = append(objs, &appsv1.DaemonSet{})
	} else {
		objs = append(objs, &appsv1.Deployment{}, &networkingv1.NetworkPolicy{})
	}
	for _, obj := range objs {
		if err := cl.Get(ctx, key, obj); err != nil {
			return false
		}
	}
	if !local {
		return true
	}
	return cl.Get(ctx, client.ObjectKey{Name: crbName}, &rbacv1.ClusterRoleBinding{}) == nil
}

// linkWriteStep is one Gateway spec edit in the steady-write table together with the exact set
// of link writes the reconcile following it must issue.
type linkWriteStep struct {
	name        string
	mutate      func(gw *wgnetv1alpha1.Gateway)
	wantEntries []string
}

// linkSteadyTimeout bounds the wait for a fresh Gateway's link objects to exist.
const linkSteadyTimeout = 30 * time.Second

// TestEnsureLinkSteadyWrites pins the link write gate: an unchanged reconcile applies nothing,
// the dirty flag forces every write, and a spec edit patches only what changed.
func TestEnsureLinkSteadyWrites(t *testing.T) {
	tests := []struct {
		name       string
		policy     wgnetv1alpha1.TrafficPolicy
		wantSteady []string
		wantDirty  []string
		steps      []linkWriteStep
	}{
		{
			name:   "cluster",
			policy: wgnetv1alpha1.TrafficPolicyCluster,
			wantDirty: []string{
				"Patch/ConfigMap=1", "Patch/Deployment=1",
				"Patch/NetworkPolicy=1", "Patch/Role=1", "Patch/RoleBinding=1", "Patch/ServiceAccount=1",
			},
			steps: []linkWriteStep{
				{
					name:        "replicas",
					mutate:      func(gw *wgnetv1alpha1.Gateway) { gw.Spec.Link.Replicas = 3 },
					wantEntries: []string{"Patch/Deployment=1", "Patch/PodDisruptionBudget=1"},
				},
				{
					name: "node selector",
					mutate: func(gw *wgnetv1alpha1.Gateway) {
						gw.Spec.Link.NodeSelector = map[string]string{"kubernetes.io/os": "linux"}
					},
					wantEntries: []string{"Patch/Deployment=1"},
				},
			},
		},
		{
			name:   "local",
			policy: wgnetv1alpha1.TrafficPolicyLocal,
			wantDirty: []string{
				"Patch/ClusterRoleBinding=1", "Patch/ConfigMap=1", "Patch/DaemonSet=1",
				"Patch/Role=1", "Patch/RoleBinding=1", "Patch/ServiceAccount=1",
			},
			steps: []linkWriteStep{
				{
					name: "node selector",
					mutate: func(gw *wgnetv1alpha1.Gateway) {
						gw.Spec.Link.NodeSelector = map[string]string{"kubernetes.io/os": "linux"}
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

			r, key := linkGatewayFixture(ctx, t, te, "link-steady-"+tt.name, tt.policy)
			var gw wgnetv1alpha1.Gateway
			mustGet(ctx, t, te.client, key, &gw)
			name, crbName := linkComponentName(&gw), linkClusterRoleBindingName(&gw)
			local := tt.policy == wgnetv1alpha1.TrafficPolicyLocal
			writes := countingLinkClient(t, te, r, []string{name, crbName})
			req := ctrl.Request{NamespacedName: key}

			pollUntil(ctx, t, linkSteadyTimeout, "gw's link objects to exist", func() bool {
				if _, err := r.Reconcile(ctx, req); err != nil {
					t.Fatalf("reconcile: %v", err)
				}
				return linkObjectsPresent(ctx, r.Client, key.Namespace, name, crbName, local)
			})

			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("steady reconcile: %v", err)
			}
			if got := writes.entries(); !slices.Equal(got, tt.wantSteady) {
				t.Errorf("steady reconcile link writes = %v, want exactly %v", got, tt.wantSteady)
			}

			r.linkDirty.mark(key)
			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("dirty reconcile: %v", err)
			}
			if got := writes.entries(); !slices.Equal(got, tt.wantDirty) {
				t.Errorf("dirty reconcile link writes = %v, want exactly %v", got, tt.wantDirty)
			}

			writes.reset()
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("reconcile after the dirty pass: %v", err)
			}
			if got := writes.entries(); !slices.Equal(got, tt.wantSteady) {
				t.Errorf("link writes after the dirty pass = %v, want exactly %v", got, tt.wantSteady)
			}

			for _, step := range tt.steps {
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
					t.Errorf("%s: link writes = %v, want exactly %v", step.name, got, step.wantEntries)
				}
			}
		})
	}
}
