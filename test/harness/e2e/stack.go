package e2e

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	hk8s "github.com/tripod-networks/wireguard-gateway-operator/test/harness/k8s"
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/shared"
)

// Stack holds the per-test resources and the observed gateway facts the
// data-path assertions read.
type Stack struct {
	Namespace string
	// NamePrefix is the run-unique prefix on every operator-owned object and GCP
	// resource the orphan check filters on. It is also the Gateway CR name.
	NamePrefix string
	// GatewayName is the Gateway CR name; the operator names the XGatewayGCP
	// composite after it.
	GatewayName string
	// GatewayUID identifies this Gateway's cloud records during teardown.
	GatewayUID string
	// Address is the gateway's observed public IP, the host-side probe target.
	Address       string
	TCPPublicPort int
	UDPPublicPort int
	// NodePortPublicPort forwards to the NodePort-backed echo Service.
	NodePortPublicPort int
	// CrossNSPublicPort forwards to the echo Service in the consent-labelled
	// second namespace.
	CrossNSPublicPort int
	// EditedPublicPort is the port the forward-edit subtest adds live.
	EditedPublicPort int
	// The lifecycle subtests attach a runtime forward to these dedicated ports and
	// remove it again, each disjoint from the create-time forwards and negativePort.
	ServiceCreatedPort     int
	ServiceDeletedPort     int
	ConsentTogglePort      int
	TargetPortScenarioPort int
	BackendRolloutPort     int
	ForwardRetargetPort    int
	// NegativePort is a non-forwarded port the negative probes target, dropped at
	// the GCP firewall. Start asserts it is disjoint from the forwarded and WG ports.
	NegativePort int
	// WireguardListenPort is this stack's WireGuard UDP listen port, opened in the
	// gateway's firewall rule. WithWireguardListenPort keeps coexisting stacks distinct.
	WireguardListenPort int
	// LinkReplicas is the link Deployment's effective replica count (override, or 1).
	// Teardown reads it: the link PDB is applied only at replicas>1.
	LinkReplicas int32
	// TrafficPolicy is the Gateway's effective data-path mode, "Cluster" or "Local".
	TrafficPolicy string
	// LinkClusterRoleBindingName is the binding a Local Gateway owns, which teardown
	// asserts is reaped. Empty in Cluster mode.
	LinkClusterRoleBindingName string
	// BackendNode is the worker every Local-mode echo backend is pinned to, and so the
	// node the link Lease holder must be on. Empty in Cluster mode.
	BackendNode string
	// WorkerNodes are the cluster's schedulable workers, sorted, so a Local test can
	// re-pin the backend to a node other than BackendNode. Empty in Cluster mode.
	WorkerNodes []string

	// Echo Deployment names behind the create-time forwards. agnhost /hostname returns
	// the serving pod's name, prefixed by its Deployment's, so a probe matches by prefix.
	TCPBackendName      string
	UDPBackendName      string
	NodePortBackendName string
	CrossNSBackendName  string
	// CrossNSNamespace is the namespace holding the cross-namespace backend, which a
	// re-pin needs alongside the Deployment name.
	CrossNSNamespace string
	// TCPBackendPort is the published port of the TCP echo Service. The targetPort
	// subtest forwards to it, first with a wrong targetPort then this one.
	TCPBackendPort int

	// extraNamespaces are namespaces Start created beyond the primary one; teardown
	// deletes them.
	extraNamespaces []string

	// addresses holds this stack's external-address permit until the Gateway is gone.
	addresses     *addressSlots
	addressWeight int64
	releaseOnce   sync.Once

	suite *Suite
	log   *zap.Logger
}

// gatewayOutcome determines whether a stack returns its external-address permit.
type gatewayOutcome int

const (
	// gatewayConfirmedGone: the Gateway object no longer exists, either because the
	// drain confirmed its deletion or because it was never created.
	gatewayConfirmedGone gatewayOutcome = iota
	// gatewayStillLive: the Gateway is up and holding GCP quota, kept for debugging or
	// left behind by a drain that did not confirm.
	gatewayStillLive
)

func (s *Stack) releaseAddressPermitFor(outcome gatewayOutcome) {
	if outcome != gatewayConfirmedGone {
		return
	}
	s.releaseOnce.Do(func() { s.addresses.release(s.addressWeight) })
}

// LocalBackendRefs are the Local shard's three backends, the set every forward needs a
// ready endpoint from on the holder node.
func (s *Stack) LocalBackendRefs() []hk8s.ServiceRef {
	return []hk8s.ServiceRef{
		{Namespace: s.Namespace, Name: s.TCPBackendName},
		{Namespace: s.Namespace, Name: s.UDPBackendName},
		{Namespace: s.CrossNSNamespace, Name: s.CrossNSBackendName},
	}
}

// StartOption configures a per-stack override applied before provisioning.
type StartOption func(*startConfig)

// startConfig holds the resolved per-stack overrides StartE applies; its zero value
// is the standard single-gateway shard.
type startConfig struct {
	// wgListenPort overrides the WireGuard listen port. Zero uses the wgListenPort
	// default.
	wgListenPort int
	// linkReplicas overrides the link replica count. Zero uses the CRD default (1).
	linkReplicas int32
	// trafficPolicy overrides the data-path mode. Empty uses the CRD default
	// (Cluster).
	trafficPolicy string
	gcpReplicas   int32
	gcpZones      []string
	loadBalancer  *hk8s.GatewayGCPLoadBalancer
}

// WithWireguardListenPort overrides the stack's WireGuard UDP listen port so coexisting
// gateways run distinct ports. It is folded into the negative-port disjointness check.
func WithWireguardListenPort(port int) StartOption {
	return func(c *startConfig) { c.wgListenPort = port }
}

// WithLinkReplicas brings the gateway up with n link replicas behind leader
// election, so the HA test gets a hot standby. n must be >=1 (the CRD's minimum).
func WithLinkReplicas(n int32) StartOption {
	return func(c *startConfig) { c.linkReplicas = n }
}

// WithTrafficPolicy brings the gateway up in the named data-path mode, "Cluster" or
// "Local". Local preserves the client's source address end to end.
func WithTrafficPolicy(policy string) StartOption {
	return func(c *startConfig) { c.trafficPolicy = policy }
}

// WithGCPReplicas configures the regional MIG member count.
func WithGCPReplicas(n int32) StartOption {
	return func(c *startConfig) { c.gcpReplicas = n }
}

// WithGCPZones configures the regional MIG's zones.
func WithGCPZones(zones []string) StartOption {
	return func(c *startConfig) { c.gcpZones = append([]string(nil), zones...) }
}

// WithLoadBalancer selects the load-balanced Gateway path and configures affinity.
func WithLoadBalancer(sessionAffinity string) StartOption {
	return func(c *startConfig) {
		c.loadBalancer = &hk8s.GatewayGCPLoadBalancer{SessionAffinity: sessionAffinity}
	}
}

// Start wraps StartE for the common single-gateway shard, failing the test on error.
// Concurrent stack setup must call StartE instead: t.Fatal off the test goroutine is illegal.
func (s *Suite) Start(ctx context.Context, t *testing.T, opts ...StartOption) (*Stack, error) {
	t.Helper()
	stack, err := s.StartE(ctx, t, opts...)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}
	return stack, nil
}

// StartE brings up a full per-test stack and registers teardown via t.Cleanup. It returns
// failures as errors rather than calling t.Fatal, so it is errgroup-safe.
func (s *Suite) StartE(ctx context.Context, t *testing.T, opts ...StartOption) (*Stack, error) {
	t.Helper()

	var cfg startConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	wgPort := wgListenPort
	if cfg.wgListenPort != 0 {
		wgPort = cfg.wgListenPort
	}

	// Fail fast before provisioning so a later forwards change cannot silently turn
	// the negative probe into a false pass.
	if err := negativePortDisjointError(wgPort); err != nil {
		return nil, err
	}

	// Kept short and label-safe so the operator-derived service-account ID fits GCP's
	// 30-char limit; the test-name slug is logged rather than folded in.
	prefix := "gw" + shared.ShortID()
	ns := prefix
	log := s.log.With(
		zap.String("ns", ns),
		zap.String("prefix", prefix),
		zap.String("test", shared.Slug(t.Name())),
	)

	if err := s.client.EnsureNamespace(ctx, ns); err != nil {
		return nil, fmt.Errorf("ensure namespace: %w", err)
	}

	local := effectiveTrafficPolicy(cfg.trafficPolicy) == hk8s.TrafficPolicyLocal

	var (
		echo            hk8s.EchoFixtures
		nodePortEcho    hk8s.EchoBackend
		crossNSEcho     hk8s.EchoBackend
		extraNamespaces []string
		workers         []string
		backendNode     string
		err             error
	)

	if local {
		// Local mode needs a ready endpoint on the holder node for every forward, so all
		// three of the shard's backends are pinned to one chosen worker.
		workers, err = s.client.WorkerNodes(ctx)
		if err != nil {
			return nil, fmt.Errorf("list worker nodes: %w", err)
		}
		if len(workers) < 2 {
			return nil, fmt.Errorf("local stack needs at least two worker nodes to observe a handoff, found %d", len(workers))
		}
		backendNode = workers[0]
		tcpBackend, err := s.client.DeployEchoOnNode(ctx, ns, localEchoName, backendNode)
		if err != nil {
			return nil, fmt.Errorf("deploy node-pinned echo: %w", err)
		}
		udpBackend, err := s.client.DeployUDPEchoOnNode(ctx, ns, localUDPEchoName, backendNode)
		if err != nil {
			return nil, fmt.Errorf("deploy node-pinned udp echo: %w", err)
		}
		xnsNamespace := prefix + "-xns"
		crossNSEcho, err = s.client.DeployEchoInNamespaceOnNode(ctx, xnsNamespace, map[string]string{
			crossNamespaceIngressLabel: crossNamespaceIngressValue,
		}, backendNode)
		if err != nil {
			return nil, fmt.Errorf("deploy node-pinned cross-namespace echo: %w", err)
		}
		extraNamespaces = []string{xnsNamespace}
		echo = hk8s.EchoFixtures{
			TCPService: tcpBackend.Service,
			TCPPort:    tcpBackend.Port,
			UDPService: udpBackend.Service,
			UDPPort:    udpBackend.Port,
		}
	} else {
		echo, err = s.client.DeployEchoFixtures(ctx, ns)
		if err != nil {
			return nil, fmt.Errorf("deploy echo fixtures: %w", err)
		}

		nodePortEcho, err = s.client.DeployNodePortEcho(ctx, ns)
		if err != nil {
			return nil, fmt.Errorf("deploy nodeport echo: %w", err)
		}

		// The cross-namespace echo lives in a second namespace carrying the consent
		// label, so the operator permits the Gateway in ns to forward into it.
		xnsNamespace := prefix + "-xns"
		crossNSEcho, err = s.client.DeployEchoInNamespaceOnNode(ctx, xnsNamespace, map[string]string{
			crossNamespaceIngressLabel: crossNamespaceIngressValue,
		}, "")
		if err != nil {
			return nil, fmt.Errorf("deploy cross-namespace echo: %w", err)
		}
		extraNamespaces = []string{xnsNamespace}
	}

	stack := &Stack{
		Namespace:              ns,
		NamePrefix:             prefix,
		GatewayName:            prefix,
		TCPPublicPort:          tcpPublicPort,
		UDPPublicPort:          udpPublicPort,
		NodePortPublicPort:     nodePortPublicPort,
		CrossNSPublicPort:      crossNSPublicPort,
		EditedPublicPort:       editedPublicPort,
		ServiceCreatedPort:     serviceCreatedPort,
		ServiceDeletedPort:     serviceDeletedPort,
		ConsentTogglePort:      consentTogglePort,
		TargetPortScenarioPort: targetPortScenarioPort,
		BackendRolloutPort:     backendRolloutPort,
		ForwardRetargetPort:    forwardRetargetPort,
		NegativePort:           negativePort,
		WireguardListenPort:    wgPort,
		LinkReplicas:           effectiveLinkReplicas(cfg.linkReplicas),
		TrafficPolicy:          effectiveTrafficPolicy(cfg.trafficPolicy),
		BackendNode:            backendNode,
		WorkerNodes:            workers,
		TCPBackendName:         echo.TCPService,
		UDPBackendName:         echo.UDPService,
		NodePortBackendName:    nodePortEcho.Service,
		CrossNSBackendName:     crossNSEcho.Service,
		CrossNSNamespace:       crossNSEcho.Namespace,
		TCPBackendPort:         echo.TCPPort,
		extraNamespaces:        extraNamespaces,
		suite:                  s,
		log:                    log,
	}
	addresses, err := liveAddresses()
	if err != nil {
		return nil, err
	}
	addressWeight := stackAddressWeight(cfg)
	if err := addresses.acquire(ctx, addressWeight); err != nil {
		return nil, err
	}
	stack.addresses = addresses
	stack.addressWeight = addressWeight
	s.registerTeardown(t, stack)

	if err := s.client.CreateGateway(ctx, ns, stack.GatewayName, gatewaySpec(s.env, echo, nodePortEcho, crossNSEcho, wgPort, cfg.linkReplicas, cfg.trafficPolicy, cfg.gcpReplicas, cfg.gcpZones, cfg.loadBalancer)); err != nil {
		stack.releaseAddressPermitFor(gatewayConfirmedGone)
		return nil, fmt.Errorf("create gateway: %w", err)
	}
	gatewayUID, err := s.client.GatewayUID(ctx, ns, stack.GatewayName)
	if err != nil {
		return nil, fmt.Errorf("read gateway uid: %w", err)
	}
	stack.GatewayUID = gatewayUID

	status, err := s.client.WaitGatewayReady(ctx, ns, stack.GatewayName, gatewayReadyTimeout)
	if err != nil {
		return nil, fmt.Errorf("wait gateway ready: %w", err)
	}
	stack.Address = status.Address
	log.Info("gateway ready", zap.String("address", status.Address))

	// Read the name from the live cluster rather than recomputing the operator's hash, so
	// teardown's reap assertion cannot drift from what the operator created.
	crbName, err := s.client.LinkClusterRoleBindingName(ctx, ns, stack.GatewayName)
	if err != nil {
		return nil, fmt.Errorf("read link clusterrolebinding name: %w", err)
	}
	// A Local gateway must own one, and teardown skips the reap assertion for an empty
	// name, so an unnamed binding here would make teardown pass without checking it.
	if local && crbName == "" {
		return nil, fmt.Errorf("local gateway %s/%s has no link clusterrolebinding", ns, stack.GatewayName)
	}
	stack.LinkClusterRoleBindingName = crbName

	return stack, nil
}

// Mirrors the operator's unexported consent gate: a namespace must carry this label
// before a Gateway in another namespace may forward into it.
const (
	crossNamespaceIngressLabel = "wgnet.dev/allow-gateway-ingress"
	crossNamespaceIngressValue = "true"
)

// localEchoName and localUDPEchoName are the Deployment and Service names of the Local
// shard's TCP and UDP echo backends, both pinned to BackendNode and both re-pinned by a
// handoff assertion. The shard's third backend keeps the cross-namespace fixture's name.
const (
	localEchoName    = "gateway-echo-local"
	localUDPEchoName = "gateway-echo-local-udp"
)

// gatewaySpec builds the Gateway CR spec. Local mode drops the NodePort forward, whose acceptance
// path the policy does not change, and keeps the forwards whose backends sit on one worker.
func gatewaySpec(env Env, echo hk8s.EchoFixtures, nodePort, crossNS hk8s.EchoBackend, wgPort int, linkReplicas int32, trafficPolicy string, gcpReplicas int32, gcpZones []string, loadBalancer *hk8s.GatewayGCPLoadBalancer) hk8s.GatewaySpec {
	spec := hk8s.GatewaySpec{
		ProjectID:   env.ProjectID,
		Region:      env.Region,
		Zone:        env.Zone,
		MachineType: "e2-micro",
		Forwards: []hk8s.GatewayForward{
			{
				Port:       tcpPublicPort,
				Protocol:   "TCP",
				Service:    echo.TCPService,
				TargetPort: echo.TCPPort,
			},
		},
	}
	if trafficPolicy != "" {
		spec.TrafficPolicy = trafficPolicy
	}
	spec.Forwards = append(spec.Forwards,
		[]hk8s.GatewayForward{
			{
				Port:       udpPublicPort,
				Protocol:   "UDP",
				Service:    echo.UDPService,
				TargetPort: echo.UDPPort,
			},
			{
				Port:       crossNSPublicPort,
				Protocol:   "TCP",
				Service:    crossNS.Service,
				Namespace:  crossNS.Namespace,
				TargetPort: crossNS.Port,
			},
		}...)
	if effectiveTrafficPolicy(trafficPolicy) != hk8s.TrafficPolicyLocal {
		spec.Forwards = append(spec.Forwards, hk8s.GatewayForward{
			Port:       nodePortPublicPort,
			Protocol:   "TCP",
			Service:    nodePort.Service,
			TargetPort: nodePort.Port,
		})
	}
	if wgPort != wgListenPort {
		spec.WireguardListenPort = wgPort
	}
	if linkReplicas > 0 {
		spec.Replicas = linkReplicas
	}
	if gcpReplicas > 0 {
		spec.GCPReplicas = gcpReplicas
	}
	if len(gcpZones) > 0 {
		spec.GCPZones = append([]string(nil), gcpZones...)
	}
	if loadBalancer != nil {
		spec.GCPLoadBalancer = &hk8s.GatewayGCPLoadBalancer{
			SessionAffinity: loadBalancer.SessionAffinity,
		}
	}
	return spec
}

const defaultGCPReplicas = 1 // GatewayGCPSpec.Replicas CRD default.

func stackAddressWeight(cfg startConfig) int64 {
	if cfg.loadBalancer == nil {
		return 1
	}
	replicas := cfg.gcpReplicas
	if replicas == 0 {
		replicas = defaultGCPReplicas
	}
	return int64(replicas) + 1
}

func effectiveLinkReplicas(configured int32) int32 {
	if configured == 0 {
		return 1
	}
	return configured
}

// effectiveTrafficPolicy resolves the configured mode to what the CRD stores, so
// teardown and the assertions can branch on it without repeating the default.
func effectiveTrafficPolicy(configured string) string {
	if configured == "" {
		return hk8s.TrafficPolicyCluster
	}
	return configured
}

// registerTeardown orders the GCP drain: delete the Gateway, wait for the orphan check
// to reach zero with the namespace alive, then delete the namespace.
func (s *Suite) registerTeardown(t *testing.T, stack *Stack) {
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("GATEWAY_E2E_PRESERVE") != "" {
			s.log.Warn("test failed; preserving per-test resources", zap.String("ns", stack.Namespace))
			stack.releaseAddressPermitFor(gatewayStillLive)
			return
		}
		// Bounded under the whole-binary `go test -timeout 25m` so a slow drain is not
		// SIGKILLed mid-flight and left leaking the VM.
		cctx, cancel := context.WithTimeout(context.Background(), orphanDrainTimeout+3*time.Minute)
		defer cancel()

		auth := gcpAuth{projectID: s.env.ProjectID, credsFile: s.env.CredsFile}

		if t.Failed() {
			s.dumpDiagnostics(cctx, t, stack, auth)
		}

		// GATEWAY_E2E_KEEP leaves every resource up for debugging regardless of result;
		// the hints cover the by-hand drain that then leaks until run.
		if s.env.Keep {
			s.log.Warn("GATEWAY_E2E_KEEP set; skipping teardown, leaving resources up for debugging",
				zap.String("ns", stack.Namespace),
				zap.String("gateway", stack.GatewayName),
				zap.String("gcp_instance_prefix", stack.NamePrefix),
				zap.String("gcp_zone", s.env.Zone),
				zap.String("gcp_project", s.env.ProjectID),
				zap.String("ssh_hint", fmt.Sprintf(
					"gcloud compute ssh %s-* --zone %s --project %s",
					stack.NamePrefix, s.env.Zone, s.env.ProjectID)),
				zap.String("serial_hint", fmt.Sprintf(
					"gcloud compute instances get-serial-port-output %s-* --port 1 --zone %s --project %s",
					stack.NamePrefix, s.env.Zone, s.env.ProjectID)),
				zap.String("drain_hint", fmt.Sprintf(
					"kubectl delete gateway %s -n %s  # then re-run to drain GCP",
					stack.GatewayName, stack.Namespace)))
			stack.releaseAddressPermitFor(gatewayStillLive)
			return
		}

		// The Gateway's finalizer drives the GCP drain, so it goes first and the namespace
		// must outlive it; a namespace delete would bypass the drain and orphan resources.
		if err := s.client.DeleteGateway(cctx, stack.Namespace, stack.GatewayName); err != nil {
			s.log.Error("delete gateway", zap.Error(err))
		}
		// The Gateway disappearing signals the drain reached the cloud; the orphan check
		// below is the authoritative zero.
		if err := s.client.WaitGatewayGone(cctx, stack.Namespace, stack.GatewayName, orphanDrainTimeout); err != nil {
			t.Errorf("wait for gateway %s/%s deletion within %s: %v", stack.Namespace, stack.GatewayName, orphanDrainTimeout, err)
			stack.releaseAddressPermitFor(gatewayStillLive)
		} else {
			stack.releaseAddressPermitFor(gatewayConfirmedGone)
		}
		// A fast confirmation, not a second drain wait.
		if err := s.client.WaitXGatewayGCPGone(cctx, stack.Namespace, stack.GatewayName, orphanDrainTimeout); err != nil {
			s.log.Error("wait xgatewaygcp gone", zap.Error(err))
		}
		// The namespace stays alive so the provider can write the per-namespace
		// ProviderConfigUsage each MR needs to release its resource.
		s.log.Info("asserting no orphaned GCP resources after gateway deletion",
			zap.String("prefix", stack.NamePrefix))
		if err := assertNoOrphans(cctx, auth, stack.Namespace, stack.GatewayName, stack.GatewayUID, stack.NamePrefix, orphanDrainTimeout, s.log); err != nil {
			t.Errorf("orphaned GCP resources after teardown: %v", err)
		}
		// Checked while the namespace is alive: the delete below would mask a child left
		// by a broken owner reference.
		s.client.AssertOwnedChildrenGone(cctx, t, hk8s.OwnedChildren{
			Namespace:              stack.Namespace,
			Gateway:                stack.GatewayName,
			ExpectPDB:              stack.LinkReplicas > 1,
			Local:                  stack.TrafficPolicy == hk8s.TrafficPolicyLocal,
			ClusterRoleBindingName: stack.LinkClusterRoleBindingName,
			Timeout:                orphanDrainTimeout,
		})
		if err := s.client.DeleteNamespace(cctx, stack.Namespace); err != nil {
			s.log.Error("delete namespace", zap.Error(err))
		}
		// The extra namespaces hold no GCP-backed resources or finalizers, so they
		// can go alongside the primary one.
		for _, ns := range stack.extraNamespaces {
			if err := s.client.DeleteNamespace(cctx, ns); err != nil {
				s.log.Error("delete extra namespace", zap.String("ns", ns), zap.Error(err))
			}
		}
	})
}
