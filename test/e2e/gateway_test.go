package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/shared"

	"golang.org/x/sync/errgroup"
	policyv1 "k8s.io/api/policy/v1"
	utilexec "k8s.io/client-go/util/exec"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	e2eharness "github.com/tripod-networks/wireguard-gateway-operator/test/harness/e2e"
	hk8s "github.com/tripod-networks/wireguard-gateway-operator/test/harness/k8s"
)

// Ready=False reasons the lifecycle subtests assert on, mirroring the operator's
// unexported reason constants.
const (
	crossNamespaceForwardDeniedReason = "CrossNamespaceForwardDenied"
	serviceNotFoundReason             = "ServiceNotFound"
	targetPortNotListeningReason      = "TargetPortNotListening"
)

// consentLabel and consentValue are the cross-namespace ingress consent label,
// mirroring the operator's unexported gate.
const (
	consentLabel = "wgnet.dev/allow-gateway-ingress"
	consentValue = "true"
)

// lifecycleConditionTimeout bounds a wait for the operator to re-stamp Ready after a
// forward, backend or consent change: a re-classification and status write, not a GCP trip.
const lifecycleConditionTimeout = 90 * time.Second

// lifecycleReadyTimeout bounds a lifecycle subtest's wait for the Gateway to return
// Ready after a forward becomes valid, sharing editRollTimeout's budget.
const lifecycleReadyTimeout = editRollTimeout

// deniedConditionTimeout bounds the wait for a validation-failure Gateway to report
// Ready=False, decided on the first reconcile and so short.
const deniedConditionTimeout = 90 * time.Second

// editRollTimeout bounds the wait for Ready after a live forward edit: re-render, in-place
// nftables re-apply and a fresh handshake, with no pod replacement.
const editRollTimeout = 3 * time.Minute

// coexistWGListenPortA and coexistWGListenPortB are the distinct WireGuard listen
// ports TestGatewayCoexistence gives its two gateways, so the isolation assertion
// can prove each rule admits only its own WG port.
const (
	coexistWGListenPortA = 51820
	coexistWGListenPortB = 51821
)

// TestGatewayCoexistence covers two gateways sharing one GCP VPC, isolated by per-gateway
// service-account scoping: each serves only its own forwards, and one VPC backs both.
func TestGatewayCoexistence(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	// Distinct WG and exposed ports make the isolation assertion test targetServiceAccounts
	// scoping, not port bookkeeping. Bring-up errors re-raise where t.Fatal is legal.
	var stackA, stackB *e2eharness.Stack
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		s, err := suite.StartE(gctx, t, e2eharness.WithWireguardListenPort(coexistWGListenPortA))
		if err != nil {
			return fmt.Errorf("start stack A: %w", err)
		}
		stackA = s
		return nil
	})
	g.Go(func() error {
		s, err := suite.StartE(gctx, t, e2eharness.WithWireguardListenPort(coexistWGListenPortB))
		if err != nil {
			return fmt.Errorf("start stack B: %w", err)
		}
		stackB = s
		return nil
	})
	if err := g.Wait(); err != nil {
		t.Fatalf("provision coexisting gateways: %v", err)
	}

	if stackA.Address == "" || stackB.Address == "" {
		t.Fatalf("a gateway reported no public IP (A=%q B=%q)", stackA.Address, stackB.Address)
	}
	t.Logf("coexisting gateways: A=%s B=%s", stackA.Address, stackB.Address)

	client := suite.Client()

	// Distinctly named backends so a marker identifies which gateway answered.
	const (
		backendA = "gateway-echo-coexist-a"
		backendB = "gateway-echo-coexist-b"
	)
	if _, err := client.DeployEchoBackend(ctx, stackA.Namespace, backendA); err != nil {
		t.Fatalf("deploy coexistence backend A: %v", err)
	}
	if _, err := client.DeployEchoBackend(ctx, stackB.Namespace, backendB); err != nil {
		t.Fatalf("deploy coexistence backend B: %v", err)
	}

	if err := client.UpdateGateway(ctx, stackA.Namespace, stackA.GatewayName, func(spec map[string]any) error {
		return appendForward(spec, hk8s.GatewayForward{
			Port: stackA.ServiceCreatedPort, Protocol: "TCP", Service: backendA, TargetPort: stackA.TCPBackendPort,
		})
	}); err != nil {
		t.Fatalf("forward coexistence backend A: %v", err)
	}
	if err := client.UpdateGateway(ctx, stackB.Namespace, stackB.GatewayName, func(spec map[string]any) error {
		return appendForward(spec, hk8s.GatewayForward{
			Port: stackB.ServiceDeletedPort, Protocol: "TCP", Service: backendB, TargetPort: stackB.TCPBackendPort,
		})
	}); err != nil {
		t.Fatalf("forward coexistence backend B: %v", err)
	}

	if _, err := client.WaitGatewayReady(ctx, stackA.Namespace, stackA.GatewayName, lifecycleReadyTimeout); err != nil {
		t.Fatalf("gateway A not ready after coexistence forward: %v", err)
	}
	if _, err := client.WaitGatewayReady(ctx, stackB.Namespace, stackB.GatewayName, lifecycleReadyTimeout); err != nil {
		t.Fatalf("gateway B not ready after coexistence forward: %v", err)
	}

	// The just-added forward uses the edit budget: the link's new nftables rule is
	// not trailed by the readiness gate.
	markerA, err := probeTCPThroughGatewayPortUntil(ctx, stackA, stackA.ServiceCreatedPort, editRollTimeout)
	if err != nil {
		t.Fatalf("gateway A data path: %v", err)
	}
	assertBackendMarker(t, markerA, backendA)
	markerB, err := probeTCPThroughGatewayPortUntil(ctx, stackB, stackB.ServiceDeletedPort, editRollTimeout)
	if err != nil {
		t.Fatalf("gateway B data path: %v", err)
	}
	assertBackendMarker(t, markerB, backendB)

	// Neither gateway forwards the other's port, so the SYN is dropped immediately;
	// the port was never opened here, so no propagation wait is needed.
	if err := probeTCPDenied(ctx, stackA, stackB.ServiceDeletedPort); err != nil {
		t.Fatalf("gateway A leaked gateway B's port %d: %v", stackB.ServiceDeletedPort, err)
	}
	if err := probeTCPDenied(ctx, stackB, stackA.ServiceCreatedPort); err != nil {
		t.Fatalf("gateway B leaked gateway A's port %d: %v", stackA.ServiceCreatedPort, err)
	}

	// Assert at the firewall-rule level that each gateway's rules target only its own
	// SA and WG port, more reliable than a silently-dropped UDP data-path probe.
	saA, err := suite.GatewayServiceAccountEmail(ctx, stackA.Namespace, stackA.GatewayName)
	if err != nil {
		t.Fatalf("read gateway A service account email: %v", err)
	}
	saB, err := suite.GatewayServiceAccountEmail(ctx, stackB.Namespace, stackB.GatewayName)
	if err != nil {
		t.Fatalf("read gateway B service account email: %v", err)
	}
	if saA == "" || saB == "" {
		t.Fatalf("a gateway reported no service account email (A=%q B=%q)", saA, saB)
	}
	if saA == saB {
		t.Fatalf("gateways share service account email %q; want distinct per-gateway SAs", saA)
	}
	assertFirewallIsolation(ctx, t, suite, stackA, saA, saB, stackB.WireguardListenPort)
	assertFirewallIsolation(ctx, t, suite, stackB, saB, saA, stackA.WireguardListenPort)

	// The VPC is created once on the first gateway and reused, never duplicated.
	residual, err := suite.SharedNetworkResidual(ctx)
	if err != nil {
		t.Fatalf("describe shared network: %v", err)
	}
	if residual == "" {
		t.Fatalf("shared network %s absent; want the one VPC backing both gateways",
			e2eharness.SharedNetworkName)
	}
}

// assertFirewallIsolation fails unless every firewall rule for stack's gateway targets only
// ownSA and opens the gateway's own WireGuard port in some rule but never otherWG.
func assertFirewallIsolation(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, ownSA, otherSA string, otherWG int) {
	t.Helper()

	rules, err := suite.GatewayFirewallTargets(ctx, stack.NamePrefix)
	if err != nil {
		t.Fatalf("list firewall rules for gateway %s: %v", stack.NamePrefix, err)
	}
	if len(rules) == 0 {
		t.Fatalf("gateway %s has no firewall rules; want at least one scoped to its SA", stack.NamePrefix)
	}

	ownWGPort := strconv.Itoa(stack.WireguardListenPort)
	otherWGPort := strconv.Itoa(otherWG)
	sawOwnWG := false
	for _, rule := range rules {
		// The caller asserted ownSA != otherSA, so a single ownSA target also proves
		// the rule never opens this gateway's ports on the other's VM.
		if len(rule.TargetServiceAccounts) != 1 || rule.TargetServiceAccounts[0] != ownSA {
			t.Fatalf("firewall rule %q targets %v, want exactly [%s] (and never the other gateway's SA %s)",
				rule.Name, rule.TargetServiceAccounts, ownSA, otherSA)
		}
		for _, allowed := range rule.Allowed {
			if !strings.EqualFold(allowed.Protocol, "udp") {
				continue
			}
			for _, p := range allowed.Ports {
				if p == ownWGPort {
					sawOwnWG = true
				}
				if p == otherWGPort {
					t.Fatalf("firewall rule %q admits the other gateway's WireGuard port %s; WG ports leak across gateways", rule.Name, otherWGPort)
				}
			}
		}
	}
	if !sawOwnWG {
		t.Fatalf("gateway %s firewall rules do not admit its own WireGuard port %s", stack.NamePrefix, ownWGPort)
	}
}

// TestGatewayDataPath covers the data path against real GCP: forwarded TCP and UDP echoes
// are reachable on the public IP while non-forwarded ports and internet ICMP are not.
func TestGatewayDataPath(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	stack, err := suite.Start(ctx, t)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}

	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	t.Logf("gateway public IP: %s", stack.Address)

	t.Run("tcp", func(t *testing.T) {
		marker, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("tcp data path: %v", err)
		}
		// The marker's prefix proves the request reached the intended echo pod, not
		// merely some pod.
		assertBackendMarker(t, marker, stack.TCPBackendName)
		t.Logf("tcp echo marker (echo pod name): %s", marker)
	})

	t.Run("clientip-cluster", func(t *testing.T) {
		got, err := probeClientIPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("clientip data path: %v", err)
		}
		podIPs, err := suite.Client().LinkPodIPs(ctx, stack.Namespace, stack.GatewayName)
		if err != nil {
			t.Fatalf("read link pod IPs: %v", err)
		}
		if !slices.Contains(podIPs, got) {
			t.Errorf("Cluster-mode /clientip = %q, want one of the link pod IPs %v; the link's postrouting masquerade is what rewrites the source in this mode",
				got, podIPs)
		}
	})

	// link-status-cluster proves a Cluster Gateway consumes no link id and still
	// reports which node runs the pod holding the Lease.
	t.Run("link-status-cluster", func(t *testing.T) {
		holder, err := suite.Client().GetLeaseHolder(ctx, stack.Namespace, linkLeaseName(stack.GatewayName))
		if err != nil {
			t.Fatalf("read lease holder: %v", err)
		}
		if holder == "" {
			t.Fatal("link lease has no holder; no replica programs the data plane")
		}
		node, err := suite.Client().PodNode(ctx, stack.Namespace, holder)
		if err != nil {
			t.Fatalf("read node of holder %s: %v", holder, err)
		}
		if err := retryUntil(ctx, lifecycleConditionTimeout, func(ctx context.Context) error {
			status, err := suite.Client().GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
			if err != nil {
				return err
			}
			if status.LinkID != 0 {
				return fmt.Errorf("status.link.id = %d, want 0; a Cluster gateway allocates no link id", status.LinkID)
			}
			if status.ActiveNode != node {
				return fmt.Errorf("status.link.activeNode = %q, want the holder %s's node %q", status.ActiveNode, holder, node)
			}
			return nil
		}); err != nil {
			t.Fatalf("cluster-mode link status: %v", err)
		}
	})

	t.Run("udp", func(t *testing.T) {
		const payload = "gateway-e2e-udp-probe"
		got, err := probeUDPThroughGateway(ctx, stack, payload)
		if err != nil {
			t.Fatalf("udp data path: %v", err)
		}
		if got != payload {
			t.Fatalf("udp echo = %q, want %q", got, payload)
		}
	})

	t.Run("nodeport", func(t *testing.T) {
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.NodePortPublicPort)
		if err != nil {
			t.Fatalf("nodeport data path: %v", err)
		}
		assertBackendMarker(t, marker, stack.NodePortBackendName)
		t.Logf("nodeport echo marker (echo pod name): %s", marker)
	})

	t.Run("cross-namespace", func(t *testing.T) {
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.CrossNSPublicPort)
		if err != nil {
			t.Fatalf("cross-namespace data path: %v", err)
		}
		assertBackendMarker(t, marker, stack.CrossNSBackendName)
		t.Logf("cross-namespace echo marker (echo pod name): %s", marker)
	})

	t.Run("icmp-denied", func(t *testing.T) {
		// The firewall does not allow internet-wide ICMP, so a reply is a leak.
		if err := pingDenied(ctx, stack); err != nil {
			t.Fatalf("icmp negative probe: %v", err)
		}
	})

	// Start asserted NegativePort is disjoint from the forwarded and WG ports, so a
	// hit here is a real leak, not a misconfigured probe.
	t.Run("tcp-denied", func(t *testing.T) {
		if err := probeTCPDenied(ctx, stack, stack.NegativePort); err != nil {
			t.Fatalf("tcp negative probe: %v", err)
		}
	})

	t.Run("udp-denied", func(t *testing.T) {
		if err := probeUDPDenied(ctx, stack, stack.NegativePort, "gateway-e2e-udp-denied"); err != nil {
			t.Fatalf("udp negative probe: %v", err)
		}
	})

	// forward-retarget points a dedicated forward at one backend then retargets it to a
	// second, leaving the create-time forwards untouched.
	t.Run("forward-retarget", func(t *testing.T) {
		client := suite.Client()

		// Read inside the cleanup, where t.Failed reflects the final result, to leave
		// a failing data path inspectable.
		preserve := os.Getenv("GATEWAY_E2E_PRESERVE") != ""

		const retargetBackend = "gateway-echo-retarget"
		t.Cleanup(func() {
			if t.Failed() && preserve {
				t.Logf("preserving forward-retarget failure state: forward on port %d and backend %s left in place (GATEWAY_E2E_PRESERVE)", stack.ForwardRetargetPort, retargetBackend)
				return
			}
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.ForwardRetargetPort)
			}); err != nil {
				t.Logf("cleanup remove forward-retarget forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, retargetBackend); err != nil {
				t.Logf("cleanup delete service %s: %v", retargetBackend, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, retargetBackend); err != nil {
				t.Logf("cleanup delete deployment %s: %v", retargetBackend, err)
			}
		})

		// Forward the dedicated port to the create-time echo first; the marker proves
		// traffic reaches the original backend before the retarget.
		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, retargetBackend); err != nil {
			t.Fatalf("deploy retarget backend: %v", err)
		}
		// The echo has no readinessProbe, so gate on it serving before the retarget's
		// DNAT goes live, else the probe blackholes for the full window.
		if err := client.WaitDeploymentAvailable(ctx, stack.Namespace, retargetBackend, lifecycleReadyTimeout); err != nil {
			t.Fatalf("retarget backend not available: %v", err)
		}
		if err := client.WaitEndpointsReady(ctx, stack.Namespace, retargetBackend, lifecycleReadyTimeout); err != nil {
			t.Fatalf("retarget backend has no ready endpoints: %v", err)
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.ForwardRetargetPort, Protocol: "TCP",
				Service: stack.TCPBackendName, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add forward to retarget origin: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after forward-retarget origin added: %v", err)
		}
		origin, err := probeTCPThroughGatewayPort(ctx, stack, stack.ForwardRetargetPort)
		if err != nil {
			t.Fatalf("forward-retarget origin data path: %v", err)
		}
		assertBackendMarker(t, origin, stack.TCPBackendName)

		// The link reloads its ConfigMap in place, so its DNAT can trail Ready and a
		// single probe can catch the old backend; poll until the marker leaves origin.
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return setForwardService(spec, stack.ForwardRetargetPort, retargetBackend, "")
		}); err != nil {
			t.Fatalf("retarget forward to second backend: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after forward retarget: %v", err)
		}
		retargeted, err := probeUntilMarkerChanges(ctx, stack, stack.ForwardRetargetPort, origin, lifecycleReadyTimeout)
		if err != nil {
			t.Fatalf("retarget did not converge to the new backend: %v", err)
		}
		assertBackendMarker(t, retargeted, retargetBackend)
	})
}

// TestGatewayForwardEdit covers live forward edits over the wire: adding one rolls the link
// onto new nftables rules with no pod roll, and a forward to a missing Service is denied.
func TestGatewayForwardEdit(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	stack, err := suite.Start(ctx, t)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}

	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	t.Logf("gateway public IP: %s", stack.Address)

	// forward-edit adds a forward live; the data-path probe on the new port is the
	// signal the link reloaded its ConfigMap in place, with no pod roll.
	t.Run("forward-edit", func(t *testing.T) {
		client := suite.Client()

		addForward := hk8s.GatewayForward{
			Port:       stack.EditedPublicPort,
			Protocol:   "TCP",
			Service:    "gateway-echo-tcp",
			TargetPort: 8080,
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, addForward)
		}); err != nil {
			t.Fatalf("add forward to gateway: %v", err)
		}

		// The in-place reload keeps the same pod, so the data-path probe on the new
		// port confirms the reloaded nftables rules took effect.
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, editRollTimeout); err != nil {
			t.Fatalf("gateway not ready after forward edit: %v", err)
		}

		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.EditedPublicPort)
		if err != nil {
			t.Fatalf("edited-forward data path: %v", err)
		}
		if marker == "" {
			t.Fatal("edited-forward echo returned an empty marker")
		}
		t.Logf("edited-forward echo marker (echo pod name): %s", marker)
	})

	// The live-classification subtests only add and remove dedicated forwards, so an invalid
	// one leaves the VM up with Ready=False rather than tearing it down.

	// service-created-after-gateway: a forward to a missing Service is denied
	// (ServiceNotFound); creating the Service admits it and the port becomes reachable.
	t.Run("service-created-after-gateway", func(t *testing.T) {
		client := suite.Client()

		const svcName = "gateway-echo-created"
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.ServiceCreatedPort)
			}); err != nil {
				t.Logf("cleanup remove service-created forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete service %s: %v", svcName, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete deployment %s: %v", svcName, err)
			}
		})

		// Adding the forward before the backend exists must keep the gateway up (its
		// create-time forwards stay valid) and report Ready=False/ServiceNotFound.
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.ServiceCreatedPort, Protocol: "TCP", Service: svcName, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add forward to missing service: %v", err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", serviceNotFoundReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("gateway did not report Ready=False/%s for missing backend: %v", serviceNotFoundReason, err)
		}

		// Creating the Service re-classifies the forward as valid; the new port
		// becomes reachable.
		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("deploy created-after backend: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after backend created: %v", err)
		}
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.ServiceCreatedPort)
		if err != nil {
			t.Fatalf("created-after-forward data path: %v", err)
		}
		assertBackendMarker(t, marker, svcName)
	})
}

// TestGatewayConsentLifecycle covers per-forward classification on a live gateway: deleting
// a backend Service closes only its forward, and the consent label gates a cross-ns one.
func TestGatewayConsentLifecycle(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	stack, err := suite.Start(ctx, t)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}

	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	t.Logf("gateway public IP: %s", stack.Address)

	// service-deleted: deleting a live backend Service drops only its forward, while
	// the create-time forwards keep working and the gateway keeps its VM.
	t.Run("service-deleted", func(t *testing.T) {
		client := suite.Client()

		const svcName = "gateway-echo-deletable"
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.ServiceDeletedPort)
			}); err != nil {
				t.Logf("cleanup remove service-deleted forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete service %s: %v", svcName, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete deployment %s: %v", svcName, err)
			}
		})

		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("deploy deletable backend: %v", err)
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.ServiceDeletedPort, Protocol: "TCP", Service: svcName, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add forward to deletable service: %v", err)
		}
		// The data path through a freshly-opened forward is already proven by the
		// service-created probe, so this asserts the admit transition via Ready only.
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready with deletable forward: %v", err)
		}

		// Deleting the backend re-classifies the forward as ServiceNotFound; the
		// operator re-renders without it (closing the port) while keeping its VM.
		if err := client.DeleteService(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("delete deletable backend service: %v", err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", serviceNotFoundReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("gateway did not report Ready=False/%s after backend deleted: %v", serviceNotFoundReason, err)
		}
		if err := waitPortDenied(ctx, stack, stack.ServiceDeletedPort, lifecycleReadyTimeout); err != nil {
			t.Fatalf("deleted-backend port did not stop responding: %v", err)
		}

		// Dropping one forward must not disturb the others.
		survivor, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward broke after unrelated backend delete: %v", err)
		}
		assertBackendMarker(t, survivor, stack.TCPBackendName)
	})

	// consent-label-toggle: the operator's Namespace watch observes the label, so the forward
	// is re-classified without a Gateway edit.
	t.Run("consent-label-toggle", func(t *testing.T) {
		client := suite.Client()

		consentNS := stack.Namespace + "-consent-target"
		const svcName = "gateway-echo-consent"
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.ConsentTogglePort)
			}); err != nil {
				t.Logf("cleanup remove consent forward: %v", err)
			}
			if err := client.DeleteNamespace(cctx, consentNS); err != nil {
				t.Logf("cleanup delete consent namespace %s: %v", consentNS, err)
			}
		})

		// The target namespace starts without the consent label.
		if err := client.EnsureNamespace(ctx, consentNS); err != nil {
			t.Fatalf("ensure consent namespace: %v", err)
		}
		if _, err := client.DeployEchoBackend(ctx, consentNS, svcName); err != nil {
			t.Fatalf("deploy consent backend: %v", err)
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.ConsentTogglePort, Protocol: "TCP", Service: svcName,
				Namespace: consentNS, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add cross-namespace forward: %v", err)
		}

		// Unlabelled: denied.
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", crossNamespaceForwardDeniedReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("cross-namespace forward into unlabelled ns not denied: %v", err)
		}

		// Label added: admitted. The probe proves the consented forward carries
		// traffic over the wire, not merely that the condition flipped.
		if err := client.SetNamespaceLabel(ctx, consentNS, consentLabel, consentValue); err != nil {
			t.Fatalf("add consent label: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after consent label added: %v", err)
		}
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.ConsentTogglePort)
		if err != nil {
			t.Fatalf("consent-forward data path after label added: %v", err)
		}
		assertBackendMarker(t, marker, svcName)

		// Label removed: re-denied and the port stops.
		if err := client.RemoveNamespaceLabel(ctx, consentNS, consentLabel); err != nil {
			t.Fatalf("remove consent label: %v", err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", crossNamespaceForwardDeniedReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("cross-namespace forward not re-denied after label removed: %v", err)
		}
		if err := waitPortDenied(ctx, stack, stack.ConsentTogglePort, lifecycleReadyTimeout); err != nil {
			t.Fatalf("consent-forward port did not stop after label removed: %v", err)
		}
	})

	// backend-rollout proves a forward's DNAT targets the Service's stable ClusterIP, not a
	// pod: after rolling every backend pod the forward still carries traffic.
	t.Run("backend-rollout", func(t *testing.T) {
		client := suite.Client()

		const svcName = "gateway-echo-rollout"
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.BackendRolloutPort)
			}); err != nil {
				t.Logf("cleanup remove backend-rollout forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete service %s: %v", svcName, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, svcName); err != nil {
				t.Logf("cleanup delete deployment %s: %v", svcName, err)
			}
		})

		if _, err := client.DeployEchoBackend(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("deploy rollout backend: %v", err)
		}
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.BackendRolloutPort, Protocol: "TCP", Service: svcName, TargetPort: stack.TCPBackendPort,
			})
		}); err != nil {
			t.Fatalf("add forward to rollout backend: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready with rollout forward: %v", err)
		}
		before, err := probeTCPThroughGatewayPort(ctx, stack, stack.BackendRolloutPort)
		if err != nil {
			t.Fatalf("rollout backend data path before roll: %v", err)
		}
		assertBackendMarker(t, before, svcName)

		// At replicas=1 the old pod can linger in endpoints across the roll, so poll until
		// the marker changes under the budget the roll and endpoint drain can need.
		if err := client.RestartDeployment(ctx, stack.Namespace, svcName); err != nil {
			t.Fatalf("restart rollout backend: %v", err)
		}
		if err := client.WaitDeploymentAvailable(ctx, stack.Namespace, svcName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("rollout backend not available after roll: %v", err)
		}
		// A Deployment can report Available before the fresh pod is a ready endpoint,
		// so gate the convergence probe on one.
		if err := client.WaitEndpointsReady(ctx, stack.Namespace, svcName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("rollout backend has no ready endpoints after roll: %v", err)
		}
		after, err := probeUntilMarkerChanges(ctx, stack, stack.BackendRolloutPort, before, lifecycleReadyTimeout)
		if err != nil {
			t.Fatalf("rollout backend did not converge to a fresh pod: %v", err)
		}
		assertBackendMarker(t, after, svcName)
	})
}

// TestGatewayTargetPortLifecycle covers targetPort classification, and a Gateway whose only
// forward is an unlabelled cross-namespace one, which must provision no VM at all.
func TestGatewayTargetPortLifecycle(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	stack, err := suite.Start(ctx, t)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}

	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	t.Logf("gateway public IP: %s", stack.Address)

	// targetPort-not-listening: a forward whose targetPort the backend does not
	// publish is denied (TargetPortNotListening); correcting it admits the forward.
	t.Run("targetPort-not-listening", func(t *testing.T) {
		client := suite.Client()

		const wrongTargetPort = 9090
		t.Cleanup(func() {
			if err := client.UpdateGateway(context.Background(), stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.TargetPortScenarioPort)
			}); err != nil {
				t.Logf("cleanup remove targetPort forward: %v", err)
			}
		})

		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.TargetPortScenarioPort, Protocol: "TCP",
				Service: stack.TCPBackendName, TargetPort: wrongTargetPort,
			})
		}); err != nil {
			t.Fatalf("add forward with wrong targetPort: %v", err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", targetPortNotListeningReason, lifecycleConditionTimeout); err != nil {
			t.Fatalf("forward with non-published targetPort not denied: %v", err)
		}
		// Prove the denied forward is also closed at the firewall, not just reported
		// denied by the condition.
		if err := waitPortDenied(ctx, stack, stack.TargetPortScenarioPort, lifecycleReadyTimeout); err != nil {
			t.Fatalf("wrong-targetPort forward port did not stay closed: %v", err)
		}

		// Correcting the targetPort admits the forward.
		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return setForwardTargetPort(spec, stack.TargetPortScenarioPort, stack.TCPBackendPort)
		}); err != nil {
			t.Fatalf("correct targetPort: %v", err)
		}
		// The probe proves the corrected forward carries traffic over the wire.
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway not ready after targetPort corrected: %v", err)
		}
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.TargetPortScenarioPort)
		if err != nil {
			t.Fatalf("corrected-targetPort data path: %v", err)
		}
		assertBackendMarker(t, marker, stack.TCPBackendName)
	})

	// cross-namespace-denied: with zero valid forwards the operator never creates a VM and
	// reports the denial reason on Ready=False.
	t.Run("cross-namespace-denied", func(t *testing.T) {
		client := suite.Client()
		env := suite.Env()

		// The namespace exists but lacks the consent label, so the reason is
		// CrossNamespaceForwardDenied, not TargetNamespaceNotFound.
		deniedNS := stack.Namespace + "-denied-target"
		if err := client.EnsureNamespace(ctx, deniedNS); err != nil {
			t.Fatalf("ensure denied-target namespace: %v", err)
		}
		t.Cleanup(func() {
			if err := client.DeleteNamespace(context.Background(), deniedNS); err != nil {
				t.Logf("cleanup denied-target namespace %s: %v", deniedNS, err)
			}
		})

		deniedGateway := stack.GatewayName + "-denied"
		spec := hk8s.GatewaySpec{
			ProjectID:   env.ProjectID,
			Region:      env.Region,
			Zone:        env.Zone,
			MachineType: "e2-micro",
			Forwards: []hk8s.GatewayForward{{
				Port:      stack.TCPPublicPort,
				Protocol:  "TCP",
				Service:   "gateway-echo-tcp",
				Namespace: deniedNS,
			}},
		}
		if err := client.CreateGateway(ctx, stack.Namespace, deniedGateway, spec); err != nil {
			t.Fatalf("create denied gateway: %v", err)
		}
		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.DeleteGateway(cctx, stack.Namespace, deniedGateway); err != nil {
				t.Logf("cleanup denied gateway %s: %v", deniedGateway, err)
				return
			}
			// The denied Gateway never created an XGatewayGCP, so its finalizer clears
			// immediately; wait so the namespace teardown does not race it.
			if err := client.WaitGatewayGone(cctx, stack.Namespace, deniedGateway, deniedConditionTimeout); err != nil {
				t.Logf("cleanup wait denied gateway gone %s: %v", deniedGateway, err)
			}
		})

		if err := client.WaitGatewayCondition(ctx, stack.Namespace, deniedGateway,
			"Ready", "False", crossNamespaceForwardDeniedReason, deniedConditionTimeout); err != nil {
			t.Fatalf("denied gateway did not reach Ready=False reason %s: %v", crossNamespaceForwardDeniedReason, err)
		}
	})

	// link-pod-restart keys on the lease holder moving, the failover signal at any replica
	// count; the new holder re-establishes the tunnel and DNAT before traffic flows.
	t.Run("link-pod-restart", func(t *testing.T) {
		client := suite.Client()

		// Baseline before the active link pod is deleted.
		before, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward broken before link restart: %v", err)
		}
		assertBackendMarker(t, before, stack.TCPBackendName)

		oldHolder, err := client.GetLeaseHolder(ctx, stack.Namespace, linkLeaseName(stack.GatewayName))
		if err != nil {
			t.Fatalf("read link lease holder before restart: %v", err)
		}
		if oldHolder == "" {
			t.Fatal("link lease has no holder before restart; the active link never acquired leadership")
		}

		// At this shard's single replica the deleted pod is the lease holder, so
		// leadership must move to its replacement.
		deleted, err := client.DeletePodsByLabel(ctx, stack.Namespace, linkSelector(stack.GatewayName))
		if err != nil {
			t.Fatalf("delete link pods: %v", err)
		}
		if deleted < 1 {
			t.Fatalf("link selector in ns %q matched no pods", stack.Namespace)
		}

		newHolder, err := client.WaitLeaseHolderChanges(ctx, stack.Namespace, linkLeaseName(stack.GatewayName), oldHolder, lifecycleReadyTimeout)
		if err != nil {
			t.Fatalf("link lease holder did not move after restart: %v", err)
		}
		t.Logf("link lease holder moved %s -> %s", oldHolder, newHolder)

		// The data-path retry absorbs the new holder's handshake and rule convergence.
		after, err := probeTCPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("create-time tcp forward did not resume after link restart: %v", err)
		}
		assertBackendMarker(t, after, stack.TCPBackendName)
	})

	// Forward classification and validation transitions live in the controller
	// envtest, not duplicated here so each shard stays a single VM.
}

// haFailoverTimeout bounds the wait for the link lease holder to move: one lease duration
// plus the new holder publishing itself, not the tunnel bring-up the probe owns.
const haFailoverTimeout = 90 * time.Second

// haReplicas is the link replica count TestGatewayLinkHA provisions: one active plus
// one standby, the minimum exercising leader election, fencing, failover, and a PDB.
const haReplicas = 2

// clusterLinkIface is the WireGuard interface a Cluster-mode link programs. Local mode
// derives its name from the link id instead.
const clusterLinkIface = "wg0"

// clusterNftTable is the inet nftables table a Cluster-mode link programs, the data-plane
// half of the single-active invariant. Local mode derives its name from the link id.
const clusterNftTable = "gateway"

// TestGatewayLinkHA covers active-passive HA at two replicas: only the lease holder runs wg0
// and the inet table, and the path survives failover, a roll and a budgeted eviction.
func TestGatewayLinkHA(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()

	stack, err := suite.Start(ctx, t, e2eharness.WithLinkReplicas(haReplicas))
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}

	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	t.Logf("gateway public IP: %s", stack.Address)

	client := suite.Client()
	leaseName := linkLeaseName(stack.GatewayName)
	selector := linkSelector(stack.GatewayName)

	// Baseline before any HA scenario perturbs the active replica.
	baseline, err := probeTCPThroughGateway(ctx, stack)
	if err != nil {
		t.Fatalf("create-time tcp forward broken at HA baseline: %v", err)
	}
	assertBackendMarker(t, baseline, stack.TCPBackendName)

	// single-active proves exactly one replica owns wg0 and it is the lease holder.
	t.Run("single-active", func(t *testing.T) {
		holder, _ := assertSingleIfaceOwner(ctx, t, client, stack.Namespace, selector, leaseName, clusterLinkIface, haFailoverTimeout)
		t.Logf("active link replica: %s (lease holder, sole wg0 owner)", holder)
	})

	// standby-idle proves every non-holder replica carries no data plane (neither wg0
	// nor the inet gateway table); otherwise it would double-drive the tunnel.
	t.Run("standby-idle", func(t *testing.T) {
		holder, err := client.GetLeaseHolder(ctx, stack.Namespace, leaseName)
		if err != nil {
			t.Fatalf("read lease holder: %v", err)
		}
		if holder == "" {
			t.Fatal("link lease has no holder; no active replica")
		}
		pods, err := client.PodNamesByLabel(ctx, stack.Namespace, selector)
		if err != nil {
			t.Fatalf("list link pods: %v", err)
		}
		standbys := 0
		for _, pod := range pods {
			if pod == holder {
				continue
			}
			standbys++
			hasIface, err := podHasIface(ctx, client, stack.Namespace, pod, clusterLinkIface)
			if err != nil {
				t.Fatalf("check %s for wg0: %v", pod, err)
			}
			if hasIface {
				t.Errorf("standby %s has wg0; a demoted replica must not carry the interface", pod)
			}
			if podHasGatewayTable(ctx, t, client, stack.Namespace, pod) {
				t.Errorf("standby %s has the inet gateway table; a demoted replica must not carry the nftables data plane", pod)
			}
		}
		if standbys == 0 {
			t.Fatalf("no standby replicas among link pods %v (holder %q); HA test needs >1 replica", pods, holder)
		}
	})

	// failover proves leadership and the data plane move to a survivor when the
	// active replica is lost.
	t.Run("failover", func(t *testing.T) {
		oldHolder, err := client.GetLeaseHolder(ctx, stack.Namespace, leaseName)
		if err != nil {
			t.Fatalf("read lease holder before failover: %v", err)
		}
		if oldHolder == "" {
			t.Fatal("link lease has no holder before failover")
		}

		// Delete only the holder, leaving the standby; leadership must move to it.
		if err := client.DeletePod(ctx, stack.Namespace, oldHolder); err != nil {
			t.Fatalf("delete lease holder %s: %v", oldHolder, err)
		}

		newHolder, err := client.WaitLeaseHolderChanges(ctx, stack.Namespace, leaseName, oldHolder, haFailoverTimeout)
		if err != nil {
			t.Fatalf("lease holder did not move after holder deletion: %v", err)
		}
		t.Logf("failover: lease holder moved %s -> %s", oldHolder, newHolder)

		// wg0 bring-up trails the lease acquire, so allow the failover budget.
		if err := waitPodHasWG0(ctx, t, client, stack.Namespace, newHolder, haFailoverTimeout); err != nil {
			t.Fatalf("new holder %s did not bring up wg0 after failover: %v", newHolder, err)
		}

		// The until-probe absorbs the new holder's handshake and DNAT convergence,
		// which can exceed the steady-state window, hence the edit budget.
		after, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.TCPPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("data path did not resume after failover: %v", err)
		}
		assertBackendMarker(t, after, stack.TCPBackendName)
	})

	// rolling-update: with maxUnavailable=0 and leader election the holder stays up until a
	// replacement is Ready, so traffic tolerates at most a brief failover blip.
	t.Run("rolling-update", func(t *testing.T) {
		if err := client.RestartDeployment(ctx, stack.Namespace, leaseName); err != nil {
			t.Fatalf("restart link deployment: %v", err)
		}

		// The until-probe tolerates a brief blip while leadership moves to a rolled
		// pod, but must converge within the edit budget.
		during, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.TCPPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("data path not serviceable across link rolling update: %v", err)
		}
		assertBackendMarker(t, during, stack.TCPBackendName)

		if err := client.WaitDeploymentRolledOut(ctx, stack.Namespace, leaseName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("link deployment rollout not complete after restart: %v", err)
		}

		// The single-active invariant must survive the roll.
		assertSingleIfaceOwner(ctx, t, client, stack.Namespace, selector, leaseName, clusterLinkIface, haFailoverTimeout)
	})

	// pdb-protects: the status assertion catches the real failure mode, a selector matching
	// no pods, which a successful eviction alone would not surface.
	t.Run("pdb-protects", func(t *testing.T) {
		if err := client.SetLinkReplicas(ctx, stack.Namespace, stack.GatewayName, haReplicas); err != nil {
			t.Fatalf("rescale link to %d replicas: %v", haReplicas, err)
		}
		if err := client.WaitDeploymentAvailable(ctx, stack.Namespace, leaseName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("link deployment not available before eviction: %v", err)
		}

		// A mismatched selector would leave the status at NoPods with no disruption
		// allowed, which this assertion fails on.
		if err := waitPDBProtects(ctx, t, client, stack.Namespace, leaseName, haReplicas, lifecycleReadyTimeout); err != nil {
			t.Fatalf("link PDB did not reach protected status: %v", err)
		}

		pods, err := client.PodNamesByLabel(ctx, stack.Namespace, selector)
		if err != nil {
			t.Fatalf("list link pods: %v", err)
		}
		if len(pods) < haReplicas {
			t.Fatalf("link has %d pods, want >=%d before eviction test", len(pods), haReplicas)
		}

		// With DisruptionsAllowed==1 one eviction is within budget; a second
		// back-to-back would race the controller's recompute, so the test does not.
		if err := client.EvictPod(ctx, stack.Namespace, pods[0]); err != nil {
			t.Fatalf("within-budget link pod eviction rejected (want allowed under minAvailable=1 with %d replicas): %v", haReplicas, err)
		}
	})
}

// linkSelector is the label selector matching a gateway's link pods, mirroring the
// operator's unexported linkSelectorLabels.
func linkSelector(gatewayName string) string {
	return fmt.Sprintf("app.kubernetes.io/component=link,app.kubernetes.io/instance=%s", gatewayName)
}

// linkLeaseName is the Lease the link runs leader election over: <gateway>-link. It
// mirrors the operator's unexported linkComponentName.
func linkLeaseName(gatewayName string) string {
	return gatewayName + "-link"
}

// assertSingleIfaceOwner polls until exactly one replica owns iface and holds the lease: a
// replaced pod can briefly leave two owners, so the invariant is given until timeout.
func assertSingleIfaceOwner(ctx context.Context, t *testing.T, client *hk8s.Client, ns, selector, leaseName, iface string, timeout time.Duration) (holder string, owners []string) {
	t.Helper()
	var pods []string
	if err := retryUntil(ctx, timeout, func(ctx context.Context) error {
		var err error
		holder, err = client.GetLeaseHolder(ctx, ns, leaseName)
		if err != nil {
			return err
		}
		if holder == "" {
			return errors.New("link lease has no holder; no active replica")
		}
		pods, err = client.PodNamesByLabel(ctx, ns, selector)
		if err != nil {
			return err
		}
		owners = nil
		for _, pod := range pods {
			has, err := podHasIface(ctx, client, ns, pod, iface)
			if err != nil {
				return err
			}
			if has {
				owners = append(owners, pod)
			}
		}
		if len(owners) != 1 || owners[0] != holder {
			return fmt.Errorf("%s owners = %v among link pods %v, want exactly the lease holder %q", iface, owners, pods, holder)
		}
		return nil
	}); err != nil {
		t.Fatalf("want exactly one %s owner, the lease holder, within %s (last holder %q, owners %v): %v", iface, timeout, holder, owners, err)
	}
	return holder, owners
}

// podHasIface reports whether the pod's node carries iface; link pods run hostNetwork.
// A non-exit exec error (container not running yet, or gone) is returned so the caller retries.
func podHasIface(ctx context.Context, client *hk8s.Client, ns, pod, iface string) (bool, error) {
	_, stderr, err := client.ExecInPod(ctx, ns, pod, []string{"ip", "link", "show", iface})
	if err == nil {
		return true, nil
	}
	if _, ok := errors.AsType[utilexec.CodeExitError](err); ok {
		return false, nil
	}
	return false, fmt.Errorf("ip link show %s in %s/%s: %w (stderr: %s)", iface, ns, pod, err, strings.TrimSpace(stderr))
}

// podHasGatewayTable reports whether the inet gateway table is present. Only the active
// replica programs it, so a standby carrying it is a stale data plane.
func podHasGatewayTable(ctx context.Context, t *testing.T, client *hk8s.Client, ns, pod string) bool {
	t.Helper()
	_, _, err := client.ExecInPod(ctx, ns, pod, []string{"nft", "list", "table", "inet", clusterNftTable})
	return err == nil
}

// waitPodHasWG0 gives wg0 a bounded window: the new holder brings it up only after
// acquiring leadership, so the failover assertion must not race it.
func waitPodHasWG0(ctx context.Context, t *testing.T, client *hk8s.Client, ns, pod string, timeout time.Duration) error {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		has, err := podHasIface(dctx, client, ns, pod, clusterLinkIface)
		if err != nil {
			t.Fatalf("check %s/%s for wg0: %v", ns, pod, err)
		}
		if has {
			return nil
		}
		select {
		case <-dctx.Done():
			return fmt.Errorf("wg0 not present on %s/%s after %s", ns, pod, timeout)
		case <-ticker.C:
		}
	}
}

// waitPDBProtects polls until the controller computes full protection, which proves the
// selector matches the link pods; a bad selector stalls at NoPods.
func waitPDBProtects(ctx context.Context, t *testing.T, client *hk8s.Client, ns, name string, replicas int32, timeout time.Duration) error {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var last policyv1.PodDisruptionBudgetStatus
	for {
		status, err := client.GetPodDisruptionBudgetStatus(dctx, ns, name)
		if err == nil {
			last = status
			if status.ExpectedPods == replicas && status.CurrentHealthy == replicas &&
				status.DesiredHealthy == replicas-1 && status.DisruptionsAllowed == 1 {
				return nil
			}
		}
		select {
		case <-dctx.Done():
			return fmt.Errorf("pdb %s/%s status not protected after %s: %+v", ns, name, timeout, last)
		case <-ticker.C:
		}
	}
}

// assertBackendMarker checks an agnhost /hostname reply: a pod name is its Deployment's name
// plus a suffix, so the prefix names the backend that answered.
func assertBackendMarker(t *testing.T, marker, backend string) {
	t.Helper()
	if marker == "" {
		t.Fatalf("echo returned an empty marker; want a %q pod name", backend)
	}
	if !strings.HasPrefix(marker, backend) {
		t.Fatalf("echo marker %q is not from backend %q; forward routed to the wrong Service", marker, backend)
	}
}

// appendForward writes the unstructured shape the API server stores. A zero targetPort is
// omitted rather than sent, since the CRD sets minimum=1.
func appendForward(spec map[string]any, f hk8s.GatewayForward) error {
	existing, _ := spec["forwards"].([]any)
	entry := map[string]any{
		"port":     int64(f.Port),
		"protocol": f.Protocol,
		"service":  f.Service,
	}
	if f.Namespace != "" {
		entry["namespace"] = f.Namespace
	}
	if f.TargetPort != 0 {
		entry["targetPort"] = int64(f.TargetPort)
	}
	spec["forwards"] = append(existing, entry)
	return nil
}

// removeForward drops the forward on the given public port. It is a no-op when no forward
// uses that port, so cleanup is idempotent.
func removeForward(spec map[string]any, port int) error {
	existing, _ := spec["forwards"].([]any)
	kept := make([]any, 0, len(existing))
	for _, raw := range existing {
		entry, ok := raw.(map[string]any)
		if !ok {
			kept = append(kept, raw)
			continue
		}
		if p, ok := entry["port"].(int64); ok && int(p) == port {
			continue
		}
		kept = append(kept, entry)
	}
	spec["forwards"] = kept
	return nil
}

// setForwardTargetPort sets the targetPort of the forward on the given public port.
// It errors if no forward uses the port, so a misaddressed edit fails loudly.
func setForwardTargetPort(spec map[string]any, port, targetPort int) error {
	existing, _ := spec["forwards"].([]any)
	for _, raw := range existing {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if p, ok := entry["port"].(int64); ok && int(p) == port {
			entry["targetPort"] = int64(targetPort)
			return nil
		}
	}
	return fmt.Errorf("no forward on port %d to set targetPort", port)
}

// setForwardService retargets the forward on the given public port, erroring if none uses
// it. An empty namespace clears the target, defaulting to the Gateway's namespace.
func setForwardService(spec map[string]any, port int, service, namespace string) error {
	existing, _ := spec["forwards"].([]any)
	for _, raw := range existing {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if p, ok := entry["port"].(int64); ok && int(p) == port {
			entry["service"] = service
			if namespace != "" {
				entry["namespace"] = namespace
			} else {
				delete(entry, "namespace")
			}
			return nil
		}
	}
	return fmt.Errorf("no forward on port %d to set service", port)
}

// localHandoffTimeout: the old holder loses its only local endpoint and scores 0, which the
// election releases at once rather than after the handoff hold, so twice the hold is ample.
const localHandoffTimeout = 60 * time.Second

// localBackendReadyTimeout bounds the wait for the re-pinned echo to be a ready endpoint on
// the new worker, the precondition for the link election to move at all.
const localBackendReadyTimeout = 3 * time.Minute

// wgGatewayAddress mirrors the CRD default of spec.wireguard.gatewayAddress, the VM's
// tunnel-side address. A Local-mode /clientip answering with it means the VM masqueraded.
const wgGatewayAddress = "10.99.0.1"

// TestGatewayTrafficPolicyLocal covers the Local data path against real GCP: the backend
// observes the external client's source, and re-pinning it moves the Lease and the path.
func TestGatewayTrafficPolicyLocal(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	client := suite.Client()
	ctx := context.Background()

	stack, err := suite.Start(ctx, t, e2eharness.WithTrafficPolicy(hk8s.TrafficPolicyLocal))
	if err != nil {
		t.Fatalf("start local stack: %v", err)
	}
	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	t.Logf("gateway public IP: %s, backend pinned to %s", stack.Address, stack.BackendNode)

	excluded := readInClusterAddresses(ctx, t, client, stack)

	t.Run("clientip-preserves-external-source", func(t *testing.T) {
		got, err := probeClientIPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("clientip data path: %v", err)
		}
		assertExternalClientIP(t, got, excluded)
		t.Logf("local-mode /clientip: %s", got)
	})

	t.Run("udp-forward-serves", func(t *testing.T) {
		const payload = "gateway-e2e-local-udp-probe"
		got, err := probeUDPThroughGateway(ctx, stack, payload)
		if err != nil {
			t.Fatalf("local udp data path: %v", err)
		}
		if got != payload {
			t.Fatalf("udp echo = %q, want %q", got, payload)
		}
	})

	t.Run("cross-namespace-forward-serves", func(t *testing.T) {
		marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.CrossNSPublicPort)
		if err != nil {
			t.Fatalf("local cross-namespace data path: %v", err)
		}
		assertBackendMarker(t, marker, stack.CrossNSBackendName)

		got, err := probeClientIPThroughGatewayPort(ctx, stack, stack.CrossNSPublicPort)
		if err != nil {
			t.Fatalf("local cross-namespace clientip data path: %v", err)
		}
		assertExternalClientIP(t, got, excluded)
		t.Logf("local cross-namespace /clientip on port %d: %s", stack.CrossNSPublicPort, got)
	})

	// link-identity proves every node-global name the link programs derives from the
	// id the Gateway reports, so an operator reading the status can find them.
	t.Run("link-identity", func(t *testing.T) {
		status, err := client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
		if err != nil {
			t.Fatalf("read gateway status: %v", err)
		}
		if status.LinkID < 1 || status.LinkID > link.MaxLinkID {
			t.Fatalf("status.link.id = %d, want an allocated id in 1..%d", status.LinkID, link.MaxLinkID)
		}
		second, err := client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
		if err != nil {
			t.Fatalf("re-read gateway status: %v", err)
		}
		if second.LinkID != status.LinkID {
			t.Fatalf("status.link.id changed between reads: %d then %d; an allocated id must never be rewritten", status.LinkID, second.LinkID)
		}

		holder, err := client.GetLeaseHolder(ctx, stack.Namespace, linkLeaseName(stack.GatewayName))
		if err != nil {
			t.Fatalf("read lease holder: %v", err)
		}
		if holder == "" {
			t.Fatal("link lease has no holder; no link pod programs the data plane")
		}
		for _, cmd := range [][]string{
			{"ip", "link", "show", link.NewSlotIdentity(status.LinkID, 0).Interface},
			{"nft", "list", "table", "inet", link.NewGatewayIdentity(status.LinkID).NftTable},
		} {
			if _, stderr, err := client.ExecInPod(ctx, stack.Namespace, holder, cmd); err != nil {
				t.Errorf("%v in holder %s: %v (stderr: %s); the id-derived name must exist on the holder", cmd, holder, err, strings.TrimSpace(stderr))
			}
		}
	})

	t.Run("active-node-follows-the-backend", func(t *testing.T) {
		assertActiveNode(ctx, t, client, stack, stack.BackendNode, haFailoverTimeout)

		other := otherWorker(t, stack.WorkerNodes, stack.BackendNode)
		refs := stack.LocalBackendRefs()
		for _, ref := range refs {
			if err := client.RepinEchoToNode(ctx, ref.Namespace, ref.Name, other); err != nil {
				t.Fatalf("re-pin echo backend %s/%s to %s: %v", ref.Namespace, ref.Name, other, err)
			}
		}
		// Every forward must have a ready endpoint on the new node before the election
		// can move: a partially re-pinned node is not fully eligible.
		if err := client.WaitEndpointsReadyOnNode(ctx, refs, other, localBackendReadyTimeout); err != nil {
			t.Fatalf("re-pinned echo backends did not become ready endpoints on %s: %v", other, err)
		}

		if err := retryUntil(ctx, localHandoffTimeout, func(ctx context.Context) error {
			st, err := client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
			if err != nil {
				return err
			}
			if st.ActiveNode != other {
				return fmt.Errorf("status.link.activeNode = %q, want %q", st.ActiveNode, other)
			}
			return nil
		}); err != nil {
			t.Fatalf("link Lease did not hand off to the backend's new node: %v", err)
		}

		got, err := probeClientIPThroughGateway(ctx, stack)
		if err != nil {
			t.Fatalf("clientip data path after handoff: %v", err)
		}
		assertExternalClientIP(t, got, readInClusterAddresses(ctx, t, client, stack))
		t.Logf("local-mode /clientip after handoff to %s: %s", other, got)
	})

	// The backend is pinned to the current Lease holder: a Local forward only serves while
	// its endpoint is ready on the holder's node.
	t.Run("forward-edit", func(t *testing.T) {
		const editBackend = "gateway-echo-local-edit"

		status, err := client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
		if err != nil {
			t.Fatalf("read gateway status: %v", err)
		}
		if status.ActiveNode == "" {
			t.Fatal("status.link.activeNode is empty; the added forward needs a known holder node to pin its backend to")
		}

		t.Cleanup(func() {
			cctx := context.Background()
			if err := client.UpdateGateway(cctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
				return removeForward(spec, stack.EditedPublicPort)
			}); err != nil {
				t.Logf("cleanup remove local forward-edit forward: %v", err)
			}
			if err := client.DeleteService(cctx, stack.Namespace, editBackend); err != nil {
				t.Logf("cleanup delete service %s: %v", editBackend, err)
			}
			if err := client.DeleteDeployment(cctx, stack.Namespace, editBackend); err != nil {
				t.Logf("cleanup delete deployment %s: %v", editBackend, err)
			}
		})

		backend, err := client.DeployEchoOnNode(ctx, stack.Namespace, editBackend, status.ActiveNode)
		if err != nil {
			t.Fatalf("deploy forward-edit backend on %s: %v", status.ActiveNode, err)
		}
		if err := client.WaitEndpointsReady(ctx, stack.Namespace, editBackend, localBackendReadyTimeout); err != nil {
			t.Fatalf("forward-edit backend did not become a ready endpoint on %s: %v", status.ActiveNode, err)
		}

		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return appendForward(spec, hk8s.GatewayForward{
				Port: stack.EditedPublicPort, Protocol: "TCP", Service: editBackend, TargetPort: backend.Port,
			})
		}); err != nil {
			t.Fatalf("add forward to local gateway: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, editRollTimeout); err != nil {
			t.Fatalf("gateway not ready after local forward edit: %v", err)
		}

		marker, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.EditedPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("local edited-forward data path: %v", err)
		}
		assertBackendMarker(t, marker, editBackend)

		clientIP, err := probeClientIPThroughGatewayPort(ctx, stack, stack.EditedPublicPort)
		if err != nil {
			t.Fatalf("local edited-forward clientip data path: %v", err)
		}
		assertExternalClientIP(t, clientIP, readInClusterAddresses(ctx, t, client, stack))
		t.Logf("local edited-forward /clientip on port %d: %s", stack.EditedPublicPort, clientIP)

		if err := client.UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
			return removeForward(spec, stack.EditedPublicPort)
		}); err != nil {
			t.Fatalf("remove forward from local gateway: %v", err)
		}
		if _, err := client.WaitGatewayReady(ctx, stack.Namespace, stack.GatewayName, editRollTimeout); err != nil {
			t.Fatalf("gateway not ready after local forward removal: %v", err)
		}
		if err := waitPortDenied(ctx, stack, stack.EditedPublicPort, lifecycleReadyTimeout); err != nil {
			t.Fatalf("removed local forward kept serving: %v", err)
		}
	})
}

// TestGatewayTrafficPolicyLocalDisruption covers losing the pod that programs the Local data
// plane, or the endpoint it needs: a kill, a graceful delete, a missing endpoint, a roll.
func TestGatewayTrafficPolicyLocalDisruption(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	client := suite.Client()
	ctx := context.Background()

	stack, err := suite.Start(ctx, t, e2eharness.WithTrafficPolicy(hk8s.TrafficPolicyLocal))
	if err != nil {
		t.Fatalf("start local disruption stack: %v", err)
	}
	if stack.Address == "" {
		t.Fatal("gateway reported no public IP")
	}
	leaseName := linkLeaseName(stack.GatewayName)
	t.Logf("gateway public IP: %s, backend pinned to %s", stack.Address, stack.BackendNode)

	// The path must serve before the ifindex is read, or the comparison passes against a link
	// about to be rebuilt; Lease continuity is what makes this adoption and not a rebuild.
	t.Run("holder-crash-adopts-the-interface", func(t *testing.T) {
		holder, node, iface := localHolderState(ctx, t, client, stack, leaseName)

		before, err := client.NodeIfaceIndex(ctx, stack.Namespace, holder, iface)
		if err != nil {
			t.Fatalf("read %s ifindex before the crash: %v", iface, err)
		}
		leaseBefore, err := client.GetLease(ctx, stack.Namespace, leaseName)
		if err != nil {
			t.Fatalf("read link lease before the crash: %v", err)
		}
		transitionsBefore := leaseTransitions(leaseBefore.Spec.LeaseTransitions)
		restartsBefore, err := client.PodRestartCount(ctx, stack.Namespace, holder)
		if err != nil {
			t.Fatalf("read holder restart count: %v", err)
		}

		killedAt := time.Now()
		if err := suite.KillContainerOnNode(ctx, node, stack.Namespace, holder); err != nil {
			t.Fatalf("sigkill the link container of %s on %s: %v", holder, node, err)
		}

		if err := retryUntil(ctx, haFailoverTimeout, func(ctx context.Context) error {
			restarts, err := client.PodRestartCount(ctx, stack.Namespace, holder)
			if err != nil {
				return err
			}
			if restarts <= restartsBefore {
				return fmt.Errorf("restart count still %d, want above %d", restarts, restartsBefore)
			}
			return nil
		}); err != nil {
			t.Fatalf("holder %s did not restart in place after the kill: %v", holder, err)
		}

		ready, err := client.WaitLinkPodReadyOnNode(ctx, stack.Namespace, stack.GatewayName, node, haFailoverTimeout)
		if err != nil {
			t.Fatalf("no ready link pod on %s after the crash: %v", node, err)
		}
		if ready != holder {
			t.Fatalf("link pod on %s is %q after the crash, want the restarted holder %q; the container must restart in place", node, ready, holder)
		}

		// The killed process cannot renew, so a renewal stamped after the kill proves the
		// restarted process is the one leading and has re-applied under its own lease.
		if err := retryUntil(ctx, haFailoverTimeout, func(ctx context.Context) error {
			lease, err := client.GetLease(ctx, stack.Namespace, leaseName)
			if err != nil {
				return err
			}
			var current string
			if lease.Spec.HolderIdentity != nil {
				current = *lease.Spec.HolderIdentity
			}
			var renewed time.Time
			if lease.Spec.RenewTime != nil {
				renewed = lease.Spec.RenewTime.Time
			}
			if current != holder || !renewed.After(killedAt) {
				return fmt.Errorf("lease holder = %q renewed at %s, want the restarted pod %q renewing after the kill at %s",
					current, renewed, holder, killedAt)
			}
			return nil
		}); err != nil {
			t.Errorf("the restarted pod did not renew the Lease as its holder within %s: %v", haFailoverTimeout, err)
		}
		assertActiveNode(ctx, t, client, stack, node, haFailoverTimeout)

		marker, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.TCPPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("tcp forward did not serve again after the link crash: %v", err)
		}
		assertBackendMarker(t, marker, stack.TCPBackendName)

		after, err := client.NodeIfaceIndex(ctx, stack.Namespace, holder, iface)
		if err != nil {
			t.Fatalf("read %s ifindex after the crash: %v", iface, err)
		}
		leaseAfter, err := client.GetLease(ctx, stack.Namespace, leaseName)
		if err != nil {
			t.Fatalf("read link lease after the crash: %v", err)
		}
		if transitionsAfter := leaseTransitions(leaseAfter.Spec.LeaseTransitions); transitionsAfter != transitionsBefore {
			t.Fatalf("link Lease transitions %d -> %d: leadership moved to the peer while %s restarted, so the restarted pod fenced its inherited interface and the adoption scenario was not exercised; the restart outran the peer's grace",
				transitionsBefore, transitionsAfter, holder)
		}
		if after != before {
			t.Errorf("%s ifindex changed %d -> %d across a crash; the restarted link must adopt the existing interface, not recreate it", iface, before, after)
		}
	})

	// The graceful counterpart: the SIGTERM teardown removes the interface, so the
	// replacement on the same node builds a fresh one instead of adopting it.
	t.Run("holder-delete-replaces-the-link", func(t *testing.T) {
		holder, node, iface := localHolderState(ctx, t, client, stack, leaseName)

		before, err := client.NodeIfaceIndex(ctx, stack.Namespace, holder, iface)
		if err != nil {
			t.Fatalf("read %s ifindex before the delete: %v", iface, err)
		}

		if err := client.DeletePod(ctx, stack.Namespace, holder); err != nil {
			t.Fatalf("delete holder %s: %v", holder, err)
		}

		replacement, err := client.WaitLinkPodReadyOnNode(ctx, stack.Namespace, stack.GatewayName, node, haFailoverTimeout)
		if err != nil {
			t.Fatalf("no ready link pod on %s after the delete: %v", node, err)
		}
		if replacement == holder {
			t.Fatalf("link pod on %s is still %q; the graceful delete must be replaced by a new pod", node, replacement)
		}
		// The peer on the empty worker can hold the Lease while the replacement starts,
		// and hands it back once the fully eligible node is ready again.
		if err := retryUntil(ctx, haFailoverTimeout, func(ctx context.Context) error {
			current, err := client.GetLeaseHolder(ctx, stack.Namespace, leaseName)
			if err != nil {
				return err
			}
			if current != replacement {
				return fmt.Errorf("lease holder = %q, want the replacement %q on %s", current, replacement, node)
			}
			return nil
		}); err != nil {
			t.Fatalf("the replacement on the backend's node did not take the Lease: %v", err)
		}

		var after int
		if err := retryUntil(ctx, haFailoverTimeout, func(ctx context.Context) error {
			index, err := client.NodeIfaceIndex(ctx, stack.Namespace, replacement, iface)
			if err != nil {
				return err
			}
			after = index
			return nil
		}); err != nil {
			t.Fatalf("replacement %s did not bring up %s: %v", replacement, iface, err)
		}
		if after == before {
			t.Errorf("%s ifindex is still %d after a graceful delete; the SIGTERM teardown must remove the interface and the replacement create a new one", iface, before)
		}
		assertActiveNode(ctx, t, client, stack, node, haFailoverTimeout)

		marker, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.TCPPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("tcp forward did not serve again after the holder was replaced: %v", err)
		}
		assertBackendMarker(t, marker, stack.TCPBackendName)
	})

	// A forward with no ready endpoint on the holder node must be dropped rather than reset,
	// leaving the holder's satisfied forwards serving.
	t.Run("no-local-endpoint-blackholes-and-recovers", func(t *testing.T) {
		// The Lease can still be settling from the previous subtest, so the baseline is
		// the backend's node rather than whatever a single status read catches.
		assertActiveNode(ctx, t, client, stack, stack.BackendNode, haFailoverTimeout)

		t.Cleanup(func() {
			if err := client.ScaleDeployment(context.Background(), stack.Namespace, stack.TCPBackendName, 1); err != nil {
				t.Logf("cleanup scale %s back to one replica: %v", stack.TCPBackendName, err)
			}
		})
		if err := client.ScaleDeployment(ctx, stack.Namespace, stack.TCPBackendName, 0); err != nil {
			t.Fatalf("scale %s to zero: %v", stack.TCPBackendName, err)
		}

		wantForward := fmt.Sprintf("tcp-%d", stack.TCPPublicPort)
		if err := client.WaitGatewayConditionMessage(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "False", link.FaultNoLocalEndpoint, wantForward, lifecycleConditionTimeout); err != nil {
			t.Fatalf("gateway did not report Ready=False/%s naming the forward whose endpoint went away: %v", link.FaultNoLocalEndpoint, err)
		}

		// A refusal would mean the packet reached a closed socket; the input drop must
		// make it time out instead.
		if err := waitPortDenied(ctx, stack, stack.TCPPublicPort, lifecycleConditionTimeout); err != nil {
			t.Errorf("tcp forward without a local endpoint: %v", err)
		}

		const payload = "gateway-e2e-local-udp-blackhole"
		if got, err := probeUDPThroughGateway(ctx, stack, payload); err != nil {
			t.Errorf("udp forward stopped serving while the TCP forward was unsatisfied: %v", err)
		} else if got != payload {
			t.Errorf("udp echo = %q, want %q", got, payload)
		}
		if marker, err := probeTCPThroughGatewayPort(ctx, stack, stack.CrossNSPublicPort); err != nil {
			t.Errorf("cross-namespace forward stopped serving while the TCP forward was unsatisfied: %v", err)
		} else {
			assertBackendMarker(t, marker, stack.CrossNSBackendName)
		}

		during, err := client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
		if err != nil {
			t.Fatalf("read gateway status while unsatisfied: %v", err)
		}
		if during.ActiveNode != stack.BackendNode {
			t.Errorf("status.link.activeNode moved to %q, want the backend's node %q; no peer scores higher, so the holder must keep the Lease", during.ActiveNode, stack.BackendNode)
		}

		if err := client.ScaleDeployment(ctx, stack.Namespace, stack.TCPBackendName, 1); err != nil {
			t.Fatalf("scale %s back to one replica: %v", stack.TCPBackendName, err)
		}
		if err := client.WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
			"Ready", "True", "", lifecycleReadyTimeout); err != nil {
			t.Fatalf("gateway did not return Ready=True after the backend came back: %v", err)
		}
		marker, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.TCPPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("tcp forward did not serve again after the backend came back: %v", err)
		}
		assertBackendMarker(t, marker, stack.TCPBackendName)
	})

	// daemonset-rolling-update asserts the state a roll leaves, not the transient during it:
	// one Lease holder, one interface owner, activeNode on the backend's worker.
	t.Run("daemonset-rolling-update", func(t *testing.T) {
		// The link DaemonSet and the Lease share the link component name.
		daemonSetName := leaseName
		selector := linkSelector(stack.GatewayName)
		podsBefore, err := client.PodNamesByLabel(ctx, stack.Namespace, selector)
		if err != nil {
			t.Fatalf("list link pods before the roll: %v", err)
		}
		if err := client.RestartDaemonSet(ctx, stack.Namespace, daemonSetName); err != nil {
			t.Fatalf("restart link daemonset: %v", err)
		}
		if err := client.WaitDaemonSetReady(ctx, stack.Namespace, daemonSetName, lifecycleReadyTimeout); err != nil {
			t.Fatalf("link daemonset did not converge after the roll: %v", err)
		}
		podsAfter, err := client.PodNamesByLabel(ctx, stack.Namespace, selector)
		if err != nil {
			t.Fatalf("list link pods after the roll: %v", err)
		}
		var survivors []string
		for _, pod := range podsAfter {
			if slices.Contains(podsBefore, pod) {
				survivors = append(survivors, pod)
			}
		}
		if len(survivors) > 0 {
			t.Fatalf("link pods %v survived the roll (before %v, after %v); a converged rolling update must replace every pod", survivors, podsBefore, podsAfter)
		}

		marker, err := probeTCPThroughGatewayPortUntil(ctx, stack, stack.TCPPublicPort, editRollTimeout)
		if err != nil {
			t.Fatalf("tcp forward did not serve again after the daemonset roll: %v", err)
		}
		assertBackendMarker(t, marker, stack.TCPBackendName)

		assertActiveNode(ctx, t, client, stack, stack.BackendNode, haFailoverTimeout)

		status, err := client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
		if err != nil {
			t.Fatalf("read gateway status after the roll: %v", err)
		}
		iface := link.NewSlotIdentity(status.LinkID, 0).Interface
		assertSingleIfaceOwner(ctx, t, client, stack.Namespace, selector, leaseName, iface, haFailoverTimeout)
	})
}

// leaseTransitions is a Lease's leadership transition count, an unset count reading 0:
// the API leaves it nil until leadership first moves.
func leaseTransitions(count *int32) int32 {
	if count == nil {
		return 0
	}
	return *count
}

// localHolderState returns the current Lease holder, its node and the id-derived
// interface name, the three facts every disruption assertion starts from.
func localHolderState(ctx context.Context, t *testing.T, client *hk8s.Client, stack *e2eharness.Stack, leaseName string) (holder, node, iface string) {
	t.Helper()
	holder, err := client.GetLeaseHolder(ctx, stack.Namespace, leaseName)
	if err != nil {
		t.Fatalf("read lease holder: %v", err)
	}
	if holder == "" {
		t.Fatal("link lease has no holder; no link pod programs the data plane")
	}
	node, err = client.PodNode(ctx, stack.Namespace, holder)
	if err != nil {
		t.Fatalf("read node of holder %s: %v", holder, err)
	}
	status, err := client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
	if err != nil {
		t.Fatalf("read gateway status: %v", err)
	}
	if status.LinkID < 1 {
		t.Fatalf("status.link.id = %d, want an allocated id; the interface name derives from it", status.LinkID)
	}
	return holder, node, link.NewSlotIdentity(status.LinkID, 0).Interface
}

// assertActiveNode fails unless status.link.activeNode settles on want within timeout.
func assertActiveNode(ctx context.Context, t *testing.T, client *hk8s.Client, stack *e2eharness.Stack, want string, timeout time.Duration) {
	t.Helper()
	if err := retryUntil(ctx, timeout, func(ctx context.Context) error {
		status, err := client.GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
		if err != nil {
			return err
		}
		if status.ActiveNode != want {
			return fmt.Errorf("status.link.activeNode = %q, want %q", status.ActiveNode, want)
		}
		return nil
	}); err != nil {
		t.Errorf("gateway did not report the expected active node: %v", err)
	}
}

// inClusterAddresses is the set a Local-mode /clientip answer must fall outside of: any of
// them would mean something between the external client and the backend rewrote the source.
type inClusterAddresses struct {
	// addresses are exact addresses: the VM's tunnel address, the link pod IPs and
	// every node address.
	addresses []string
	// podCIDRs are the per-node pod CIDRs, checked by containment because a pod IP the
	// list missed still proves a rewrite.
	podCIDRs []*net.IPNet
}

// readInClusterAddresses builds the excluded set from the live cluster, so it stays
// correct as pods reschedule and no assertion depends on a hardcoded cluster layout.
func readInClusterAddresses(ctx context.Context, t *testing.T, client *hk8s.Client, stack *e2eharness.Stack) inClusterAddresses {
	t.Helper()
	podIPs, err := client.LinkPodIPs(ctx, stack.Namespace, stack.GatewayName)
	if err != nil {
		t.Fatalf("read link pod IPs: %v", err)
	}
	nodeAddrs, rawCIDRs, err := client.NodeAddressesAndPodCIDRs(ctx)
	if err != nil {
		t.Fatalf("read node addresses and pod CIDRs: %v", err)
	}
	cidrs := make([]*net.IPNet, 0, len(rawCIDRs))
	for _, raw := range rawCIDRs {
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			t.Fatalf("parse node podCIDR %q: %v", raw, err)
		}
		cidrs = append(cidrs, cidr)
	}
	addresses := append([]string{wgGatewayAddress}, podIPs...)
	addresses = append(addresses, nodeAddrs...)
	return inClusterAddresses{addresses: addresses, podCIDRs: cidrs}
}

// assertExternalClientIP fails when the observed /clientip address is any in-cluster
// or tunnel address, which is what a masquerade anywhere on the path would produce.
func assertExternalClientIP(t *testing.T, got string, excluded inClusterAddresses) {
	t.Helper()
	if slices.Contains(excluded.addresses, got) {
		t.Errorf("Local-mode /clientip = %q, want an address outside the in-cluster set %v; Local must preserve the external client's source end to end",
			got, excluded.addresses)
		return
	}
	ip := net.ParseIP(got)
	if ip == nil {
		t.Errorf("Local-mode /clientip = %q, want a parseable IP address", got)
		return
	}
	for _, cidr := range excluded.podCIDRs {
		if cidr.Contains(ip) {
			t.Errorf("Local-mode /clientip = %q, want an address outside the pod CIDR %s; a pod-sourced address means something rewrote the client's",
				got, cidr)
			return
		}
	}
}

// otherWorker returns the worker that is not current, the re-pin target the handoff
// assertion needs.
func otherWorker(t *testing.T, workers []string, current string) string {
	t.Helper()
	for _, w := range workers {
		if w != current {
			return w
		}
	}
	t.Fatalf("no worker other than %q in %v; the handoff assertion needs two", current, workers)
	return ""
}

func TestGatewaySingleInstanceRetainedReasons(t *testing.T) {
	t.Parallel()

	suite := getSuite(t)
	ctx := context.Background()
	stack, err := suite.Start(ctx, t)
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}
	var serviceAccount string
	if err := retryUntil(ctx, 2*time.Minute, func(ctx context.Context) error {
		email, err := suite.GatewayServiceAccountEmail(ctx, stack.Namespace, stack.GatewayName)
		if err != nil {
			return err
		}
		serviceAccount = email
		if serviceAccount == "" {
			return errors.New("service account email is empty")
		}
		return nil
	}); err != nil {
		t.Fatalf("wait for gateway service account email (last value %q): %v", serviceAccount, err)
	}
	network, err := suite.GatewaySharedNetworkName(ctx, stack.Namespace, stack.GatewayName)
	if err != nil {
		t.Fatalf("read gateway shared network name: %v", err)
	}
	if network == "" {
		t.Fatal("gateway shared network name is empty")
	}
	denyGatewayWireGuard(ctx, t, suite, stack.NamePrefix, network, serviceAccount)
	holder, err := suite.Client().GetLeaseHolder(ctx, stack.Namespace, linkLeaseName(stack.GatewayName))
	if err != nil {
		t.Fatalf("read lease holder: %v", err)
	}
	if holder == "" {
		t.Fatal("link lease has no holder")
	}
	if err := suite.Client().DeletePod(ctx, stack.Namespace, holder); err != nil {
		t.Fatalf("delete lease holder %s: %v", holder, err)
	}
	t.Logf("deleted holder link pod %s", holder)
	if err := suite.Client().WaitGatewayCondition(ctx, stack.Namespace, stack.GatewayName,
		"Ready", "False", "Provisioning", 6*time.Minute); err != nil {
		t.Fatalf("wait for retained single-instance provisioning condition: %v", err)
	}
	status, err := suite.Client().GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
	if err != nil {
		t.Fatalf("read gateway status: %v", err)
	}
	if !slices.Equal(status.GCPMembers, []hk8s.GatewayGCPMember{}) {
		t.Errorf("single-instance status.gcp.members = %v, want exactly %v", status.GCPMembers, []hk8s.GatewayGCPMember{})
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	hold := time.NewTimer(90 * time.Second)
	defer hold.Stop()
	for {
		select {
		case <-hold.C:
			return
		case <-ticker.C:
			conditionStatus, reason, message, found, err := suite.Client().GetGatewayCondition(ctx, stack.Namespace, stack.GatewayName, "Ready")
			if err != nil {
				t.Fatalf("read retained single-instance Ready condition: %v", err)
			}
			status, err := suite.Client().GetGatewayStatus(ctx, stack.Namespace, stack.GatewayName)
			if err != nil {
				t.Fatalf("read retained single-instance gateway status: %v", err)
			}
			if !found || conditionStatus != "False" || reason != "Provisioning" || !slices.Equal(status.GCPMembers, []hk8s.GatewayGCPMember{}) {
				t.Fatalf("retained single-instance Ready condition: status=%q reason=%q message=%q found=%t members=%v, want status=%q reason=%q members=%v",
					conditionStatus, reason, message, found, status.GCPMembers, "False", "Provisioning", []hk8s.GatewayGCPMember{})
			}
		}
	}
}

const (
	// Run 20260918-221808 hit not-ready on the shared VPC about four minutes after its
	// re-creation; an auto-mode VPC's implicit-subnet tail runs minutes.
	firewallRuleNotReadyTimeout  = 10 * time.Minute
	firewallRuleNotReadyInterval = 5 * time.Second
)

func denyGatewayWireGuard(ctx context.Context, t *testing.T, suite *e2eharness.Suite, prefix, network, serviceAccount string) {
	t.Helper()
	env := suite.Env()
	rules := []struct {
		name string
		args []string
	}{
		{
			name: prefix + "-deny-wg-in",
			args: []string{
				"compute", "firewall-rules", "create", prefix + "-deny-wg-in",
				"--project", env.ProjectID, "--network", network, "--direction", "INGRESS",
				"--action", "DENY", "--rules", "udp", "--priority", "100",
				"--source-ranges", "0.0.0.0/0", "--target-service-accounts", serviceAccount, "--quiet",
			},
		},
		{
			name: prefix + "-deny-wg-out",
			args: []string{
				"compute", "firewall-rules", "create", prefix + "-deny-wg-out",
				"--project", env.ProjectID, "--network", network, "--direction", "EGRESS",
				"--action", "DENY", "--rules", "udp", "--priority", "100",
				"--destination-ranges", "0.0.0.0/0", "--target-service-accounts", serviceAccount, "--quiet",
			},
		},
	}
	for _, rule := range rules {
		createCtx, cancel := context.WithTimeout(ctx, firewallRuleNotReadyTimeout)
		err := e2eharness.RetryNotReady(createCtx, firewallRuleNotReadyInterval, t.Logf, func() error {
			_, err := shared.RunCmdStdout(createCtx,
				[]string{"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + env.CredsFile}, "gcloud", rule.args...)
			return err
		})
		cancel()
		if err != nil {
			t.Fatalf("create firewall rule %s: %v", rule.name, err)
		}
		t.Logf("created firewall rule %s", rule.name)
		ruleName := rule.name
		t.Cleanup(func() {
			deleteCtx, cancel := context.WithTimeout(context.Background(), firewallRuleNotReadyTimeout)
			defer cancel()
			err := e2eharness.RetryNotReady(deleteCtx, firewallRuleNotReadyInterval, t.Logf, func() error {
				_, err := shared.RunCmdStdout(deleteCtx,
					[]string{"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + env.CredsFile},
					"gcloud", "compute", "firewall-rules", "delete", ruleName,
					"--project", env.ProjectID, "--quiet")
				return err
			})
			if err != nil {
				t.Errorf("delete firewall rule %s: %v", ruleName, err)
			}
		})
	}
}
