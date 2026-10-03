package e2e_test

import (
	"context"
	"testing"
	"time"

	e2eharness "github.com/tripod-networks/wireguard-gateway-operator/test/harness/e2e"
)

// TestGCPHA verifies a multi-member GCP gateway repairs, rolls out, and retains its identity.
func TestGCPHA(t *testing.T) {
	t.Run("serving-repair-and-outage-on-one-fleet", func(t *testing.T) {
		t.Parallel()

		suite := getSuite(t)
		ctx := context.Background()
		stack, err := suite.Start(ctx, t,
			e2eharness.WithGCPReplicas(gcpHAReplicas),
			e2eharness.WithGCPZones([]string{suite.Env().Zone}),
			e2eharness.WithLoadBalancer("NONE"),
		)
		if err != nil {
			t.Fatalf("start load-balanced stack: %v", err)
		}

		t.Run("fleet-serves-from-every-member", func(t *testing.T) {
			assertFleet(ctx, t, suite, stack, gcpHAReplicas)
			waitForFleetHealthy(ctx, t, suite, stack, gcpHAReplicas, migInitialDelay)
			waitForFleetServing(ctx, t, suite, stack, gcpHAReplicas)
			assertMemberIngress(ctx, t, suite, stack)
		})
		t.Run("gcp-accepts-the-rendered-fields-and-probes-arrive", func(t *testing.T) {
			for _, affinity := range []string{"NONE", "CLIENT_IP_PORT_PROTO", "CLIENT_IP_PROTO", "CLIENT_IP"} {
				setSessionAffinity(ctx, t, suite, stack, affinity)
				waitForSessionAffinity(ctx, t, suite, stack, affinity)
			}
			mig := migName(ctx, t, suite, stack)
			assertMIGFieldMatrix(ctx, t, suite, mig)
			assertHealthCheckFieldMatrix(ctx, t, suite, stack, mig)
			assertProbeArrival(ctx, t, suite, stack)
		})
		t.Run("deleted-member-is-repaired-and-serves", func(t *testing.T) {
			before := bootDiskIDs(ctx, t, suite, stack)
			instances := gatewayInstances(ctx, t, suite, stack)
			runGcloud(ctx, t, suite, "compute", "instances", "delete", instances[0], "--zone", suite.Env().Zone, "--quiet")
			waitForReplacementServing(ctx, t, suite, stack, gcpHAReplicas, before, 1, replacementTimeout)
		})
		t.Run("tunnel-outage-recreates-members-and-recovers", func(t *testing.T) {
			mig := migName(ctx, t, suite, stack)
			waitForFleetHealthy(ctx, t, suite, stack, gcpHAReplicas, rolloutRecoveryTimeout)
			before := snapshotFleet(ctx, t, suite, stack, mig)
			if len(before) != int(gcpHAReplicas) {
				t.Fatalf("members before the outage = %+v, want exactly %d", before, gcpHAReplicas)
			}
			natIPs := make([]string, 0, len(before))
			for _, member := range before {
				natIPs = append(natIPs, member.NATIP)
			}
			outage := dropTunnelTraffic(ctx, t, suite, natIPs)
			waitForRepairedFleet(ctx, t, suite, stack, mig, before, 2*migInitialDelay)
			if err := outage.lift(ctx); err != nil {
				t.Fatalf("lift the outage: %v", err)
			}
			waitForFleetHealthy(ctx, t, suite, stack, gcpHAReplicas, migInitialDelay)
			assertSameFleetIdentity(t, fleetMembers(ctx, t, suite, stack, mig), before)
			waitForFleetServing(ctx, t, suite, stack, gcpHAReplicas)
		})
	})

	t.Run("identity-survives-on-its-own-fleet", func(t *testing.T) {
		t.Parallel()

		suite := getSuite(t)
		ctx := context.Background()
		stack, err := suite.Start(ctx, t,
			e2eharness.WithGCPReplicas(gcpHAReplicas),
			e2eharness.WithGCPZones([]string{suite.Env().Zone}),
			e2eharness.WithLoadBalancer("NONE"),
		)
		if err != nil {
			t.Fatalf("start load-balanced stack: %v", err)
		}

		t.Run("names-and-addresses-survive-repair-rollout-reboot", func(t *testing.T) {
			waitForFleetHealthy(ctx, t, suite, stack, gcpHAReplicas, migInitialDelay)
			waitForFleetServing(ctx, t, suite, stack, gcpHAReplicas)
			before := instanceAddresses(ctx, t, suite, stack)
			bootDisks := bootDiskIDs(ctx, t, suite, stack)
			instances := gatewayInstances(ctx, t, suite, stack)
			runGcloud(ctx, t, suite, "compute", "instances", "delete", instances[0], "--zone", suite.Env().Zone, "--quiet")
			waitForReplacementServing(ctx, t, suite, stack, gcpHAReplicas, bootDisks, 1, replacementTimeout)
			assertSameInstanceAddresses(ctx, t, suite, stack, before)

			bootDisks = bootDiskIDs(ctx, t, suite, stack)
			setDiskSize(ctx, t, suite, stack, 22)
			waitForReplacementServing(ctx, t, suite, stack, gcpHAReplicas, bootDisks, len(bootDisks), rolloutTimeout)
			assertSameInstanceAddresses(ctx, t, suite, stack, before)

			instances = gatewayInstances(ctx, t, suite, stack)
			rebooted := instances[0]
			readsBefore := bundleReads(ctx, t, suite, rebooted)
			if len(readsBefore) == 0 {
				t.Fatalf("instance %s has no keyfetch bundle read on its serial console before the reset", rebooted)
			}
			runGcloud(ctx, t, suite, "compute", "instances", "reset", rebooted, "--zone", suite.Env().Zone, "--quiet")
			waitForRunning(ctx, t, suite, rebooted)
			waitForBundleReread(ctx, t, suite, rebooted, readsBefore)
			assertSameInstanceAddresses(ctx, t, suite, stack, before)
			waitForFleetServing(ctx, t, suite, stack, gcpHAReplicas)

			setGCPReplicas(ctx, t, suite, stack, 1)
			waitForFleetServing(ctx, t, suite, stack, 1)
			assertPromotedAddresses(ctx, t, suite, stack)
		})
	})

	t.Run("template-rollout-on-its-own-fleets", func(t *testing.T) {
		t.Parallel()

		suite := getSuite(t)
		ctx := context.Background()
		stack, err := suite.Start(ctx, t,
			e2eharness.WithGCPReplicas(gcpHAReplicas),
			e2eharness.WithGCPZones([]string{suite.Env().Zone}),
			e2eharness.WithLoadBalancer("NONE"),
		)
		if err != nil {
			t.Fatalf("start load-balanced stack: %v", err)
		}

		t.Run("template-change-rolls-one-member-per-zone", func(t *testing.T) {
			waitForFleetHealthy(ctx, t, suite, stack, gcpHAReplicas, migInitialDelay)
			waitForFleetServing(ctx, t, suite, stack, gcpHAReplicas)
			mig := migName(ctx, t, suite, stack)
			before := snapshotFleet(ctx, t, suite, stack, mig)
			oldTemplate := assertSingleTemplate(ctx, t, suite, stack, mig, "before the rollout")
			oldRevision := templateRevision(ctx, t, suite, stack)
			setDiskSize(ctx, t, suite, stack, 21)
			newTemplate := waitForNewTemplateName(ctx, t, suite, stack, oldRevision)
			assertRollingReplacement(ctx, t, suite, stack, mig, before, oldTemplate, newTemplate)

			single, err := suite.Start(ctx, t,
				e2eharness.WithGCPReplicas(1),
				e2eharness.WithGCPZones([]string{suite.Env().Zone}),
				e2eharness.WithLoadBalancer("NONE"),
			)
			if err != nil {
				t.Fatalf("start single-member rollout stack: %v", err)
			}
			singleBefore := bootDiskIDs(ctx, t, suite, single)
			setDiskSize(ctx, t, suite, single, 21)
			waitForBootCycleOutage(ctx, t, suite, single, singleBefore)
			waitForFleetHealthy(ctx, t, suite, single, 1, migInitialDelay)
			waitForFleetServing(ctx, t, suite, single, 1)
		})
	})
}

const gcpHAReplicas int32 = 2

const (
	// migInitialDelay mirrors the composition's autohealing initialDelaySec (900 s).
	migInitialDelay        = 15 * time.Minute
	rolloutRecoveryTimeout = 20 * time.Minute
	replacementTimeout     = migInitialDelay
	// A RECREATE rollout with maxUnavailable 1 replaces the two members one after the other.
	rolloutTimeout = 3 * migInitialDelay
)

// gcpHAZones is how many zones the GCP HA test MIG spans, which the composition uses as
// the update policy's maxUnavailable: a rollout may take that many members down at once.
const gcpHAZones = 1

const rolloutPoll = 15 * time.Second
