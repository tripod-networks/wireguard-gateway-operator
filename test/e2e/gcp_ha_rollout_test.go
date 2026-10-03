package e2e_test

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	e2eharness "github.com/tripod-networks/wireguard-gateway-operator/test/harness/e2e"
)

// instanceTemplates returns the gateway's instance templates, sorted. Their names are
// composed external names, so the prefix filter names them exactly.
func instanceTemplates(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) []string {
	t.Helper()
	templates := strings.Fields(runGcloud(ctx, t, suite, "compute", "instance-templates", "list",
		"--filter", "name~^"+stack.NamePrefix, "--format", "value(name)"))
	slices.Sort(templates)
	return templates
}

// currentTemplate is the template the MIG's version target names: the destination of a
// rollout and the one template that survives its completion.
func currentTemplate(ctx context.Context, t *testing.T, suite *e2eharness.Suite, mig string) string {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "instance-groups", "managed", "describe", mig,
		"--region", suite.Env().Region, "--format", "value(versions[].instanceTemplate)")
	targets := strings.Fields(strings.ReplaceAll(out, ";", " "))
	if len(targets) != 1 {
		t.Fatalf("mig %s version targets = %v, want exactly one template", mig, targets)
	}
	return path.Base(targets[0])
}

// templateRevision is the revision the operator writes into the composite's spec.
func templateRevision(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) string {
	t.Helper()
	revision, err := suite.Client().GetXGatewayGCPTemplateRevision(ctx, stack.Namespace, stack.GatewayName)
	if err != nil {
		t.Fatalf("read template revision of gateway %s/%s: %v", stack.Namespace, stack.GatewayName, err)
	}
	if revision == "" {
		t.Fatalf("gateway %s/%s has no template revision in its composite", stack.Namespace, stack.GatewayName)
	}
	return revision
}

// waitForNewTemplateName discovers the provider-generated template name by its revision prefix.
func waitForNewTemplateName(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack,
	previous string) string {
	t.Helper()
	transitions := newMemberTransitions(t, "waitForNewTemplateName "+stack.GatewayName)
	revision, err := suite.Client().WaitXGatewayGCPTemplateRevisionChanges(ctx, stack.Namespace, stack.GatewayName,
		previous, rolloutTimeout)
	if err != nil {
		t.Fatalf("wait for a template revision past %s of gateway %s/%s: %v",
			previous, stack.Namespace, stack.GatewayName, err)
	}
	templatePrefix := stack.GatewayName + "-" + revision
	deadline := time.Now().Add(rolloutTimeout)
	for time.Now().Before(deadline) {
		var matches []string
		for _, template := range instanceTemplates(ctx, t, suite, stack) {
			if strings.HasPrefix(template, templatePrefix) {
				matches = append(matches, template)
			}
		}
		transitions.observeStates(map[string]string{
			"template revision": revision,
			"templates":         strings.Join(matches, ","),
		})
		if len(matches) == 1 {
			transitions.done()
			return matches[0]
		}
		if len(matches) > 1 {
			t.Fatalf("templates for revision %s = %v, want exactly one", revision, matches)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for template %s: %v", templatePrefix, ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("template %s did not appear within %s", templatePrefix, rolloutTimeout)
	return ""
}

// assertSingleTemplate fails unless the gateway's only instance template is the MIG's
// current version target, which it returns.
func assertSingleTemplate(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack,
	mig string, when string) string {
	t.Helper()
	current := currentTemplate(ctx, t, suite, mig)
	assertTemplateSet(t, instanceTemplates(ctx, t, suite, stack), []string{current}, when)
	return current
}

func assertTemplateSet(t *testing.T, got []string, want []string, when string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("instance templates %s = %v, want exactly %v", when, got, want)
	}
}

// versionTargetReached reports the MIG's own rollup of whether every member runs the
// current version, which is what gates retiring the previous template.
func versionTargetReached(ctx context.Context, t *testing.T, suite *e2eharness.Suite, mig string) bool {
	t.Helper()
	got := strings.TrimSpace(runGcloud(ctx, t, suite, "compute", "instance-groups", "managed", "describe", mig,
		"--region", suite.Env().Region, "--format", "value(status.versionTarget.isReached)"))
	return strings.EqualFold(got, "True")
}

// assertRollingReplacement verifies rolling replacement preserves expected fleet state.
func assertRollingReplacement(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack,
	mig string, before []e2eharness.MIGMember, oldTemplate, newTemplate string) {
	t.Helper()
	if len(before) != int(gcpHAReplicas) {
		t.Fatalf("members before the rollout = %+v, want exactly %d", before, gcpHAReplicas)
	}
	minServing := len(before)
	allowed := e2eharness.RolloutStates(oldTemplate, newTemplate)
	reachedStep := 0
	var templates []string
	round := func(members []e2eharness.MIGMember) bool {
		assertProbe(ctx, t, stack)
		serving := servingMemberNames(members)
		minServing = min(minServing, len(serving))
		// The version target is read before the listing and the listing before the rollup, so
		// a state is only ever judged against a target at least as old and a rollup at least as new.
		observed := e2eharness.RolloutState{Target: currentTemplate(ctx, t, suite, mig)}
		templates = instanceTemplates(ctx, t, suite, stack)
		observed.Templates = templates
		observed.Reached = versionTargetReached(ctx, t, suite, mig)
		step := slices.IndexFunc(allowed, func(state e2eharness.RolloutState) bool { return observed.Matches(state, oldTemplate) }) + 1
		if step == 0 {
			t.Fatalf("rollout state %s, want one of %s", observed, e2eharness.RolloutStateList(allowed))
		}
		if step < reachedStep {
			t.Fatalf("rollout state went back to %s from %s", observed, allowed[reachedStep-1])
		}
		reachedStep = step
		return step == len(allowed) && slices.Equal(memberNames(members), serving)
	}
	waitForReplacedFleet(ctx, t, suite, stack, mig, before, round, rolloutTimeout)
	assertTemplateSet(t, templates, []string{newTemplate}, "after the rollout")
	if want := int(gcpHAReplicas) - gcpHAZones; minServing < want {
		t.Errorf("serving members fell to %d during the rollout, want never below %d", minServing, want)
	}
}

func setDiskSize(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, size int64) {
	t.Helper()
	if err := suite.Client().UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
		gcp, _ := spec["gcp"].(map[string]any)
		if gcp == nil {
			return fmt.Errorf("Gateway spec has no gcp block")
		}
		gcp["diskSizeGB"] = size
		return nil
	}); err != nil {
		t.Fatalf("set disk size: %v", err)
	}
}

func setGCPReplicas(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, replicas int64) {
	t.Helper()
	if err := suite.Client().UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
		gcp, _ := spec["gcp"].(map[string]any)
		if gcp == nil {
			return fmt.Errorf("Gateway spec has no gcp block")
		}
		gcp["replicas"] = replicas
		return nil
	}); err != nil {
		t.Fatalf("set GCP replicas: %v", err)
	}
}

func setSessionAffinity(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, affinity string) {
	t.Helper()
	if err := suite.Client().UpdateGateway(ctx, stack.Namespace, stack.GatewayName, func(spec map[string]any) error {
		gcp, _ := spec["gcp"].(map[string]any)
		if gcp == nil {
			return fmt.Errorf("Gateway spec has no gcp block")
		}
		loadBalancer, _ := gcp["loadBalancer"].(map[string]any)
		if loadBalancer == nil {
			return fmt.Errorf("Gateway spec has no gcp.loadBalancer block")
		}
		loadBalancer["sessionAffinity"] = affinity
		return nil
	}); err != nil {
		t.Fatalf("set session affinity: %v", err)
	}
}

func waitForSessionAffinity(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, affinity string) {
	t.Helper()
	transitions := newMemberTransitions(t, "waitForSessionAffinity "+stack.GatewayName)
	deadline := time.Now().Add(migInitialDelay)
	for time.Now().Before(deadline) {
		backend := strings.TrimSpace(runGcloud(ctx, t, suite, "compute", "backend-services", "list", "--filter", "name~^"+stack.NamePrefix, "--format", "value(sessionAffinity)"))
		transitions.observeState("session affinity", backend)
		if backend == affinity {
			transitions.done()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for session affinity %q: %v", affinity, ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("backend service did not accept session affinity %q", affinity)
}

func assertMIGFieldMatrix(ctx context.Context, t *testing.T, suite *e2eharness.Suite, mig string) {
	t.Helper()
	got := strings.Fields(runGcloud(ctx, t, suite, "compute", "instance-groups", "managed", "describe", mig, "--region", suite.Env().Region, "--format", "value(updatePolicy.type,updatePolicy.replacementMethod,updatePolicy.maxSurge.fixed,updatePolicy.maxUnavailable.fixed,updatePolicy.instanceRedistributionType,statefulPolicy.preservedState.externalIPs.nic0.autoDelete)"))
	want := []string{"PROACTIVE", "RECREATE", "0", "1", "NONE", "ON_PERMANENT_INSTANCE_DELETION"}
	if !slices.Equal(got, want) {
		t.Errorf("MIG field matrix = %v, want %v", got, want)
	}
}

func assertHealthCheckFieldMatrix(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, mig string) {
	t.Helper()
	got := strings.Fields(runGcloud(ctx, t, suite, "compute", "health-checks", "list", "--filter", "name~^"+stack.NamePrefix, "--format", "value(name,checkIntervalSec,timeoutSec,healthyThreshold,unhealthyThreshold)"))
	want := []string{stack.NamePrefix + "-health-check-lb", "5", "5", "2", "2", stack.NamePrefix + "-health-check-mig", "30", "10", "2", "10"}
	if !slices.Equal(got, want) {
		t.Errorf("health check field matrix = %v, want %v", got, want)
	}
	initialDelay := strings.TrimSpace(runGcloud(ctx, t, suite, "compute", "instance-groups", "managed", "describe", mig, "--region", suite.Env().Region, "--format", "value(autoHealingPolicies[0].initialDelaySec)"))
	if initialDelay != "900" {
		t.Errorf("MIG autohealing initial delay = %q, want %q", initialDelay, "900")
	}
}

// bundleReads returns the slot each keyfetch bundle read on the instance's serial console
// reported, oldest first. A reboot appends one more.
func bundleReads(ctx context.Context, t *testing.T, suite *e2eharness.Suite, instance string) []string {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "instances", "get-serial-port-output", instance,
		"--zone", suite.Env().Zone, "--port", "1")
	var slots []string
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.Contains(line, bundleReadMarker) {
			continue
		}
		for field := range strings.FieldsSeq(line) {
			if slot, found := strings.CutPrefix(field, "slot="); found {
				slots = append(slots, slot)
			}
		}
	}
	return slots
}

// bundleReadMarker is what keyfetch.sh logs once it has the member's bundle.
const bundleReadMarker = "gateway-keyfetch: bundle obtained on attempt="

// waitForBundleReread proves the rebooted guest re-read its bundle: the serial console
// gains a keyfetch read, and it reports the same slot as the read before the reboot.
func waitForBundleReread(ctx context.Context, t *testing.T, suite *e2eharness.Suite, instance string, before []string) {
	t.Helper()
	deadline := time.Now().Add(bundleRereadTimeout)
	for time.Now().Before(deadline) {
		got := bundleReads(ctx, t, suite, instance)
		if len(got) > len(before) {
			if newest, previous := got[len(got)-1], before[len(before)-1]; newest != previous {
				t.Errorf("instance %s re-read bundle slot %q after the reset, want the same slot %q", instance, newest, previous)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for instance %s to re-read its bundle: %v", instance, ctx.Err())
		case <-time.After(bundleRereadPoll):
		}
	}
	t.Fatalf("instance %s logged no bundle read after the reset within %s", instance, bundleRereadTimeout)
}
