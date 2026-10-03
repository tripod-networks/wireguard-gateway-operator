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
	"github.com/tripod-networks/wireguard-gateway-operator/test/harness/shared"
)

func runGcloud(ctx context.Context, t *testing.T, suite *e2eharness.Suite, args ...string) string {
	t.Helper()
	env := suite.Env()
	out, err := shared.RunCmdStdout(ctx, []string{"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + env.CredsFile}, "gcloud", append(args, "--project", env.ProjectID)...)
	if err != nil {
		t.Fatalf("gcloud %s: %v", strings.Join(args, " "), err)
	}
	return out
}

func gatewayInstances(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) []string {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "instances", "list", "--filter", "name~^"+stack.NamePrefix, "--format", "value(name)")
	instances := strings.Fields(out)
	slices.Sort(instances)
	return instances
}

func bootDiskIDs(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) map[string]string {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "disks", "list", "--filter", "name~^"+stack.NamePrefix, "--format", "value(name,id)")
	disks := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			t.Fatalf("boot disk row = %q, want a name and an id", line)
		}
		disks[fields[0]] = fields[1]
	}
	return disks
}

// migName returns the provider-generated MIG name the composite publishes. The composition
// sets no external name on the MIG, so the prefix does not name it.
func migName(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) string {
	t.Helper()
	name, err := suite.Client().WaitXGatewayGCPMIGName(ctx, stack.Namespace, stack.GatewayName, observedNameTimeout)
	if err != nil {
		t.Fatalf("read observed mig name of gateway %s/%s: %v", stack.Namespace, stack.GatewayName, err)
	}
	return name
}

func assertFleet(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, want int32) {
	t.Helper()
	instances := gatewayInstances(ctx, t, suite, stack)
	if len(instances) != int(want) {
		t.Fatalf("fleet instances = %v, want exactly %d members", instances, want)
	}
}

func waitForReplacementServing(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, want int32, previous map[string]string, minReplaced int, timeout time.Duration) {
	t.Helper()
	mig := migName(ctx, t, suite, stack)
	transitions := newMemberTransitions(t, "waitForReplacementServing "+stack.GatewayName)
	deadline := time.Now().Add(timeout)
	var members []e2eharness.MIGMember
	for time.Now().Before(deadline) {
		hostname, err := probeGateway(ctx, stack)
		if err != nil {
			t.Fatalf("probe load balancer: %v", err)
		}
		members = fleetMembers(ctx, t, suite, stack, mig)
		states := make(map[string]string, len(members)+1)
		states["response"] = strings.TrimSpace(hostname)
		for _, member := range members {
			states["member/"+member.Name] = fmt.Sprintf("id=%s serving=%t health=%s address=%s", memberID(member.BootDiskID), member.Serving, member.Health, member.NATIP)
		}
		transitions.observeStates(states)
		if e2eharness.ReplacementServing(members, previous, want, minReplaced) {
			transitions.done()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for serving fleet replacement: %v", ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("serving fleet did not reach exactly %d members with %d replacements within %s: previous disks %v, members %+v", want, minReplaced, timeout, previous, members)
}

func waitForFleetServing(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, want int32) {
	t.Helper()
	transitions := newMemberTransitions(t, "waitForFleetServing "+stack.GatewayName)
	deadline := time.Now().Add(migInitialDelay)
	for time.Now().Before(deadline) {
		instances := gatewayInstances(ctx, t, suite, stack)
		state := "not serving: members=" + strings.Join(instances, ",")
		if len(instances) == int(want) {
			hostname, err := probeGateway(ctx, stack)
			if err == nil {
				state = strings.TrimSpace(hostname)
				transitions.observeState("responding members", state)
				transitions.done()
				return
			}
			state = "not serving: " + err.Error()
		}
		transitions.observeState("responding members", state)
		select {
		case <-ctx.Done():
			t.Fatalf("wait for serving fleet: %v", ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("fleet did not serve with exactly %d members", want)
}

func waitForBootCycleOutage(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, previous map[string]string) {
	t.Helper()
	transitions := newMemberTransitions(t, "waitForBootCycleOutage "+stack.GatewayName)
	deadline := time.Now().Add(migInitialDelay)
	var disks map[string]string
	for time.Now().Before(deadline) {
		disks = bootDiskIDs(ctx, t, suite, stack)
		members := make([]e2eharness.MIGMember, 0, len(disks))
		for name, id := range disks {
			members = append(members, e2eharness.MIGMember{Name: name, BootDiskID: id})
		}
		transitions.observe(members)
		replaced := false
		for name, id := range previous {
			current, found := disks[name]
			if !found {
				replaced = false
				break
			}
			if current != id {
				replaced = true
			}
		}
		if replaced {
			if _, err := probeGateway(ctx, stack); err != nil {
				transitions.done()
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for boot-cycle outage: %v", ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("single-member rollout did not observe a boot-cycle outage: previous disks %v, current disks %v", previous, disks)
}

type memberTransitions struct {
	t     testing.TB
	label string
	start time.Time
	last  map[string]string
}

func newMemberTransitions(t testing.TB, label string) *memberTransitions {
	t.Helper()
	return &memberTransitions{t: t, label: label, start: time.Now(), last: map[string]string{}}
}

func (m *memberTransitions) observe(members []e2eharness.MIGMember) {
	m.t.Helper()
	current := make(map[string]string, len(members))
	for _, member := range members {
		state := fmt.Sprintf("serving=%t health=%s", member.Serving, member.Health)
		if id := memberID(member.BootDiskID); id != "" {
			state = "id=" + id + " " + state
		}
		if member.NATIP != "" {
			state += " address=" + member.NATIP
		}
		current[member.Name] = state
	}
	m.observeStates(current)
}

func (m *memberTransitions) observeState(name, state string) {
	m.t.Helper()
	m.observeStates(map[string]string{name: state})
}

func (m *memberTransitions) observeStates(current map[string]string) {
	names := make([]string, 0, len(m.last)+len(current))
	seen := make(map[string]struct{}, len(m.last)+len(current))
	for name := range m.last {
		seen[name] = struct{}{}
		names = append(names, name)
	}
	for name := range current {
		if _, found := seen[name]; !found {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	elapsed := time.Since(m.start).Round(time.Second)
	for _, name := range names {
		previous, before := m.last[name]
		state, now := current[name]
		if !now {
			m.t.Logf("%s +%s: %s: %s -> (gone)", m.label, elapsed, name, previous)
			continue
		}
		if !before {
			m.t.Logf("%s +%s: %s: (new) -> %s", m.label, elapsed, name, state)
			continue
		}
		if previous != state {
			m.t.Logf("%s +%s: %s: %s -> %s", m.label, elapsed, name, previous, state)
		}
	}
	m.last = current
}

func (m *memberTransitions) done() {
	m.t.Helper()
	m.t.Logf("%s: done after %s", m.label, time.Since(m.start).Round(time.Second))
}

func memberID(id string) string {
	if len(id) > 4 {
		return id[len(id)-4:]
	}
	return id
}

// migMembers reads the MIG's managed instances. It addresses the MIG by its observed name,
// never by the stack prefix.
func migMembers(ctx context.Context, t *testing.T, suite *e2eharness.Suite, mig string) []e2eharness.MIGMember {
	t.Helper()
	out := runGcloud(ctx, t, suite, "compute", "instance-groups", "managed", "list-instances", mig,
		"--region", suite.Env().Region, "--format", "value(name,instanceStatus,currentAction,instanceHealth[0].detailedHealthState)")
	var members []e2eharness.MIGMember
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("managed instance row = %q, want an instance, a status, a current action and health", line)
		}
		members = append(members, e2eharness.MIGMember{
			Name:    path.Base(fields[0]),
			Health:  fields[3],
			Serving: fields[1] == "RUNNING" && fields[2] == "NONE",
		})
	}
	return members
}

// waitForFleetHealthy waits until all members are running, idle, and HEALTHY on the MIG check.
// This is also when each member's autohealing initial delay has ended.
func waitForFleetHealthy(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack,
	want int32, timeout time.Duration) {
	t.Helper()
	mig := migName(ctx, t, suite, stack)
	transitions := newMemberTransitions(t, "waitForFleetHealthy "+stack.GatewayName)
	deadline := time.Now().Add(timeout)
	var members []e2eharness.MIGMember
	for time.Now().Before(deadline) {
		members = migMembers(ctx, t, suite, mig)
		transitions.observe(members)
		healthy := 0
		for _, member := range members {
			if member.Serving && member.Health == "HEALTHY" {
				healthy++
			}
		}
		if len(members) == int(want) && healthy == int(want) {
			transitions.done()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for a healthy fleet: %v", ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("fleet %+v did not become healthy within %s", members, timeout)
}

func memberNames(members []e2eharness.MIGMember) []string {
	names := make([]string, 0, len(members))
	for _, member := range members {
		names = append(names, member.Name)
	}
	slices.Sort(names)
	return names
}

func servingMemberNames(members []e2eharness.MIGMember) []string {
	names := make([]string, 0, len(members))
	for _, member := range members {
		if member.Serving {
			names = append(names, member.Name)
		}
	}
	slices.Sort(names)
	return names
}

// fleetMembers joins the MIG's managed members with their promoted addresses. A member the
// instance list does not carry yet gets an empty address, which no snapshot matches.
func fleetMembers(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, mig string) []e2eharness.MIGMember {
	t.Helper()
	addresses := memberNATIPs(ctx, t, suite, stack)
	disks := bootDiskIDs(ctx, t, suite, stack)
	members := migMembers(ctx, t, suite, mig)
	for i := range members {
		members[i].BootDiskID = disks[members[i].Name]
		members[i].NATIP = addresses[members[i].Name]
	}
	slices.SortFunc(members, func(a, b e2eharness.MIGMember) int { return strings.Compare(a.Name, b.Name) })
	return members
}

// snapshotFleet records every member's name, boot-disk identity, and promoted address.
func snapshotFleet(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack, mig string) []e2eharness.MIGMember {
	t.Helper()
	members := fleetMembers(ctx, t, suite, stack, mig)
	if len(members) == 0 {
		t.Fatalf("mig %s has no member to snapshot", mig)
	}
	for _, member := range members {
		if member.NATIP == "" {
			t.Fatalf("member %s has no promoted address to snapshot", member.Name)
		}
		if member.BootDiskID == "" {
			t.Fatalf("member %s has no boot disk to snapshot", member.Name)
		}
	}
	return members
}

// memberNATIPs returns each member's promoted external address by instance name.
func memberNATIPs(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack) map[string]string {
	t.Helper()
	addresses := map[string]string{}
	for _, row := range instanceAddresses(ctx, t, suite, stack) {
		fields := strings.Fields(row)
		if len(fields) != 2 {
			t.Fatalf("instance address row = %q, want a name and an address", row)
		}
		addresses[fields[0]] = fields[1]
	}
	return addresses
}

// replacedFleet reports whether current holds exactly before's names, each keeping its
// promoted address and carrying a new boot disk. Both slices are sorted by name.
func replacedFleet(current, before []e2eharness.MIGMember) bool {
	if len(current) != len(before) {
		return false
	}
	for i, member := range current {
		if member.Name != before[i].Name || member.NATIP != before[i].NATIP || member.BootDiskID == "" || member.BootDiskID == before[i].BootDiskID {
			return false
		}
	}
	return true
}

func waitForRepairedFleet(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack,
	mig string, before []e2eharness.MIGMember, timeout time.Duration) {
	t.Helper()
	transitions := newMemberTransitions(t, "waitForRepairedFleet "+stack.GatewayName)
	deadline := time.Now().Add(timeout)
	var members []e2eharness.MIGMember
	for time.Now().Before(deadline) {
		members = fleetMembers(ctx, t, suite, stack, mig)
		transitions.observe(members)
		if repairedFleet(members, before) {
			transitions.done()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for a repaired fleet: %v: %s", ctx.Err(), repairObservations(before, members))
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("fleet did not repair within %s: %s", timeout, repairObservations(before, members))
}

func repairedFleet(current, before []e2eharness.MIGMember) bool {
	if len(current) != len(before) {
		return false
	}
	changed := false
	for i, member := range current {
		if member.Name != before[i].Name || member.NATIP != before[i].NATIP {
			return false
		}
		replaced := member.BootDiskID != "" && member.BootDiskID != before[i].BootDiskID
		if !replaced && member.Health == "HEALTHY" {
			return false
		}
		changed = changed || replaced
	}
	return changed
}

func repairObservations(before, current []e2eharness.MIGMember) string {
	snapshots := make(map[string]e2eharness.MIGMember, len(before))
	for _, member := range before {
		snapshots[member.Name] = member
	}
	members := make(map[string]e2eharness.MIGMember, len(current))
	names := make([]string, 0, len(before)+len(current))
	for _, member := range before {
		names = append(names, member.Name)
	}
	for _, member := range current {
		members[member.Name] = member
		if _, found := snapshots[member.Name]; !found {
			names = append(names, member.Name)
		}
	}
	slices.Sort(names)
	observations := make([]string, 0, len(names))
	for _, name := range names {
		snapshot := snapshots[name]
		member := members[name]
		observations = append(observations, fmt.Sprintf("name=%s address=%s snapshot_id=%s current_id=%s health=%s",
			name, member.NATIP, snapshot.BootDiskID, member.BootDiskID, member.Health))
	}
	return strings.Join(observations, "; ")
}

func assertSameFleetIdentity(t *testing.T, current, before []e2eharness.MIGMember) {
	t.Helper()
	if len(current) != len(before) {
		t.Fatalf("fleet members = %+v, want the snapshot %+v", current, before)
	}
	for i, member := range current {
		if member.Name != before[i].Name || member.NATIP != before[i].NATIP {
			t.Fatalf("fleet members = %+v, want the snapshot %+v", current, before)
		}
	}
}

// waitForReplacedFleet waits for every replacement member to become observable.
func waitForReplacedFleet(ctx context.Context, t *testing.T, suite *e2eharness.Suite, stack *e2eharness.Stack,
	mig string, before []e2eharness.MIGMember, round func(members []e2eharness.MIGMember) bool, timeout time.Duration) {
	t.Helper()
	transitions := newMemberTransitions(t, "waitForReplacedFleet "+stack.GatewayName)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		members := fleetMembers(ctx, t, suite, stack, mig)
		transitions.observe(members)
		gated := round == nil || round(members)
		if gated && replacedFleet(members, before) {
			transitions.done()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for the replaced fleet: %v", ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("fleet did not replace every member of %+v within %s", before, timeout)
}

func waitForRunning(ctx context.Context, t *testing.T, suite *e2eharness.Suite, name string) {
	t.Helper()
	transitions := newMemberTransitions(t, "waitForRunning "+name)
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		state := strings.TrimSpace(runGcloud(ctx, t, suite, "compute", "instances", "describe", name, "--zone", suite.Env().Zone, "--format", "value(status)"))
		transitions.observeState(name, "status="+state)
		if state == "RUNNING" {
			transitions.done()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for instance %s running: %v", name, ctx.Err())
		case <-time.After(rolloutPoll):
		}
	}
	t.Fatalf("instance %s did not return to RUNNING", name)
}
