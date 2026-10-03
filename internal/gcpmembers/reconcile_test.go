package gcpmembers

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/mock"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

type testDeps struct {
	*MockDeps
	records         map[string]*Record
	uidSeq          int
	confirmAbsent   func(ManagedResourceNames) (bool, string, error)
	compositeSynced func() (bool, string, error)
	keypairSeq      int
	createCalls     []Record
	updateCalls     []recordedUpdate
	deleteCalls     []recordedDelete
}

type recordedUpdate struct {
	name   string
	labels map[string]string
}
type recordedDelete struct {
	name string
	uid  types.UID
	rv   string
}

func newTestDeps(t *testing.T) *testDeps {
	t.Helper()
	deps := &testDeps{
		MockDeps: NewMockDeps(t), records: map[string]*Record{},
		confirmAbsent:   func(ManagedResourceNames) (bool, string, error) { return true, "", nil },
		compositeSynced: func() (bool, string, error) { return true, "", nil },
	}
	deps.EXPECT().GetRecord(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, _, _, name string) (*Record, bool, error) {
		rec, ok := deps.records[name]
		if !ok {
			return nil, false, nil
		}
		dup := *rec
		return &dup, true, nil
	}).Maybe()
	deps.EXPECT().CreateRecord(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, _, _ string, rec Record) error {
		if _, exists := deps.records[rec.Name]; exists {
			return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, rec.Name)
		}
		deps.createCalls = append(deps.createCalls, rec)
		deps.uidSeq++
		rec.UID = types.UID(fmt.Sprintf("secret-uid-%d", deps.uidSeq))
		rec.ResourceVersion = "1"
		deps.records[rec.Name] = &rec
		return nil
	}).Maybe()
	deps.EXPECT().UpdateRecordLabels(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, _, _, name string, labels map[string]string) error {
		rec, ok := deps.records[name]
		if !ok {
			return apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
		}
		deps.updateCalls = append(deps.updateCalls, recordedUpdate{name: name, labels: labels})
		if v, ok := labels[labelDepartureCount]; ok {
			_, _ = fmt.Sscanf(v, "%d", &rec.DepartureCount)
		}
		if v, ok := labels[labelPendingConfirmation]; ok {
			rec.PendingConfirmation = v == "true"
		}
		if v, ok := labels[labelExternalAddress]; ok {
			rec.ExternalAddress = v
		}
		if v, ok := labels[labelInstanceID]; ok {
			rec.InstanceID = v
		}
		if v, ok := labels[labelZone]; ok {
			rec.Zone = v
		}
		if v, ok := labels[labelRevision]; ok {
			rec.Revision = v
		}
		rec.ResourceVersion = fmt.Sprintf("%d", len(deps.updateCalls)+1)
		return nil
	}).Maybe()
	deps.EXPECT().DeleteRecord(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, _, _, name string, uid types.UID, resourceVersion string) error {
		rec, ok := deps.records[name]
		if !ok {
			return nil
		}
		if rec.UID != uid || rec.ResourceVersion != resourceVersion {
			return fmt.Errorf("delete precondition mismatch for %q", name)
		}
		deps.deleteCalls = append(deps.deleteCalls, recordedDelete{name: name, uid: uid, rv: resourceVersion})
		delete(deps.records, name)
		return nil
	}).Maybe()
	deps.EXPECT().ConfirmManagedResourcesAbsent(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, names ManagedResourceNames) (bool, string, error) {
		return deps.confirmAbsent(names)
	}).Maybe()
	deps.EXPECT().CompositeSynced(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(context.Context, string, string) (bool, string, error) { return deps.compositeSynced() }).Maybe()
	deps.EXPECT().GenerateKeypair().RunAndReturn(func() (string, string, error) {
		deps.keypairSeq++
		return fmt.Sprintf("priv-%d", deps.keypairSeq), fmt.Sprintf("pub-%d", deps.keypairSeq), nil
	}).Maybe()
	deps.EXPECT().ListRecordNames(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(context.Context, string, string) ([]string, error) {
		names := make([]string, 0, len(deps.records))
		for name := range deps.records {
			names = append(names, name)
		}
		sort.Strings(names)
		return names, nil
	}).Maybe()
	return deps
}

func (deps *testDeps) seed(rec Record) *Record {
	if rec.UID == "" {
		deps.uidSeq++
		rec.UID = types.UID(fmt.Sprintf("secret-uid-%d", deps.uidSeq))
	}
	if rec.ResourceVersion == "" {
		rec.ResourceVersion = "1"
	}
	dup := rec
	deps.records[rec.Name] = &dup
	return &dup
}

// testZone and testRevision are the fixture zone and template revision every listed test
// member reports, used to assert Result.Members carries them through unchanged.
const testZone = "us-central1-a"
const testRevision = "tmpl-1"

func presentMember(name, instanceID string) gcpdiscovery.ListedMember {
	return gcpdiscovery.ListedMember{Name: name, Action: gcpdiscovery.ActionNone, InstanceID: instanceID, Verdict: gcpdiscovery.VerdictPresent, Zone: testZone, TemplateRevision: testRevision}
}

// departedMember is a listing entry GCP is removing: DELETING carries no version, so its
// TemplateRevision is empty.
func departedMember(name, instanceID string) gcpdiscovery.ListedMember {
	return gcpdiscovery.ListedMember{Name: name, Action: gcpdiscovery.ActionDeleting, InstanceID: instanceID, Verdict: gcpdiscovery.VerdictDeparted, Zone: testZone}
}

func recreatingMember(name, instanceID string) gcpdiscovery.ListedMember {
	return gcpdiscovery.ListedMember{Name: name, Action: gcpdiscovery.ActionRecreating, InstanceID: instanceID, Verdict: gcpdiscovery.VerdictPresent, Zone: testZone, TemplateRevision: testRevision}
}

func findMember(members []wgnetv1alpha1.GatewayGCPMemberStatus, name string) (wgnetv1alpha1.GatewayGCPMemberStatus, bool) {
	for _, m := range members {
		if m.Name == name {
			return m, true
		}
	}
	return wgnetv1alpha1.GatewayGCPMemberStatus{}, false
}

// The fixture Gateway: a /29 with 10.99.0.1 on the gateway end and 10.99.0.2 on the link end.
const (
	testGatewayAddress = "10.99.0.1"
	testSubnetPrefix   = 29
)

var testBundle = BundleInputs{SubnetPrefix: testSubnetPrefix, PeerPublicKey: "link-pub", PeerAllowedIPs: "10.99.0.2/32"}

// testKeypair generates real WireGuard key material, which the record Secret's bundle
// payload requires: the public key is derived from the private one on every read.
func testKeypair(t *testing.T) (privateKey, publicKey string) {
	t.Helper()
	priv, pub, err := wg.GenerateKeypair()
	if err != nil {
		t.Fatalf("wg.GenerateKeypair() returned unexpected error: %v", err)
	}
	return priv, pub
}

func wantRosterEntry(t *testing.T, name string, slot int, tunnelAddress string) RosterEntry {
	t.Helper()
	names, err := NameResourceNames("gw-uid", "proj", name)
	if err != nil {
		t.Fatalf("NameResourceNames(%q) returned unexpected error: %v", name, err)
	}
	return RosterEntry{Name: name, Slot: slot, TunnelAddress: tunnelAddress, ManagedResourceNames: names}
}

func allocatedRecord(name string, slot int, tunnelAddress, zone, instanceID string, keySeq int) Record {
	return Record{
		Name:           name,
		Zone:           zone,
		Revision:       testRevision,
		Slot:           slot,
		PrivateKey:     fmt.Sprintf("priv-%d", keySeq),
		PublicKey:      fmt.Sprintf("pub-%d", keySeq),
		TunnelAddress:  tunnelAddress,
		SubnetPrefix:   testSubnetPrefix,
		PeerPublicKey:  testBundle.PeerPublicKey,
		PeerAllowedIPs: testBundle.PeerAllowedIPs,
		InstanceID:     instanceID,
		GatewayUID:     types.UID("gw-uid"),
		Project:        "proj",
	}
}

func activeMember(name string, slot int, tunnelAddress, instanceID string, state wgnetv1alpha1.GatewayGCPMemberState) wgnetv1alpha1.GatewayGCPMemberStatus {
	return wgnetv1alpha1.GatewayGCPMemberStatus{
		Name:          name,
		Zone:          testZone,
		Slot:          int32(slot),
		TunnelAddress: tunnelAddress,
		InstanceID:    instanceID,
		Revision:      testRevision,
		State:         state,
	}
}

func TestReconcileAllocation(t *testing.T) {
	seededPriv, seededPub := testKeypair(t)
	seeded := func(rec Record) Record {
		rec.PrivateKey, rec.PublicKey = seededPriv, seededPub
		rec.SubnetPrefix = testSubnetPrefix
		rec.GatewayUID, rec.Project = types.UID("gw-uid"), "proj"
		return rec
	}

	tests := []struct {
		name            string
		seed            []Record
		snap            *gcpdiscovery.Snapshot
		desiredReplicas int32
		capacity        int
		eligible        []string
		lastTargetSize  int32
		confirmAbsent   func(ManagedResourceNames) (bool, string, error)
		wantCreates     []Record
		wantUpdates     []recordedUpdate
		wantDeletes     []recordedDelete
		wantTargetSize  int32
		wantMembers     []wgnetv1alpha1.GatewayGCPMemberStatus
		wantPeers       []Peer
		wantRoster      []RosterEntry
		// wantRecord, when set, is the whole persisted record for its name after the pass.
		wantRecord *Record
	}{
		{
			name:            "allocates_slot_0_to_gateway_address",
			snap:            &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{presentMember("vm-a", "1")}},
			desiredReplicas: 1,
			capacity:        1,
			wantCreates:     []Record{allocatedRecord("vm-a", 0, testGatewayAddress, testZone, "1", 1)},
			wantTargetSize:  1,
			wantMembers:     []wgnetv1alpha1.GatewayGCPMemberStatus{activeMember("vm-a", 0, testGatewayAddress, "1", wgnetv1alpha1.GatewayGCPMemberActive)},
			wantPeers:       []Peer{{Slot: 0, PublicKey: "pub-1", TunnelAddress: testGatewayAddress}},
			wantRoster:      []RosterEntry{wantRosterEntry(t, "vm-a", 0, testGatewayAddress)},
		},
		{
			name: "allocates_ascending_slots_arbitrary_order",
			snap: &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{
				presentMember("vm-c", "3"),
				presentMember("vm-b", "2"),
				presentMember("vm-a", "1"),
			}},
			desiredReplicas: 3,
			capacity:        3,
			eligible:        []string{"10.99.0.3", "10.99.0.4"},
			wantCreates: []Record{
				allocatedRecord("vm-a", 0, testGatewayAddress, testZone, "1", 1),
				allocatedRecord("vm-b", 1, "10.99.0.3", testZone, "2", 2),
				allocatedRecord("vm-c", 2, "10.99.0.4", testZone, "3", 3),
			},
			wantTargetSize: 3,
			wantMembers: []wgnetv1alpha1.GatewayGCPMemberStatus{
				activeMember("vm-a", 0, testGatewayAddress, "1", wgnetv1alpha1.GatewayGCPMemberActive),
				activeMember("vm-b", 1, "10.99.0.3", "2", wgnetv1alpha1.GatewayGCPMemberActive),
				activeMember("vm-c", 2, "10.99.0.4", "3", wgnetv1alpha1.GatewayGCPMemberActive),
			},
			wantPeers: []Peer{
				{Slot: 0, PublicKey: "pub-1", TunnelAddress: testGatewayAddress},
				{Slot: 1, PublicKey: "pub-2", TunnelAddress: "10.99.0.3"},
				{Slot: 2, PublicKey: "pub-3", TunnelAddress: "10.99.0.4"},
			},
			wantRoster: []RosterEntry{
				wantRosterEntry(t, "vm-a", 0, testGatewayAddress),
				wantRosterEntry(t, "vm-b", 1, "10.99.0.3"),
				wantRosterEntry(t, "vm-c", 2, "10.99.0.4"),
			},
		},
		{
			name: "capacity_exhausted_stays_pending",
			snap: &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{
				presentMember("vm-a", "1"),
				presentMember("vm-b", "2"),
			}},
			desiredReplicas: 2,
			capacity:        1,
			wantCreates:     []Record{allocatedRecord("vm-a", 0, testGatewayAddress, testZone, "1", 1)},
			wantTargetSize:  0,
			wantMembers: []wgnetv1alpha1.GatewayGCPMemberStatus{
				activeMember("vm-a", 0, testGatewayAddress, "1", wgnetv1alpha1.GatewayGCPMemberActive),
				{Name: "vm-b", State: wgnetv1alpha1.GatewayGCPMemberPending},
			},
			wantPeers:  []Peer{{Slot: 0, PublicKey: "pub-1", TunnelAddress: testGatewayAddress}},
			wantRoster: []RosterEntry{wantRosterEntry(t, "vm-a", 0, testGatewayAddress)},
		},
		{
			name:            "resumes_existing_record_unchanged",
			seed:            []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0, TunnelAddress: testGatewayAddress, InstanceID: "1"})},
			snap:            &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{presentMember("vm-a", "1")}},
			desiredReplicas: 1,
			capacity:        1,
			wantTargetSize:  1,
			wantMembers:     []wgnetv1alpha1.GatewayGCPMemberStatus{activeMember("vm-a", 0, testGatewayAddress, "1", wgnetv1alpha1.GatewayGCPMemberActive)},
			wantPeers:       []Peer{{Slot: 0, PublicKey: seededPub, TunnelAddress: testGatewayAddress}},
			wantRoster:      []RosterEntry{wantRosterEntry(t, "vm-a", 0, testGatewayAddress)},
		},
		{
			name:            "debounce_absent_once_reports_departing",
			seed:            []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0, TunnelAddress: testGatewayAddress})},
			snap:            &gcpdiscovery.Snapshot{},
			desiredReplicas: 1,
			capacity:        1,
			wantUpdates: []recordedUpdate{{name: "vm-a", labels: map[string]string{
				labelDepartureCount: "1",
				labelState:          string(wgnetv1alpha1.GatewayGCPMemberDeparting),
			}}},
			wantTargetSize: 1,
			wantMembers:    []wgnetv1alpha1.GatewayGCPMemberStatus{activeMember("vm-a", 0, testGatewayAddress, "", wgnetv1alpha1.GatewayGCPMemberDeparting)},
			wantPeers:      []Peer{{Slot: 0, PublicKey: seededPub, TunnelAddress: testGatewayAddress}},
			wantRoster:     []RosterEntry{wantRosterEntry(t, "vm-a", 0, testGatewayAddress)},
		},
		{
			name:            "debounce_third_absence_departs",
			seed:            []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0, TunnelAddress: testGatewayAddress, DepartureCount: 2})},
			snap:            &gcpdiscovery.Snapshot{},
			desiredReplicas: 1,
			capacity:        1,
			wantUpdates: []recordedUpdate{{name: "vm-a", labels: map[string]string{
				labelDepartureCount:      "3",
				labelPendingConfirmation: "true",
				labelState:               string(wgnetv1alpha1.GatewayGCPMemberDeparted),
			}}},
			wantTargetSize: 1,
			wantMembers:    []wgnetv1alpha1.GatewayGCPMemberStatus{activeMember("vm-a", 0, testGatewayAddress, "", wgnetv1alpha1.GatewayGCPMemberDeparted)},
		},
		{
			name:            "debounce_reappearance_resets",
			seed:            []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0, TunnelAddress: testGatewayAddress, InstanceID: "1", DepartureCount: 2})},
			snap:            &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{presentMember("vm-a", "1")}},
			desiredReplicas: 1,
			capacity:        1,
			wantUpdates:     []recordedUpdate{{name: "vm-a", labels: map[string]string{labelDepartureCount: "0"}}},
			wantTargetSize:  1,
			wantMembers:     []wgnetv1alpha1.GatewayGCPMemberStatus{activeMember("vm-a", 0, testGatewayAddress, "1", wgnetv1alpha1.GatewayGCPMemberActive)},
			wantPeers:       []Peer{{Slot: 0, PublicKey: seededPub, TunnelAddress: testGatewayAddress}},
			wantRoster:      []RosterEntry{wantRosterEntry(t, "vm-a", 0, testGatewayAddress)},
		},
		{
			name:            "unusable_pass_holds_last_accepted_target_size",
			desiredReplicas: 4,
			capacity:        5,
			lastTargetSize:  2,
			wantTargetSize:  2,
		},
		{
			name:            "confirmation_blocked_leaves_departed",
			seed:            []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0, TunnelAddress: testGatewayAddress, PendingConfirmation: true})},
			snap:            &gcpdiscovery.Snapshot{},
			desiredReplicas: 1,
			capacity:        1,
			confirmAbsent: func(ManagedResourceNames) (bool, string, error) {
				return false, "SecretIAMMember still present", nil
			},
			wantTargetSize: 1,
			wantMembers: []wgnetv1alpha1.GatewayGCPMemberStatus{{
				Name: "vm-a", Zone: testZone, Slot: 0, TunnelAddress: testGatewayAddress, Revision: testRevision,
				State: wgnetv1alpha1.GatewayGCPMemberDeparted, Message: "SecretIAMMember still present",
			}},
		},
		{
			name:            "confirmation_holds_releases",
			seed:            []Record{seeded(Record{Name: "vm-a", Slot: 0, TunnelAddress: testGatewayAddress, PendingConfirmation: true})},
			snap:            &gcpdiscovery.Snapshot{},
			desiredReplicas: 1,
			capacity:        1,
			wantDeletes:     []recordedDelete{{name: "vm-a", uid: types.UID("secret-uid-1"), rv: "1"}},
			wantTargetSize:  1,
		},
		{
			name:            "targetsize_over_capacity_holds_last_accepted",
			snap:            &gcpdiscovery.Snapshot{},
			desiredReplicas: 9,
			capacity:        5,
			lastTargetSize:  4,
			wantTargetSize:  4,
		},
		{
			name:            "departure_reports_the_recorded_revision",
			seed:            []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: "tmpl-a", Slot: 0, TunnelAddress: testGatewayAddress, InstanceID: "1"})},
			snap:            &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{departedMember("vm-a", "1")}},
			desiredReplicas: 1,
			capacity:        1,
			wantUpdates: []recordedUpdate{{name: "vm-a", labels: map[string]string{
				labelPendingConfirmation: "true",
				labelState:               string(wgnetv1alpha1.GatewayGCPMemberDeparted),
			}}},
			wantTargetSize: 1,
			wantMembers: []wgnetv1alpha1.GatewayGCPMemberStatus{{
				Name: "vm-a", Zone: testZone, Slot: 0, TunnelAddress: testGatewayAddress, InstanceID: "1",
				Revision: "tmpl-a", State: wgnetv1alpha1.GatewayGCPMemberDeparted,
			}},
		},
		{
			name: "blocked_confirmation_reports_the_recorded_revision",
			seed: []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: "tmpl-a", Slot: 0,
				TunnelAddress: testGatewayAddress, InstanceID: "1", PendingConfirmation: true})},
			snap:            &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{departedMember("vm-a", "1")}},
			desiredReplicas: 1,
			capacity:        1,
			confirmAbsent: func(ManagedResourceNames) (bool, string, error) {
				return false, "SecretIAMMember still present", nil
			},
			wantTargetSize: 1,
			wantMembers: []wgnetv1alpha1.GatewayGCPMemberStatus{{
				Name: "vm-a", Zone: testZone, Slot: 0, TunnelAddress: testGatewayAddress, InstanceID: "1",
				Revision: "tmpl-a", State: wgnetv1alpha1.GatewayGCPMemberDeparted, Message: "SecretIAMMember still present",
			}},
		},
		{
			name: "pending_confirmation_reappearing_present_adopts_the_new_id_and_address",
			seed: []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0,
				TunnelAddress: testGatewayAddress, ExternalAddress: "203.0.113.1", InstanceID: "1",
				DepartureCount: 3, PendingConfirmation: true})},
			snap: &gcpdiscovery.Snapshot{
				Members: []gcpdiscovery.ListedMember{presentMember("vm-a", "2")},
				Details: map[string]gcpdiscovery.Detail{"vm-a": {
					Name: "vm-a", InstanceID: "2", ExternalAddress: "203.0.113.9",
					Reason: gcpdiscovery.DetailReasonIDChanged,
				}},
			},
			desiredReplicas: 1,
			capacity:        1,
			wantUpdates: []recordedUpdate{{name: "vm-a", labels: map[string]string{
				labelPendingConfirmation: "false",
				labelDepartureCount:      "0",
				labelState:               string(wgnetv1alpha1.GatewayGCPMemberActive),
				labelExternalAddress:     "203.0.113.9",
				labelInstanceID:          "2",
			}}},
			wantTargetSize: 1,
			wantMembers: []wgnetv1alpha1.GatewayGCPMemberStatus{{
				Name: "vm-a", Zone: testZone, Slot: 0, TunnelAddress: testGatewayAddress,
				ExternalAddress: "203.0.113.9", InstanceID: "2", Revision: testRevision,
				State: wgnetv1alpha1.GatewayGCPMemberActive,
			}},
			wantPeers: []Peer{{Slot: 0, PublicKey: seededPub, ExternalAddress: "203.0.113.9",
				TunnelAddress: testGatewayAddress}},
			wantRoster: []RosterEntry{wantRosterEntry(t, "vm-a", 0, testGatewayAddress)},
			wantRecord: &Record{
				Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0,
				PrivateKey: seededPriv, PublicKey: seededPub, TunnelAddress: testGatewayAddress,
				SubnetPrefix: testSubnetPrefix, ExternalAddress: "203.0.113.9", InstanceID: "2",
				GatewayUID: types.UID("gw-uid"), Project: "proj",
				UID: types.UID("secret-uid-1"), ResourceVersion: "2",
			},
		},
		{
			name: "pending_confirmation_reappearing_recreating_resumes_recreating",
			seed: []Record{seeded(Record{Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0,
				TunnelAddress: testGatewayAddress, InstanceID: "1", DepartureCount: 3, PendingConfirmation: true})},
			snap:            &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{recreatingMember("vm-a", "1")}},
			desiredReplicas: 1,
			capacity:        1,
			wantUpdates: []recordedUpdate{{name: "vm-a", labels: map[string]string{
				labelPendingConfirmation: "false",
				labelDepartureCount:      "0",
				labelState:               string(wgnetv1alpha1.GatewayGCPMemberRecreating),
			}}},
			wantTargetSize: 1,
			wantMembers:    []wgnetv1alpha1.GatewayGCPMemberStatus{activeMember("vm-a", 0, testGatewayAddress, "1", wgnetv1alpha1.GatewayGCPMemberRecreating)},
			wantPeers:      []Peer{{Slot: 0, PublicKey: seededPub, TunnelAddress: testGatewayAddress}},
			wantRoster:     []RosterEntry{wantRosterEntry(t, "vm-a", 0, testGatewayAddress)},
			wantRecord: &Record{
				Name: "vm-a", Zone: testZone, Revision: testRevision, Slot: 0,
				PrivateKey: seededPriv, PublicKey: seededPub, TunnelAddress: testGatewayAddress,
				InstanceID: "1", SubnetPrefix: testSubnetPrefix,
				GatewayUID: types.UID("gw-uid"), Project: "proj",
				UID: types.UID("secret-uid-1"), ResourceVersion: "2",
			},
		},
		{
			name:            "adoption_rejects_foreign_gateway_uid",
			seed:            []Record{{Name: "vm-a", Slot: 0, PrivateKey: seededPriv, PublicKey: seededPub, TunnelAddress: testGatewayAddress, GatewayUID: "other-gw-uid", Project: "proj"}},
			snap:            &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{presentMember("vm-a", "1")}},
			desiredReplicas: 1,
			capacity:        1,
			wantTargetSize:  1,
			wantMembers:     []wgnetv1alpha1.GatewayGCPMemberStatus{{Name: "vm-a", State: wgnetv1alpha1.GatewayGCPMemberPending}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := newTestDeps(t)
			for _, rec := range tt.seed {
				deps.seed(rec)
			}
			if tt.confirmAbsent != nil {
				deps.confirmAbsent = tt.confirmAbsent
			}

			result, err := Reconcile(context.Background(), deps, "gw-uid", "ns", "gw", "proj",
				tt.snap, tt.desiredReplicas, tt.capacity, tt.eligible, testGatewayAddress, tt.lastTargetSize, testBundle)
			if err != nil {
				t.Fatalf("Reconcile(...) returned unexpected error: %v", err)
			}

			if !reflect.DeepEqual(deps.createCalls, wantSlice(tt.wantCreates)) {
				t.Errorf("CreateRecord calls = %+v, want %+v", deps.createCalls, tt.wantCreates)
			}
			if !reflect.DeepEqual(deps.updateCalls, wantSlice(tt.wantUpdates)) {
				t.Errorf("UpdateRecordLabels calls = %+v, want %+v", deps.updateCalls, tt.wantUpdates)
			}
			if !reflect.DeepEqual(deps.deleteCalls, wantSlice(tt.wantDeletes)) {
				t.Errorf("DeleteRecord calls = %+v, want %+v", deps.deleteCalls, tt.wantDeletes)
			}
			if result.TargetSize != tt.wantTargetSize {
				t.Errorf("Result.TargetSize = %d, want %d", result.TargetSize, tt.wantTargetSize)
			}
			if result.Unusable != (tt.snap == nil) {
				t.Errorf("Result.Unusable = %v, want %v", result.Unusable, tt.snap == nil)
			}
			if !reflect.DeepEqual(result.Members, wantSlice(tt.wantMembers)) {
				t.Errorf("Result.Members = %+v, want %+v", result.Members, tt.wantMembers)
			}
			if !reflect.DeepEqual(result.Peers, wantSlice(tt.wantPeers)) {
				t.Errorf("Result.Peers = %+v, want %+v", result.Peers, tt.wantPeers)
			}
			if !reflect.DeepEqual(result.Roster, wantSlice(tt.wantRoster)) {
				t.Errorf("Result.Roster = %+v, want %+v", result.Roster, tt.wantRoster)
			}
			if tt.wantRecord != nil {
				got, ok := deps.records[tt.wantRecord.Name]
				if !ok {
					t.Fatalf("persisted records = %+v, want a record for %q", deps.records, tt.wantRecord.Name)
				}
				if !reflect.DeepEqual(*got, *tt.wantRecord) {
					t.Errorf("persisted record = %+v, want %+v", *got, *tt.wantRecord)
				}
			}
		})
	}
}

// wantSlice normalises an empty expectation to the nil slice both Result and the recorded
// call slices carry when nothing happened.
func wantSlice[T any](want []T) []T {
	if len(want) == 0 {
		return nil
	}
	return want
}

func TestReconcileSingle(t *testing.T) {
	priv, pub := testKeypair(t)
	singleRecord := Record{
		Name:           "gw-inst-9x2",
		Slot:           0,
		PrivateKey:     priv,
		PublicKey:      pub,
		TunnelAddress:  testGatewayAddress,
		SubnetPrefix:   testSubnetPrefix,
		PeerPublicKey:  testBundle.PeerPublicKey,
		PeerAllowedIPs: testBundle.PeerAllowedIPs,
		GatewayUID:     types.UID("gw-uid"),
		Project:        "proj",
	}

	tests := []struct {
		name         string
		seed         []Record
		instanceName string
		wantCreates  []Record
		wantRoster   []RosterEntry
	}{
		{
			name:         "unobserved_instance_name_renders_no_roster",
			instanceName: "",
		},
		{
			name:         "observed_instance_name_allocates_slot_0",
			instanceName: "gw-inst-9x2",
			wantCreates:  []Record{singleRecord},
			wantRoster:   []RosterEntry{wantRosterEntry(t, "gw-inst-9x2", 0, testGatewayAddress)},
		},
		{
			name:         "existing_record_is_resumed",
			seed:         []Record{singleRecord},
			instanceName: "gw-inst-9x2",
			wantRoster:   []RosterEntry{wantRosterEntry(t, "gw-inst-9x2", 0, testGatewayAddress)},
		},
		{
			name: "foreign_record_is_not_adopted",
			seed: []Record{{
				Name: "gw-inst-9x2", Slot: 0, PrivateKey: priv, PublicKey: pub,
				TunnelAddress: testGatewayAddress, GatewayUID: "other-gw-uid", Project: "proj",
			}},
			instanceName: "gw-inst-9x2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := newTestDeps(t)
			for _, rec := range tt.seed {
				deps.seed(rec)
			}

			result, err := ReconcileSingle(context.Background(), deps, "gw-uid", "ns", "gw", "proj",
				tt.instanceName, testGatewayAddress, priv, pub, testBundle)
			if err != nil {
				t.Fatalf("ReconcileSingle(...) returned unexpected error: %v", err)
			}

			if !reflect.DeepEqual(deps.createCalls, wantSlice(tt.wantCreates)) {
				t.Errorf("CreateRecord calls = %+v, want %+v", deps.createCalls, tt.wantCreates)
			}
			if wantUpdates := []recordedUpdate(nil); !reflect.DeepEqual(deps.updateCalls, wantUpdates) {
				t.Errorf("UpdateRecordLabels calls = %+v, want %+v", deps.updateCalls, wantUpdates)
			}
			if wantDeletes := []recordedDelete(nil); !reflect.DeepEqual(deps.deleteCalls, wantDeletes) {
				t.Errorf("DeleteRecord calls = %+v, want %+v", deps.deleteCalls, wantDeletes)
			}
			if !reflect.DeepEqual(result.Roster, wantSlice(tt.wantRoster)) {
				t.Errorf("Result.Roster = %+v, want %+v", result.Roster, tt.wantRoster)
			}
			if wantMembers := []wgnetv1alpha1.GatewayGCPMemberStatus(nil); !reflect.DeepEqual(result.Members, wantMembers) {
				t.Errorf("Result.Members = %+v, want %+v", result.Members, wantMembers)
			}
			if wantPeers := []Peer(nil); !reflect.DeepEqual(result.Peers, wantPeers) {
				t.Errorf("Result.Peers = %+v, want %+v", result.Peers, wantPeers)
			}
		})
	}
}

// TestReconcileRevisionPersisted verifies revisions across allocation, updates, and departure.
func TestReconcileRevisionPersisted(t *testing.T) {
	tests := []struct {
		name string
		// listedRevisions is one usable pass per entry, vm-a listed carrying that revision.
		listedRevisions []string
		wantRevision    string
	}{
		{name: "revision of the creating pass", listedRevisions: []string{"tmpl-a"}, wantRevision: "tmpl-a"},
		{name: "revision of the latest listing", listedRevisions: []string{"tmpl-a", "tmpl-b"}, wantRevision: "tmpl-b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := newTestDeps(t)
			ctx := context.Background()
			for _, revision := range tt.listedRevisions {
				listed := presentMember("vm-a", "1")
				listed.TemplateRevision = revision
				snap := &gcpdiscovery.Snapshot{Members: []gcpdiscovery.ListedMember{listed}}
				if _, err := Reconcile(ctx, deps, "gw-uid", "ns", "gw", "proj", snap, 1, 1, nil,
					testGatewayAddress, 0, testBundle); err != nil {
					t.Fatalf("Reconcile(listed %s) returned unexpected error: %v", revision, err)
				}
			}
			if got := deps.records["vm-a"].Revision; got != tt.wantRevision {
				t.Errorf("persisted Record.Revision = %q, want %q", got, tt.wantRevision)
			}

			result, err := Reconcile(ctx, deps, "gw-uid", "ns", "gw", "proj", &gcpdiscovery.Snapshot{}, 1, 1, nil,
				testGatewayAddress, 0, testBundle)
			if err != nil {
				t.Fatalf("Reconcile(absent) returned unexpected error: %v", err)
			}
			want := []wgnetv1alpha1.GatewayGCPMemberStatus{{
				Name: "vm-a", Zone: testZone, Slot: 0, TunnelAddress: testGatewayAddress, InstanceID: "1",
				Revision: tt.wantRevision, State: wgnetv1alpha1.GatewayGCPMemberDeparting,
			}}
			if !reflect.DeepEqual(result.Members, want) {
				t.Errorf("Result.Members = %+v, want %+v", result.Members, want)
			}
		})
	}
}
