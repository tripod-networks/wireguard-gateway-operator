package gcpmembers

import (
	"context"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// Peer is what the link's RuntimeConfig.WireGuard.Peer list needs per live member
// .
type Peer struct {
	Slot            int
	PublicKey       string
	ExternalAddress string
	ListenPort      int
	// TunnelAddress is this member's tunnel address, rendered into the peer's
	// AllowedIPs as a /32 by the caller.
	TunnelAddress string
}

// RosterEntry is one live member's composite-roster entry: name, slot,
// tunnel address, ManagedResourceNames.
type RosterEntry struct {
	Name          string
	Slot          int
	TunnelAddress string
	ManagedResourceNames
}

// Result is one Reconcile pass's output.
type Result struct {
	// Members mirrors verbatim onto Gateway.Status.GCP.Members.
	Members []wgnetv1alpha1.GatewayGCPMemberStatus
	// TargetSize preserves the last accepted value when replicas exceed capacity.
	TargetSize int32
	// Peers are every live (Active/Recreating/Departing) member's link peer entry.
	Peers []Peer
	// Roster is every live member's composite-roster entry: name, slot,
	// tunnel address, ManagedResourceNames.
	Roster []RosterEntry
	// Unusable preserves the caller-applied membership values.
	Unusable bool
}

// BundleInputs are the per-Gateway values every member's bundle payload carries beside its
// own key, address and slot. They are uniform across the fleet.
type BundleInputs struct {
	// SubnetPrefix is spec.wireguard.subnet's prefix length, which renders the member's
	// tunnel address in CIDR form.
	SubnetPrefix int
	// PeerPublicKey is the Gateway's link public key.
	PeerPublicKey string
	// PeerAllowedIPs is the link address as a /32, authoritative for the member's peer.
	PeerAllowedIPs string
}

// Reconcile advances member allocation and retirement from a usable discovery snapshot.
// An unusable snapshot returns only the prior target size.
func Reconcile(ctx context.Context, deps Deps, gatewayUID, gatewayNamespace, gatewayName, project string, snap *gcpdiscovery.Snapshot, desiredReplicas int32, capacity int, eligibleAddresses []string, gatewayAddress string, lastAcceptedTargetSize int32, bundle BundleInputs) (Result, error) {
	if snap == nil {
		return Result{Unusable: true, TargetSize: lastAcceptedTargetSize}, nil
	}
	targetSize := computeTargetSize(desiredReplicas, capacity, lastAcceptedTargetSize)

	listedByName := make(map[string]gcpdiscovery.ListedMember, len(snap.Members))
	for _, m := range snap.Members {
		listedByName[m.Name] = m
	}

	trackedNames, err := deps.ListRecordNames(ctx, gatewayNamespace, gatewayName)
	if err != nil {
		return Result{}, fmt.Errorf("gcpmembers: listing tracked records: %w", err)
	}

	allNames := make(map[string]struct{}, len(listedByName)+len(trackedNames))
	for n := range listedByName {
		allNames[n] = struct{}{}
	}
	for _, n := range trackedNames {
		allNames[n] = struct{}{}
	}

	// Adopt only records owned by this Gateway to prevent slot displacement.
	adopted := make(map[string]*Record, len(allNames))
	occupiedSlots := make(map[int]bool, len(allNames))
	for name := range allNames {
		rec, found, err := deps.GetRecord(ctx, gatewayNamespace, gatewayName, name)
		if err != nil {
			return Result{}, fmt.Errorf("gcpmembers: reading record for %q: %w", name, err)
		}
		if !found {
			continue
		}
		if rec.GatewayUID != types.UID(gatewayUID) || rec.Project != project || rec.Name != name {
			continue
		}
		adopted[name] = rec
		occupiedSlots[rec.Slot] = true
	}

	// Fresh allocation candidates: VerdictPresent, not adopted, processed in a fixed
	// (name-ascending) order so allocation order never depends on listing/observation order.
	var candidates []string
	for name, listed := range listedByName {
		if listed.Verdict == gcpdiscovery.VerdictPresent {
			if _, ok := adopted[name]; !ok {
				candidates = append(candidates, name)
			}
		}
	}
	sort.Strings(candidates)

	for _, name := range candidates {
		rec, allocated, err := tryAllocate(ctx, deps, gatewayNamespace, gatewayName, gatewayUID, project, name, listedByName[name], snap, occupiedSlots, capacity, eligibleAddresses, gatewayAddress, bundle)
		if err != nil {
			return Result{}, err
		}
		if allocated {
			adopted[name] = &rec
			occupiedSlots[rec.Slot] = true
		}
	}

	names := make([]string, 0, len(allNames))
	for n := range allNames {
		names = append(names, n)
	}
	sort.Strings(names)

	var result Result
	result.TargetSize = targetSize

	for _, name := range names {
		rec := adopted[name]
		listed, isListed := listedByName[name]

		switch {
		case rec == nil:
			result.Members = append(result.Members, pendingMember(name))

		case rec.PendingConfirmation:
			member, peer, entry, err := confirmOrResume(ctx, deps, gatewayNamespace, gatewayName, gatewayUID, *rec, isListed, listed, snap)
			if err != nil {
				return Result{}, err
			}
			if member != nil {
				result.Members = append(result.Members, *member)
			}
			if peer != nil {
				result.Peers = append(result.Peers, *peer)
				result.Roster = append(result.Roster, *entry)
			}

		case isListed && listed.Verdict == gcpdiscovery.VerdictDeparted:
			if err := deps.UpdateRecordLabels(ctx, gatewayNamespace, gatewayName, name, map[string]string{
				labelPendingConfirmation: "true",
				labelState:               string(wgnetv1alpha1.GatewayGCPMemberDeparted),
			}); err != nil {
				return Result{}, fmt.Errorf("gcpmembers: marking %q pending confirmation: %w", name, err)
			}
			result.Members = append(result.Members, buildMemberStatus(*rec, listed.Zone, rec.Revision, wgnetv1alpha1.GatewayGCPMemberDeparted, ""))

		case isListed && listed.Verdict == gcpdiscovery.VerdictPresent:
			member, peer, entry, err := resumeActive(ctx, deps, gatewayNamespace, gatewayName, *rec, listed, snap, false)
			if err != nil {
				return Result{}, err
			}
			result.Members = append(result.Members, member)
			result.Peers = append(result.Peers, peer)
			result.Roster = append(result.Roster, entry)

		default:
			member, peer, entry, err := debounceAbsence(ctx, deps, gatewayNamespace, gatewayName, *rec)
			if err != nil {
				return Result{}, err
			}
			result.Members = append(result.Members, member)
			if peer != nil {
				result.Peers = append(result.Peers, *peer)
				result.Roster = append(result.Roster, *entry)
			}
		}
	}

	return result, nil
}

func computeTargetSize(desiredReplicas int32, capacity int, lastAcceptedTargetSize int32) int32 {
	if int(desiredReplicas) <= capacity {
		return desiredReplicas
	}
	return lastAcceptedTargetSize
}

func lowestFreeSlot(occupied map[int]bool, capacity int) (int, bool) {
	for s := range capacity {
		if !occupied[s] {
			return s, true
		}
	}
	return 0, false
}

// slotAddress resolves the tunnel address for slot: slot 0 takes
// gatewayAddress, slot s>0 takes eligibleAddresses[s-1].
func slotAddress(slot int, gatewayAddress string, eligibleAddresses []string) (string, error) {
	if slot == 0 {
		return gatewayAddress, nil
	}
	idx := slot - 1
	if idx < 0 || idx >= len(eligibleAddresses) {
		return "", fmt.Errorf("gcpmembers: slot %d has no eligible address (have %d)", slot, len(eligibleAddresses))
	}
	return eligibleAddresses[idx], nil
}

// tryAllocate persists the lowest free slot; exhaustion and name collisions are not errors.
func tryAllocate(ctx context.Context, deps Deps, gatewayNamespace, gatewayName, gatewayUID, project, name string, listed gcpdiscovery.ListedMember, snap *gcpdiscovery.Snapshot, occupiedSlots map[int]bool, capacity int, eligibleAddresses []string, gatewayAddress string, bundle BundleInputs) (Record, bool, error) {
	slot, ok := lowestFreeSlot(occupiedSlots, capacity)
	if !ok {
		return Record{}, false, nil
	}
	tunnelAddress, err := slotAddress(slot, gatewayAddress, eligibleAddresses)
	if err != nil {
		return Record{}, false, err
	}
	priv, pub, err := deps.GenerateKeypair()
	if err != nil {
		return Record{}, false, fmt.Errorf("gcpmembers: generating keypair for %q: %w", name, err)
	}
	externalAddress := ""
	if d, ok := snap.Details[name]; ok {
		externalAddress = d.ExternalAddress
	}
	rec := Record{
		Name:            name,
		Zone:            listed.Zone,
		Revision:        listed.TemplateRevision,
		Slot:            slot,
		PrivateKey:      priv,
		PublicKey:       pub,
		TunnelAddress:   tunnelAddress,
		SubnetPrefix:    bundle.SubnetPrefix,
		PeerPublicKey:   bundle.PeerPublicKey,
		PeerAllowedIPs:  bundle.PeerAllowedIPs,
		ExternalAddress: externalAddress,
		InstanceID:      listed.InstanceID,
		GatewayUID:      types.UID(gatewayUID),
		Project:         project,
	}
	if err := deps.CreateRecord(ctx, gatewayNamespace, gatewayName, rec); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("gcpmembers: creating record for %q: %w", name, err)
	}
	return rec, true, nil
}

func pendingMember(name string) wgnetv1alpha1.GatewayGCPMemberStatus {
	return wgnetv1alpha1.GatewayGCPMemberStatus{Name: name, State: wgnetv1alpha1.GatewayGCPMemberPending}
}

// buildMemberStatus uses listing fields when present, otherwise recorded fields.
func buildMemberStatus(rec Record, zone, revision string, state wgnetv1alpha1.GatewayGCPMemberState, message string) wgnetv1alpha1.GatewayGCPMemberStatus {
	return wgnetv1alpha1.GatewayGCPMemberStatus{
		Name:            rec.Name,
		Zone:            zone,
		Slot:            int32(rec.Slot),
		TunnelAddress:   rec.TunnelAddress,
		ExternalAddress: rec.ExternalAddress,
		InstanceID:      rec.InstanceID,
		Revision:        revision,
		State:           state,
		Message:         message,
	}
}

// buildPeer leaves ListenPort zero: Reconcile has no listen-port input, so its caller fills
// in the Gateway-wide listen port before use.
func buildPeer(rec Record) Peer {
	return Peer{Slot: rec.Slot, PublicKey: rec.PublicKey, ExternalAddress: rec.ExternalAddress, TunnelAddress: rec.TunnelAddress}
}

func buildRosterEntry(rec Record) (RosterEntry, error) {
	names, err := NameResourceNames(string(rec.GatewayUID), rec.Project, rec.Name)
	if err != nil {
		return RosterEntry{}, fmt.Errorf("gcpmembers: deriving roster names for %q: %w", rec.Name, err)
	}
	return RosterEntry{Name: rec.Name, Slot: rec.Slot, TunnelAddress: rec.TunnelAddress, ManagedResourceNames: names}, nil
}

// resumeActive updates a present record without rewriting its bundle payload.
func resumeActive(ctx context.Context, deps Deps, gatewayNamespace, gatewayName string, rec Record, listed gcpdiscovery.ListedMember, snap *gcpdiscovery.Snapshot, pendingConfirmation bool) (wgnetv1alpha1.GatewayGCPMemberStatus, Peer, RosterEntry, error) {
	updates := map[string]string{}
	if rec.DepartureCount != 0 || pendingConfirmation {
		updates[labelDepartureCount] = "0"
		rec.DepartureCount = 0
	}
	if d, ok := snap.Details[rec.Name]; ok && d.ExternalAddress != "" && d.ExternalAddress != rec.ExternalAddress {
		updates[labelExternalAddress] = d.ExternalAddress
		rec.ExternalAddress = d.ExternalAddress
	}
	if listed.InstanceID != "" && listed.InstanceID != rec.InstanceID {
		updates[labelInstanceID] = listed.InstanceID
		rec.InstanceID = listed.InstanceID
	}
	if listed.Zone != "" && listed.Zone != rec.Zone {
		updates[labelZone] = listed.Zone
		rec.Zone = listed.Zone
	}
	if listed.TemplateRevision != "" && listed.TemplateRevision != rec.Revision {
		updates[labelRevision] = listed.TemplateRevision
		rec.Revision = listed.TemplateRevision
	}
	state := wgnetv1alpha1.GatewayGCPMemberActive
	if listed.Action == gcpdiscovery.ActionRecreating {
		state = wgnetv1alpha1.GatewayGCPMemberRecreating
	}
	if pendingConfirmation {
		updates[labelPendingConfirmation] = "false"
		updates[labelState] = string(state)
		rec.PendingConfirmation = false
	}
	if len(updates) > 0 {
		if err := deps.UpdateRecordLabels(ctx, gatewayNamespace, gatewayName, rec.Name, updates); err != nil {
			return wgnetv1alpha1.GatewayGCPMemberStatus{}, Peer{}, RosterEntry{}, fmt.Errorf("gcpmembers: updating record labels for %q: %w", rec.Name, err)
		}
	}

	entry, err := buildRosterEntry(rec)
	if err != nil {
		return wgnetv1alpha1.GatewayGCPMemberStatus{}, Peer{}, RosterEntry{}, err
	}
	return buildMemberStatus(rec, listed.Zone, listed.TemplateRevision, state, ""), buildPeer(rec), entry, nil
}

// debounceAbsence advances the usable-snapshot departure counter.
func debounceAbsence(ctx context.Context, deps Deps, gatewayNamespace, gatewayName string, rec Record) (wgnetv1alpha1.GatewayGCPMemberStatus, *Peer, *RosterEntry, error) {
	newCount := rec.DepartureCount + 1
	if newCount >= 3 {
		if err := deps.UpdateRecordLabels(ctx, gatewayNamespace, gatewayName, rec.Name, map[string]string{
			labelDepartureCount:      "3",
			labelPendingConfirmation: "true",
			labelState:               string(wgnetv1alpha1.GatewayGCPMemberDeparted),
		}); err != nil {
			return wgnetv1alpha1.GatewayGCPMemberStatus{}, nil, nil, fmt.Errorf("gcpmembers: departing %q: %w", rec.Name, err)
		}
		rec.DepartureCount = 3
		return buildMemberStatus(rec, rec.Zone, rec.Revision, wgnetv1alpha1.GatewayGCPMemberDeparted, ""), nil, nil, nil
	}

	if err := deps.UpdateRecordLabels(ctx, gatewayNamespace, gatewayName, rec.Name, map[string]string{
		labelDepartureCount: fmt.Sprintf("%d", newCount),
		labelState:          string(wgnetv1alpha1.GatewayGCPMemberDeparting),
	}); err != nil {
		return wgnetv1alpha1.GatewayGCPMemberStatus{}, nil, nil, fmt.Errorf("gcpmembers: advancing debounce for %q: %w", rec.Name, err)
	}
	rec.DepartureCount = newCount
	entry, err := buildRosterEntry(rec)
	if err != nil {
		return wgnetv1alpha1.GatewayGCPMemberStatus{}, nil, nil, err
	}
	peer := buildPeer(rec)
	member := buildMemberStatus(rec, rec.Zone, rec.Revision, wgnetv1alpha1.GatewayGCPMemberDeparting, "")
	return member, &peer, &entry, nil
}

// confirmOrResume resumes a reappearing member or confirms its resource cleanup.
func confirmOrResume(ctx context.Context, deps Deps, gatewayNamespace, gatewayName, gatewayUID string, rec Record, isListed bool, listed gcpdiscovery.ListedMember, snap *gcpdiscovery.Snapshot) (*wgnetv1alpha1.GatewayGCPMemberStatus, *Peer, *RosterEntry, error) {
	if isListed && listed.Verdict == gcpdiscovery.VerdictPresent {
		member, peer, entry, err := resumeActive(ctx, deps, gatewayNamespace, gatewayName, rec, listed, snap, true)
		if err != nil {
			return nil, nil, nil, err
		}
		return &member, &peer, &entry, nil
	}

	names, err := NameResourceNames(gatewayUID, rec.Project, rec.Name)
	if err != nil {
		return nil, nil, nil, err
	}

	// A departing listing has no template, so report the record revision.
	blockedZone := rec.Zone
	if isListed {
		blockedZone = listed.Zone
	}
	blocked := func(message string) *wgnetv1alpha1.GatewayGCPMemberStatus {
		m := buildMemberStatus(rec, blockedZone, rec.Revision, wgnetv1alpha1.GatewayGCPMemberDeparted, message)
		return &m
	}

	absent, reason, err := deps.ConfirmManagedResourcesAbsent(ctx, names)
	if err != nil {
		return blocked(err.Error()), nil, nil, nil
	}
	if !absent {
		return blocked(reason), nil, nil, nil
	}
	synced, reason, err := deps.CompositeSynced(ctx, gatewayNamespace, gatewayName)
	if err != nil {
		return blocked(err.Error()), nil, nil, nil
	}
	if !synced {
		return blocked(reason), nil, nil, nil
	}
	if err := deps.DeleteRecord(ctx, gatewayNamespace, gatewayName, rec.Name, rec.UID, rec.ResourceVersion); err != nil {
		return blocked(err.Error()), nil, nil, nil
	}
	return nil, nil, nil, nil
}

// ReconcileSingle maintains the observed single-instance member roster.
func ReconcileSingle(ctx context.Context, deps Deps, gatewayUID, gatewayNamespace, gatewayName, project, instanceName, tunnelAddress, privateKey, publicKey string, bundle BundleInputs) (Result, error) {
	if instanceName == "" {
		return Result{}, nil
	}

	rec, found, err := deps.GetRecord(ctx, gatewayNamespace, gatewayName, instanceName)
	if err != nil {
		return Result{}, fmt.Errorf("gcpmembers: reading record for %q: %w", instanceName, err)
	}
	if found && (rec.GatewayUID != types.UID(gatewayUID) || rec.Project != project || rec.Name != instanceName) {
		return Result{}, nil
	}
	if !found {
		fresh := Record{
			Name:           instanceName,
			Slot:           0,
			PrivateKey:     privateKey,
			PublicKey:      publicKey,
			TunnelAddress:  tunnelAddress,
			SubnetPrefix:   bundle.SubnetPrefix,
			PeerPublicKey:  bundle.PeerPublicKey,
			PeerAllowedIPs: bundle.PeerAllowedIPs,
			GatewayUID:     types.UID(gatewayUID),
			Project:        project,
		}
		if err := deps.CreateRecord(ctx, gatewayNamespace, gatewayName, fresh); err != nil {
			return Result{}, fmt.Errorf("gcpmembers: creating record for %q: %w", instanceName, err)
		}
		rec = &fresh
	}

	entry, err := buildRosterEntry(*rec)
	if err != nil {
		return Result{}, err
	}
	return Result{Roster: []RosterEntry{entry}}, nil
}
