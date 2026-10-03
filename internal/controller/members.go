package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpdiscovery"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/gcpmembers"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// reasonMemberCleanupBlocked is an event-only reason: a blocked departure is reported on the
// member's own status.gcp.members entry, never in the Ready condition.
const reasonMemberCleanupBlocked = "MemberCleanupBlocked"

// blockedCleanupWarnKeyPrefix distinguishes warnBlockedMemberCleanup's suppression entries
// from the other warn helpers' in the shared unresolvedWarned map.
const blockedCleanupWarnKeyPrefix = "member-cleanup/"

// xgatewayMember aliases the generated composite's roster entry, so both branches render the
// roster through one helper.
type xgatewayMember = struct {
	CloudSecretIamMemberName string `json:"cloudSecretIamMemberName"`
	CloudSecretName          string `json:"cloudSecretName"`
	CloudSecretVersionName   string `json:"cloudSecretVersionName"`
	KubernetesSecretName     string `json:"kubernetesSecretName"`
	Name                     string `json:"name"`
	Slot                     int    `json:"slot"`
	TunnelAddress            string `json:"tunnelAddress"`
}

func gatewayRefreshKey(gw *wgnetv1alpha1.Gateway) string { return gw.Namespace + "/" + gw.Name }

// rosterOf is result's roster, empty when no pass has produced one yet.
func rosterOf(result *gcpmembers.Result) []gcpmembers.RosterEntry {
	if result == nil {
		return nil
	}
	return result.Roster
}

func rosterMembers(roster []gcpmembers.RosterEntry) []xgatewayMember {
	members := make([]xgatewayMember, 0, len(roster))
	for _, e := range roster {
		members = append(members, xgatewayMember{
			CloudSecretIamMemberName: e.CloudSecretIAMMemberName,
			CloudSecretName:          e.CloudSecretName,
			CloudSecretVersionName:   e.CloudSecretVersionName,
			KubernetesSecretName:     e.KubernetesSecretName,
			Name:                     e.Name,
			Slot:                     e.Slot,
			TunnelAddress:            e.TunnelAddress,
		})
	}
	return members
}

// fillPeerListenPort supplies the Gateway-wide port omitted by member reconciliation.
func fillPeerListenPort(peers []gcpmembers.Peer, port int) []gcpmembers.Peer {
	out := make([]gcpmembers.Peer, len(peers))
	for i, p := range peers {
		p.ListenPort = port
		out[i] = p
	}
	return out
}

func discoveryRecorded(records []gcpmembers.Record) []gcpdiscovery.Recorded {
	recorded := make([]gcpdiscovery.Recorded, 0, len(records))
	for _, rec := range records {
		recorded = append(recorded, gcpdiscovery.Recorded{Name: rec.Name, ExternalAddress: rec.ExternalAddress, InstanceID: rec.InstanceID})
	}
	return recorded
}

func gcpAddressRefreshDue(refreshed *sync.Map, key string, now time.Time, interval time.Duration) bool {
	last, found := refreshed.Load(key)
	if !found {
		return true
	}
	at, ok := last.(time.Time)
	if !ok {
		return true
	}
	return now.Sub(at) >= interval
}

// reconcileSingleMember retains the applied roster until an instance name is observed.
func (r *GatewayReconciler) reconcileSingleMember(ctx context.Context, gw *wgnetv1alpha1.Gateway, instanceName string) (*gcpmembers.Result, error) {
	if instanceName == "" {
		return &gcpmembers.Result{Unusable: true}, nil
	}
	gatewayPrivateKey, linkPublicKey, err := r.readGatewayKeys(ctx, gw)
	if err != nil {
		return nil, err
	}
	gatewayPublicKey, err := r.readLinkPeerPublicKey(ctx, gw)
	if err != nil {
		return nil, err
	}
	deps := gcpmembers.NewKubernetesDeps(r.Client, r.APIReader, gw.UID, gw.Spec.GCP.ProjectID)
	res, err := gcpmembers.ReconcileSingle(ctx, deps, string(gw.UID), gw.Namespace, gw.Name,
		gw.Spec.GCP.ProjectID, instanceName, effectiveWGGatewayAddress(gw),
		gatewayPrivateKey, gatewayPublicKey, bundleInputs(gw, linkPublicKey))
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// reconcileMembers runs one discovery-and-allocation pass for a load-balanced Gateway.
func (r *GatewayReconciler) reconcileMembers(ctx context.Context, gw *wgnetv1alpha1.Gateway, migName string, eligibleAddresses []string) (result *gcpmembers.Result, discoveryFailed bool, discoveryMessage string, err error) {
	if migName == "" {
		waiting, werr := r.dependencyWaitResult(ctx, gw)
		return waiting, false, "", werr
	}

	deps := gcpmembers.NewKubernetesDeps(r.Client, r.APIReader, gw.UID, gw.Spec.GCP.ProjectID)
	names, nerr := deps.ListRecordNames(ctx, gw.Namespace, gw.Name)
	if nerr != nil {
		return nil, false, "", fmt.Errorf("list member records: %w", nerr)
	}
	records := make([]gcpmembers.Record, 0, len(names))
	for _, name := range names {
		rec, found, rerr := deps.GetRecord(ctx, gw.Namespace, gw.Name, name)
		if rerr != nil {
			return nil, false, "", fmt.Errorf("get member record %q: %w", name, rerr)
		}
		if found {
			records = append(records, *rec)
		}
	}
	recorded := discoveryRecorded(records)
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	refreshNames := []string(nil)
	if gcpAddressRefreshDue(&r.gcpAddressRefreshed, gatewayRefreshKey(gw), now, r.Config.GCPAddressRefreshInterval) {
		refreshNames = names
	}

	var snap *gcpdiscovery.Snapshot
	credNamespace, credName, cerr := parseCredentialsSecretRef(r.Config.GCPCredentialsSecret)
	if cerr != nil {
		return nil, false, "", cerr
	}
	discClient, cerr := r.gcpCreds.clientFor(ctx, r.APIReader, credNamespace, credName, r.Config.GCPCredentialsKey)
	if cerr != nil {
		discoveryFailed = true
		discoveryMessage = cerr.Error()
	} else {
		listed, lerr := discClient.List(ctx, gw.Spec.GCP.ProjectID, gw.Spec.GCP.Region, migName, recorded, refreshNames)
		if lerr != nil {
			discoveryFailed = true
			discoveryMessage = lerr.Error()
		} else {
			snap = &listed
			r.gcpAddressRefreshed.Store(gatewayRefreshKey(gw), now)
		}
	}

	lastTargetSize, terr := r.readXGatewayGCPTargetSize(ctx, gw)
	if terr != nil {
		return nil, false, "", terr
	}
	_, linkPublicKey, kerr := r.readGatewayKeys(ctx, gw)
	if kerr != nil {
		return nil, false, "", kerr
	}
	res, rerr := gcpmembers.Reconcile(ctx, deps, string(gw.UID), gw.Namespace, gw.Name, gw.Spec.GCP.ProjectID,
		snap, gw.Spec.GCP.Replicas, capacity(effectiveWGSubnet(gw)), eligibleAddresses,
		effectiveWGGatewayAddress(gw), lastTargetSize, bundleInputs(gw, linkPublicKey))
	if rerr != nil {
		return nil, false, "", rerr
	}
	if res.Unusable && discoveryMessage == "" {
		discoveryFailed = true
		discoveryMessage = "gcp member discovery pass produced no usable snapshot"
	}
	// An unusable pass neither changes cleanup warnings nor releases suppression.
	if !res.Unusable {
		r.warnBlockedMemberCleanup(gw, blockedMemberCleanups(&res))
	}
	return &res, discoveryFailed, discoveryMessage, nil
}

// dependencyWaitResult retains applied membership while the MIG name is unavailable.
func (r *GatewayReconciler) dependencyWaitResult(ctx context.Context, gw *wgnetv1alpha1.Gateway) (*gcpmembers.Result, error) {
	exists, err := r.xgatewayGCPExists(ctx, gw)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	targetSize, err := r.readXGatewayGCPTargetSize(ctx, gw)
	if err != nil {
		return nil, err
	}
	return &gcpmembers.Result{TargetSize: targetSize, Unusable: true}, nil
}

// passRoster retains the composite roster when discovery is unusable.
func (r *GatewayReconciler) passRoster(ctx context.Context, gw *wgnetv1alpha1.Gateway, result *gcpmembers.Result) ([]gcpmembers.RosterEntry, error) {
	if !result.Unusable {
		return result.Roster, nil
	}
	xg := newXGatewayGCP()
	key := client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}
	if err := r.Get(ctx, key, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get xgatewaygcp %s for applied members: %w", key, err)
	}
	raw, found, err := unstructured.NestedSlice(xg.Object, "spec", "members")
	if err != nil {
		return nil, fmt.Errorf("read spec.members of %s: %w", key, err)
	}
	if !found {
		return nil, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encode applied members of %s: %w", key, err)
	}
	var applied []struct {
		CloudSecretIAMMemberName string `json:"cloudSecretIamMemberName"`
		CloudSecretName          string `json:"cloudSecretName"`
		CloudSecretVersionName   string `json:"cloudSecretVersionName"`
		KubernetesSecretName     string `json:"kubernetesSecretName"`
		Name                     string `json:"name"`
		Slot                     int    `json:"slot"`
		TunnelAddress            string `json:"tunnelAddress"`
	}
	if err := json.Unmarshal(data, &applied); err != nil {
		return nil, fmt.Errorf("decode applied members of %s: %w", key, err)
	}
	entries := make([]gcpmembers.RosterEntry, 0, len(applied))
	for _, m := range applied {
		entries = append(entries, gcpmembers.RosterEntry{
			Name:          m.Name,
			Slot:          m.Slot,
			TunnelAddress: m.TunnelAddress,
			ManagedResourceNames: gcpmembers.ManagedResourceNames{
				KubernetesSecretName:     m.KubernetesSecretName,
				CloudSecretName:          m.CloudSecretName,
				CloudSecretVersionName:   m.CloudSecretVersionName,
				CloudSecretIAMMemberName: m.CloudSecretIAMMemberName,
			},
		})
	}
	return entries, nil
}

// blockedMemberCleanups are the members whose confirmation could not complete this pass:
// Departed carrying the message naming what blocks the release.
func blockedMemberCleanups(result *gcpmembers.Result) []wgnetv1alpha1.GatewayGCPMemberStatus {
	if result == nil {
		return nil
	}
	blocked := make([]wgnetv1alpha1.GatewayGCPMemberStatus, 0, len(result.Members))
	for _, m := range result.Members {
		if m.State == wgnetv1alpha1.GatewayGCPMemberDeparted && m.Message != "" {
			blocked = append(blocked, m)
		}
	}
	return blocked
}

func blockedCleanupSignature(blocked []wgnetv1alpha1.GatewayGCPMemberStatus) string {
	parts := make([]string, 0, len(blocked))
	for _, m := range blocked {
		parts = append(parts, m.Name+"="+m.Message)
	}
	return strings.Join(parts, ",")
}

// warnBlockedMemberCleanup emits one Warning per member whose departure cannot complete, only when
// the blocked set changed: the block persists until its cause clears, so a requeue must not warn.
func (r *GatewayReconciler) warnBlockedMemberCleanup(gw *wgnetv1alpha1.Gateway, blocked []wgnetv1alpha1.GatewayGCPMemberStatus) {
	if r.Recorder == nil {
		return
	}
	key := blockedCleanupWarnKeyPrefix + unresolvedWarnKey(gw)
	if len(blocked) == 0 {
		r.unresolvedWarned.Delete(key)
		return
	}
	signature := blockedCleanupSignature(blocked)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
		return
	}
	r.unresolvedWarned.Store(key, signature)
	for _, m := range blocked {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonMemberCleanupBlocked, actionReconcile,
			"member %q has departed but its cleanup cannot complete: %s", m.Name, m.Message)
	}
}
