package controller

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

func TestEffectiveZones(t *testing.T) {
	tests := []struct {
		name  string
		zones []string
		zone  string
		want  []string
	}{
		{"effective_zones_absent_defaults_to_zone", nil, "us-central1-a", []string{"us-central1-a"}},
		{"present zones are returned verbatim", []string{"us-central1-b", "us-central1-c"}, "us-central1-a", []string{"us-central1-b", "us-central1-c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &wgnetv1alpha1.Gateway{Spec: wgnetv1alpha1.GatewaySpec{
				GCP: wgnetv1alpha1.GatewayGCPSpec{Zone: tt.zone, Zones: tt.zones},
			}}
			got := effectiveZones(gw)
			if len(got) != len(tt.want) {
				t.Fatalf("effectiveZones = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("effectiveZones[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestTunnelAddresses(t *testing.T) {
	tests := []struct {
		name                string
		subnet              string
		gatewayAddress      string
		linkAddress         string
		wantOK              bool
		wantReasonSubstring string
		wantEligible        []string
	}{
		{
			name: "accepts default subnet hosts", subnet: "10.99.0.0/29",
			gatewayAddress: "10.99.0.1", linkAddress: "10.99.0.2", wantOK: true,
			wantEligible: []string{"10.99.0.3", "10.99.0.4", "10.99.0.5", "10.99.0.6"},
		},
		{
			name: "eligible list stops at the capacity bound", subnet: "10.0.0.0/8",
			gatewayAddress: "10.0.0.1", linkAddress: "10.0.0.2", wantOK: true,
			wantEligible: expectedEligibleAddresses(t, "10.0.0.3", capacityLimit-1),
		},
		{
			name: "rejects an address outside the subnet", subnet: "10.99.0.0/29",
			gatewayAddress: "10.99.0.1", linkAddress: "10.1.0.2", wantOK: false, wantReasonSubstring: "10.1.0.2", wantEligible: []string{},
		},
		{
			name: "rejects equal gateway and link addresses", subnet: "10.99.0.0/29",
			gatewayAddress: "10.99.0.1", linkAddress: "10.99.0.1", wantOK: false, wantReasonSubstring: "distinct", wantEligible: []string{},
		},
		{
			name: "rejects the network or broadcast address", subnet: "10.99.0.0/29",
			gatewayAddress: "10.99.0.0", linkAddress: "10.99.0.2", wantOK: false, wantReasonSubstring: "usable host", wantEligible: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eligible, ok, reason := tunnelAddresses(tt.subnet, tt.gatewayAddress, tt.linkAddress)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (reason %q)", ok, tt.wantOK, reason)
			}
			if !slices.Equal(eligible, tt.wantEligible) {
				t.Errorf("eligible = %v, want %v", eligible, tt.wantEligible)
			}
			if !ok {
				if reason == "" {
					t.Errorf("reason is empty, want it to mention %q", tt.wantReasonSubstring)
				}
				if tt.wantReasonSubstring != "" && !strings.Contains(reason, tt.wantReasonSubstring) {
					t.Errorf("reason = %q, want it to mention %q", reason, tt.wantReasonSubstring)
				}
			}
		})
	}
}

func TestCapacity(t *testing.T) {
	tests := []struct {
		name   string
		subnet string
		want   int
	}{
		{"a default /29 yields 5", wgDefaultSubnet, 5},
		{"a /30 yields 1", "10.99.0.0/30", 1},
		{"a /31 yields 0", "10.99.0.0/31", 0},
		{"a /24 yields 253", "10.99.0.0/24", 253},
		{"a /8 is capped at 256", "10.0.0.0/8", 256},
		{"a /0 is capped at 256", "0.0.0.0/0", 256},
		{"an IPv6 subnet yields 0", "2001:db8::/64", 0},
		{"an invalid CIDR yields 0", "not-a-cidr", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := capacity(tt.subnet); got != tt.want {
				t.Errorf("capacity(%q) = %d, want %d", tt.subnet, got, tt.want)
			}
		})
	}
}

func expectedEligibleAddresses(t *testing.T, first string, count int) []string {
	t.Helper()
	address, err := netip.ParseAddr(first)
	if err != nil {
		t.Fatalf("parse first eligible address: %v", err)
	}
	addresses := make([]string, 0, count)
	for range count {
		addresses = append(addresses, address.String())
		address = address.Next()
	}
	return addresses
}
