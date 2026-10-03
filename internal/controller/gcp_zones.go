package controller

import (
	"fmt"
	"net"

	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// effectiveZones returns spec.gcp.zones, or [spec.gcp.zone] when absent.
func effectiveZones(gw *wgnetv1alpha1.Gateway) []string {
	if len(gw.Spec.GCP.Zones) > 0 {
		return gw.Spec.GCP.Zones
	}
	return []string{gw.Spec.GCP.Zone}
}

// capacityLimit is the link's slot range: the routing key carries the slot in one byte,
// so no subnet width yields more than 256 members.
const capacityLimit = 256

// tunnelAddresses validates tunnel hosts and returns bounded allocation addresses.
func tunnelAddresses(subnet, gatewayAddress, linkAddress string) (eligible []string, ok bool, reason string) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, false, fmt.Sprintf("spec.wireguard.subnet %q is not a valid CIDR", subnet)
	}
	gateway := net.ParseIP(gatewayAddress)
	if gateway == nil {
		return nil, false, fmt.Sprintf("spec.wireguard.gatewayAddress %q is not a valid address", gatewayAddress)
	}
	link := net.ParseIP(linkAddress)
	if link == nil {
		return nil, false, fmt.Sprintf("spec.wireguard.linkAddress %q is not a valid address", linkAddress)
	}
	if gateway.Equal(link) {
		return nil, false, fmt.Sprintf("spec.wireguard.gatewayAddress and spec.wireguard.linkAddress must be distinct, both are %q", gatewayAddress)
	}
	if !usableHost(ipnet, gateway) {
		return nil, false, fmt.Sprintf("spec.wireguard.gatewayAddress %q is not a usable host of spec.wireguard.subnet %q", gatewayAddress, subnet)
	}
	if !usableHost(ipnet, link) {
		return nil, false, fmt.Sprintf("spec.wireguard.linkAddress %q is not a usable host of spec.wireguard.subnet %q", linkAddress, subnet)
	}

	base, size := networkRange(ipnet)
	taken := map[uint32]bool{ipToUint32(gateway.To4()): true, ipToUint32(link.To4()): true}
	want := capacityOf(ipnet) - 1
	eligible = make([]string, 0, want)
	for i := uint64(1); i < size-1 && len(eligible) < want; i++ {
		host := base + uint32(i)
		if taken[host] {
			continue
		}
		eligible = append(eligible, uint32ToIP(host).String())
	}
	return eligible, true, ""
}

// capacity is min(256, usable hosts of subnet minus the link address),
// derived from the prefix length rather than by enumerating hosts.
func capacity(subnet string) int {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return 0
	}
	return capacityOf(ipnet)
}

func capacityOf(ipnet *net.IPNet) int {
	_, size := networkRange(ipnet)
	if size < 4 {
		return 0
	}
	hosts := min(size-2-1, capacityLimit)
	return int(hosts)
}

// networkRange returns ipnet's first address and its size in addresses. A non-IPv4 network
// reports size 0, which every caller reads as "no usable host".
func networkRange(ipnet *net.IPNet) (base uint32, size uint64) {
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return 0, 0
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return 0, 0
	}
	return ipToUint32(ip4), uint64(1) << uint(bits-ones)
}

// usableHost reports whether ip is a host of ipnet other than its network and broadcast
// addresses.
func usableHost(ipnet *net.IPNet, ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || !ipnet.Contains(ip4) {
		return false
	}
	base, size := networkRange(ipnet)
	if size < 4 {
		return false
	}
	v := ipToUint32(ip4)
	return v != base && uint64(v) != uint64(base)+size-1
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// subnetPrefix is subnet's prefix length, which renders a member's tunnel address in CIDR
// form. An unparsable subnet reports 0; tunnelAddresses has already rejected the Gateway.
func subnetPrefix(subnet string) int {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return 0
	}
	ones, _ := ipnet.Mask.Size()
	return ones
}
