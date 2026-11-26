package p2p

import (
	"net"
	"strings"
)

// Discovery is restricted to broadcast-capable LAN interfaces, never VPN/TUN
// or peer-to-peer links. No global 255.255.255.255 fallback is emitted.
func isLANInterface(iface net.Interface) bool {
	f := iface.Flags
	if f&net.FlagUp == 0 || f&net.FlagBroadcast == 0 || f&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
		return false
	}
	name := strings.ToLower(iface.Name)
	for _, prefix := range []string{"utun", "awdl", "llw", "tun", "tap", "ppp", "ipsec", "tailscale", "wg"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}
func isLANIPv4(ip net.IP) bool {
	v := ip.To4()
	return v != nil && v.IsGlobalUnicast() && !v.IsLoopback() && !v.IsLinkLocalUnicast() && !(v[0] == 198 && (v[1] == 18 || v[1] == 19))
}
func networksForInterfaces(ifaces []net.Interface, addresses func(net.Interface) ([]net.Addr, error)) []net.IPNet {
	var out []net.IPNet
	for _, iface := range ifaces {
		if !isLANInterface(iface) {
			continue
		}
		addrs, err := addresses(iface)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || !isLANIPv4(n.IP) {
				continue
			}
			ones, bits := n.Mask.Size()
			if bits != 32 || ones < 1 || ones > 30 {
				continue
			}
			out = append(out, net.IPNet{IP: append(net.IP(nil), n.IP.To4()...), Mask: append(net.IPMask(nil), n.Mask...)})
		}
	}
	return out
}
func lanNetworks() []net.IPNet {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return networksForInterfaces(ifaces, func(i net.Interface) ([]net.Addr, error) { return i.Addrs() })
}
func GetLANIPs() []string {
	ips := []string{}
	seen := map[string]bool{}
	for _, n := range lanNetworks() {
		s := n.IP.String()
		if !seen[s] {
			ips = append(ips, s)
			seen[s] = true
		}
	}
	if len(ips) == 0 {
		return []string{"127.0.0.1"}
	}
	return ips
}
func selectBestIPForRemote(remote net.IP) string {
	for _, n := range lanNetworks() {
		if n.Contains(remote) {
			return n.IP.String()
		}
	}
	return GetLANIPs()[0]
}
func broadcastsForNetworks(networks []net.IPNet, port int) []*net.UDPAddr {
	var out []*net.UDPAddr
	seen := map[string]bool{}
	for _, n := range networks {
		ones, bits := n.Mask.Size()
		ip := n.IP.To4()
		if !isLANIPv4(ip) || bits != 32 || ones < 1 || ones > 30 {
			continue
		}
		b := make(net.IP, 4)
		for i := range b {
			b[i] = ip[i] | ^n.Mask[i]
		}
		if !seen[b.String()] {
			seen[b.String()] = true
			out = append(out, &net.UDPAddr{IP: b, Port: port})
		}
	}
	return out
}
func getBroadcastAddrs(port int) []*net.UDPAddr { return broadcastsForNetworks(lanNetworks(), port) }
