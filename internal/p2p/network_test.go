package p2p

import (
	"net"
	"testing"
	"time"
)

func TestDiscoveryExcludesVirtualAndNonBroadcastInterfaces(t *testing.T) {
	flags := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	ifaces := []net.Interface{{Name: "en0", Flags: flags}, {Name: "utun3", Flags: flags}, {Name: "awdl0", Flags: flags}, {Name: "llw0", Flags: flags}, {Name: "tun0", Flags: flags}, {Name: "tap1", Flags: flags}, {Name: "vpn", Flags: flags | net.FlagPointToPoint}, {Name: "no-broadcast", Flags: net.FlagUp}, {Name: "down", Flags: net.FlagBroadcast}, {Name: "fake", Flags: flags}, {Name: "host-route", Flags: flags}, {Name: "default-route", Flags: flags}}
	nets := networksForInterfaces(ifaces, func(i net.Interface) ([]net.Addr, error) {
		cidr := "192.168.10.5/24"
		switch i.Name {
		case "fake":
			cidr = "198.18.0.1/15"
		case "host-route":
			cidr = "10.0.0.1/32"
		case "default-route":
			cidr = "10.0.0.1/0"
		}
		ip, n, _ := net.ParseCIDR(cidr)
		n.IP = ip
		return []net.Addr{n}, nil
	})
	if len(nets) != 1 || nets[0].IP.String() != "192.168.10.5" {
		t.Fatalf("unexpected discovery networks: %v", nets)
	}
	addrs := broadcastsForNetworks(append(nets, nets...), DefaultUDPPort)
	if len(addrs) != 1 || addrs[0].IP.String() != "192.168.10.255" || addrs[0].Port != 32525 {
		t.Fatalf("unexpected broadcasts: %v", addrs)
	}
	if len(broadcastsForNetworks(nil, DefaultUDPPort)) != 0 {
		t.Fatal("global broadcast fallback reintroduced")
	}
	for _, ip := range []string{"198.18.0.1", "198.19.255.254", "127.0.0.1", "169.254.1.2", "0.0.0.0", "255.255.255.255"} {
		if isLANIPv4(net.ParseIP(ip)) {
			t.Errorf("unsafe LAN IP accepted: %s", ip)
		}
	}
}
func TestOfflineHeartbeatBackoff(t *testing.T) {
	m := NewMeshEngine(nil, nil, 1, DefaultUDPPort, nil, nil)
	defer m.cancel()
	now := time.Now()
	for failures := 1; failures <= 10; failures++ {
		m.recordHeartbeat("offline", false, now)
		delay := retryDelay(failures)
		if delay < 8*time.Second || delay > 2*time.Minute {
			t.Fatal("backoff outside bounds", delay)
		}
		if m.heartbeatDue("offline", now.Add(delay-time.Nanosecond)) {
			t.Fatal("retried before backoff")
		}
		if !m.heartbeatDue("offline", now.Add(delay)) {
			t.Fatal("did not retry after backoff")
		}
		now = now.Add(delay)
	}
	m.recordHeartbeat("offline", true, now)
	if !m.heartbeatDue("offline", now) {
		t.Fatal("online peer retained backoff")
	}
}
