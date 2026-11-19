package p2p

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanchat/internal/crypto"
	"lanchat/internal/store"
)

const (
	DefaultUDPPort   = 52525
	DiscoverMagicReq = "LANCHAT_SCAN_V1"
)

// DiscoveredNode represents a node on the LAN that currently has its "Allow Discovery" switch turned ON.
type DiscoveredNode struct {
	PeerID string `json:"peer_id"`
	Name   string `json:"name"`
	OS     string `json:"os"`
	Addr   string `json:"addr"` // IP:HTTPPort
}

// PairRequest is sent from the initiating node to the discoverable/target node.
type PairRequest struct {
	PeerID       string `json:"peer_id"`
	Name         string `json:"name"`
	OS           string `json:"os"`
	PublicKeyHex string `json:"public_key_hex"`
	SharedKeyHex string `json:"shared_key_hex"`
	HTTPPort     int    `json:"http_port"`
	PIN          string `json:"pin"`
	Signature    string `json:"signature,omitempty"`
}

// PairResponse is returned when the 6-digit PIN is verified.
type PairResponse struct {
	PeerID       string `json:"peer_id"`
	Name         string `json:"name"`
	OS           string `json:"os"`
	PublicKeyHex string `json:"public_key_hex"`
	HTTPPort     int    `json:"http_port"`
}

// WireMessage is the payload pushed over P2P HTTP between trusted nodes.
type WireMessage struct {
	Message          *store.Message `json:"message"`
	InlineDataBase64 string         `json:"inline_data_b64,omitempty"`
}

// MeshEngine coordinates privacy-first discovery, pairing, and trusted peer synchronization.
type MeshEngine struct {
	identity     *crypto.IdentityManager
	ring         *store.RingBuffer
	httpPort     int
	udpPort      int
	udpConn      *net.UDPConn
	onNewMessage func(msg *store.Message)
	onPeerChange func()
	stopCh       chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	jobs         chan deliveryJob
	onDelivery   func(string, map[string]string)
	stopOnce     sync.Once
	wg           sync.WaitGroup
}

func NewMeshEngine(
	im *crypto.IdentityManager,
	rb *store.RingBuffer,
	httpPort int,
	udpPort int,
	onNewMessage func(msg *store.Message),
	onPeerChange func(),
) *MeshEngine {
	if udpPort <= 0 {
		udpPort = DefaultUDPPort
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &MeshEngine{
		ctx: ctx, cancel: cancel, jobs: make(chan deliveryJob, 256),
		identity:     im,
		ring:         rb,
		httpPort:     httpPort,
		udpPort:      udpPort,
		onNewMessage: onNewMessage,
		onPeerChange: onPeerChange,
		stopCh:       make(chan struct{}),
	}
}

// Start launches the passive UDP listener and silent trusted-peer heartbeat loop.
// Zero public broadcast packets are emitted on startup.
func (m *MeshEngine) Start() error {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: m.udpPort}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		// Fallback to ephemeral UDP port if 52525 is already bound by another instance on the same host
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	if err == nil {
		m.udpConn = conn
		m.wg.Add(1)
		go m.udpListenLoop()
	}

	for i := 0; i < 4; i++ {
		m.wg.Add(1)
		go m.deliveryWorker()
	}
	m.wg.Add(1)
	go m.trustedHeartbeatLoop()
	return err
}

func (m *MeshEngine) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh); m.cancel() })
	if m.udpConn != nil {
		_ = m.udpConn.Close()
	}
	m.wg.Wait()
}

func (m *MeshEngine) udpListenLoop() {
	defer m.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, remoteAddr, err := m.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.stopCh:
				return
			default:
				continue
			}
		}
		pkt := buf[:n]

		// 1. Check if this is an opaque 50-byte HMAC silent probe from an already-trusted peer
		if n == 50 {
			if senderPeerID, senderHTTPPort, ok := m.identity.VerifySilentProbePacket(pkt); ok {
				peerAddr := fmt.Sprintf("%s:%d", remoteAddr.IP.String(), senderHTTPPort)
				m.identity.SetPeerOnline(senderPeerID, peerAddr, true)
				if m.onPeerChange != nil {
					m.onPeerChange()
				}
				// Trigger an immediate signed ping back so the probing peer learns our current IP:Port
				go m.pingTrustedPeer(senderPeerID, peerAddr)
			}
			continue
		}

		// 2. Check if this is an explicit scan request ("LANCHAT_SCAN_V1")
		// STRICT PRIVACY GATE: Only respond if local "Discoverable Mode" switch is currently ON!
		if string(pkt) == DiscoverMagicReq {
			enabled, _, _ := m.identity.DiscoverableState()
			if !enabled {
				// Default silent mode: ignore completely!
				continue
			}
			resp := DiscoveredNode{
				PeerID: m.identity.PeerID(),
				Name:   m.identity.Name(),
				OS:     m.identity.OS(),
				Addr:   fmt.Sprintf("%s:%d", selectBestIPForRemote(remoteAddr.IP), m.httpPort),
			}
			if data, err := json.Marshal(resp); err == nil {
				_, _ = m.udpConn.WriteToUDP(data, remoteAddr)
			}
		}
	}
}

// ScanDiscoverablePeers sends a one-time UDP scan when the user explicitly clicks "Scan LAN" in UI.
// Only remote nodes that have toggled "Allow Discovery" ON will reply.
func (m *MeshEngine) ScanDiscoverablePeers(timeout time.Duration) ([]DiscoveredNode, error) {
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	bcastAddrs := getBroadcastAddrs(m.udpPort)
	reqBytes := []byte(DiscoverMagicReq)
	for _, dst := range bcastAddrs {
		_, _ = conn.WriteToUDP(reqBytes, dst)
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	found := make(map[string]DiscoveredNode)
	buf := make([]byte, 2048)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var node DiscoveredNode
		if json.Unmarshal(buf[:n], &node) == nil && node.PeerID != "" && node.PeerID != m.identity.PeerID() {
			if node.Addr == "" || strings.HasPrefix(node.Addr, "127.") || strings.HasPrefix(node.Addr, ":") {
				_, portStr, _ := net.SplitHostPort(node.Addr)
				if portStr == "" {
					portStr = strconv.Itoa(m.httpPort)
				}
				node.Addr = net.JoinHostPort(raddr.IP.String(), portStr)
			}
			found[node.PeerID] = node
		}
	}

	out := make([]DiscoveredNode, 0, len(found))
	for _, v := range found {
		out = append(out, v)
	}
	return out, nil
}

// PairWithPeer initiates pairing with a remote node at targetAddr using its 6-digit PIN.
func (m *MeshEngine) PairWithPeer(targetAddr string, pin string) (*crypto.TrustedPeer, error) {
	fingerprint := ""
	targetAddr = strings.TrimSpace(targetAddr)
	targetAddr = strings.TrimPrefix(targetAddr, "http://")
	targetAddr = strings.TrimPrefix(targetAddr, "https://")
	if idx := strings.Index(targetAddr, "#"); idx != -1 {
		fragment := strings.Split(targetAddr[idx+1:], "@")
		if len(fragment) == 2 {
			fingerprint = strings.TrimSpace(fragment[1])
			if pin == "" {
				pin = strings.TrimSpace(fragment[0])
			}
		}
		targetAddr = strings.TrimSpace(targetAddr[:idx])
	}
	if !strings.Contains(targetAddr, ":") {
		targetAddr = fmt.Sprintf("%s:%d", targetAddr, m.httpPort)
	}
	if fingerprint == "" {
		return nil, errors.New("complete pairing string with device fingerprint required")
	}
	if pin == "" {
		return nil, errors.New("6-digit pairing PIN is required")
	}

	if _, _, err := net.SplitHostPort(targetAddr); err != nil {
		return nil, errors.New("invalid device address")
	}
	client, err := crypto.PinnedClient(fingerprint, 8*time.Second)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	sharedSecret := crypto.GenerateSharedSecret()
	reqPayload := PairRequest{
		PeerID:       m.identity.PeerID(),
		Name:         m.identity.Name(),
		OS:           m.identity.OS(),
		PublicKeyHex: m.identity.PublicKeyHex(),
		SharedKeyHex: sharedSecret,
		HTTPPort:     m.httpPort,
		PIN:          pin,
	}
	proof, _ := json.Marshal(reqPayload)
	reqPayload.Signature = m.identity.SignPairing(proof)
	body, _ := json.Marshal(reqPayload)
	url := fmt.Sprintf("https://%s/api/p2p/pair", targetAddr)

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("connect to %s failed: %w", targetAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("pairing rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var pairResp PairResponse
	if err := json.NewDecoder(resp.Body).Decode(&pairResp); err != nil {
		return nil, fmt.Errorf("invalid pair response: %w", err)
	}

	if !crypto.ValidPeerIdentity(pairResp.PeerID, pairResp.PublicKeyHex) {
		return nil, errors.New("invalid paired identity")
	}
	pub, _ := hex.DecodeString(pairResp.PublicKeyHex)
	fp := sha256.Sum256(pub)
	if hex.EncodeToString(fp[:]) != fingerprint {
		return nil, errors.New("pair response identity mismatch")
	}
	peer := crypto.TrustedPeer{
		PeerID:       pairResp.PeerID,
		Name:         pairResp.Name,
		OS:           pairResp.OS,
		PublicKeyHex: pairResp.PublicKeyHex,
		SharedKeyHex: sharedSecret,
		LastAddr:     targetAddr,
		PairedAt:     time.Now().UnixMilli(),
		LastSeen:     time.Now().UnixMilli(),
		Online:       true,
	}
	if err := m.identity.AddOrUpdateTrustedPeer(peer); err != nil {
		return nil, err
	}
	if m.onPeerChange != nil {
		m.onPeerChange()
	}
	return &peer, nil
}

func (m *MeshEngine) trustedHeartbeatLoop() {
	defer m.wg.Done()
	// Run an initial check shortly after startup
	select {
	case <-m.ctx.Done():
		return
	case <-time.After(500 * time.Millisecond):
	}
	m.checkAllTrustedPeers()

	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkAllTrustedPeers()
		}
	}
}

func (m *MeshEngine) checkAllTrustedPeers() {
	peers := m.identity.ListTrustedPeers()
	if len(peers) == 0 {
		return
	}
	changed := false
	for _, p := range peers {
		wasOnline := p.Online
		ok := false
		if p.LastAddr != "" {
			ok = m.pingTrustedPeer(p.PeerID, p.LastAddr)
		}
		if !ok {
			m.identity.SetPeerOnline(p.PeerID, p.LastAddr, false)
			// Send opaque 50-byte HMAC silent probe in case DHCP changed the trusted peer's IP
			m.sendSilentProbe(p.PeerID)
		}
		if !wasOnline && ok {
			m.retryFailed(p.PeerID)
		}
		if wasOnline != ok {
			changed = true
		}
	}
	if changed && m.onPeerChange != nil {
		m.onPeerChange()
	}
}

func (m *MeshEngine) sendSilentProbe(targetPeerID string) {
	if m.udpConn == nil {
		return
	}
	pkt, err := m.identity.MakeSilentProbePacket(targetPeerID, m.httpPort)
	if err != nil {
		return
	}
	for _, dst := range getBroadcastAddrs(m.udpPort) {
		_, _ = m.udpConn.WriteToUDP(pkt, dst)
	}
}

func (m *MeshEngine) pingTrustedPeer(peerID string, addr string) bool {
	payload := map[string]any{
		"peer_id":   m.identity.PeerID(),
		"name":      m.identity.Name(),
		"os":        m.identity.OS(),
		"http_port": m.httpPort,
	}
	body, _ := json.Marshal(payload)
	resp, err := m.doSignedPost(peerID, addr, "/api/p2p/ping", body)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		m.identity.SetPeerOnline(peerID, addr, true)
		return true
	}
	return false
}

type deliveryJob struct{ id, peer string }

func (m *MeshEngine) SetDeliveryCallback(cb func(string, map[string]string)) { m.onDelivery = cb }

// PrepareDelivery reserves bounded recipient metadata before storing the message.
func (m *MeshEngine) PrepareDelivery(msg *store.Message) {
	msg.Delivery = map[string]string{}
	for _, p := range m.identity.ListTrustedPeers() {
		if msg.TargetPeerID == "" || msg.TargetPeerID == p.PeerID {
			msg.Delivery[p.PeerID] = "pending"
		}
	}
}
func (m *MeshEngine) PushMessageToPeers(msg *store.Message) {
	for peer := range msg.Delivery {
		m.enqueue(deliveryJob{msg.ID, peer})
	}
}
func (m *MeshEngine) enqueue(job deliveryJob) {
	select {
	case <-m.ctx.Done():
		return
	default:
	}
	select {
	case m.jobs <- job:
	default:
		m.deliveryStatus(job, "failed")
	}
}
func (m *MeshEngine) deliveryStatus(job deliveryJob, status string) {
	if m.ring.SetDelivery(job.id, job.peer, status) && m.onDelivery != nil {
		if msg, ok := m.ring.GetMessage(job.id); ok {
			m.onDelivery(job.id, msg.Delivery)
		}
	}
}
func (m *MeshEngine) retryFailed(peer string) {
	for _, msg := range m.ring.List(m.identity.PeerID()) {
		if msg.SenderID == m.identity.PeerID() && msg.Delivery[peer] == "failed" {
			job := deliveryJob{msg.ID, peer}
			m.deliveryStatus(job, "pending")
			m.enqueue(job)
		}
	}
}
func (m *MeshEngine) RetryMessage(id string) bool {
	msg, ok := m.ring.GetMessage(id)
	if !ok || msg.SenderID != m.identity.PeerID() {
		return false
	}
	for peer, status := range msg.Delivery {
		if status == "failed" {
			job := deliveryJob{id, peer}
			m.deliveryStatus(job, "pending")
			m.enqueue(job)
		}
	}
	return true
}
func (m *MeshEngine) deliveryWorker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case job := <-m.jobs:
			success := false
			for attempt := 0; attempt < 3; attempt++ {
				msg, exists := m.ring.GetMessage(job.id)
				if !exists {
					break
				}
				peer, trusted := m.identity.GetTrustedPeer(job.peer)
				if !trusted {
					break
				}
				wire := WireMessage{Message: msg}
				wire.Message.Delivery = nil
				if msg.Kind == store.KindImage {
					wire.InlineDataBase64 = base64.StdEncoding.EncodeToString(msg.InlineData)
				}
				body, err := json.Marshal(wire)
				if err != nil {
					break
				}
				resp, err := m.doSignedPost(peer.PeerID, peer.LastAddr, "/api/p2p/message", body)
				if err == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						success = true
						break
					}
					if resp.StatusCode >= 400 && resp.StatusCode < 500 {
						break
					}
				}
				if attempt < 2 {
					select {
					case <-m.ctx.Done():
						return
					case <-time.After(time.Duration(attempt+1) * time.Second):
					}
				}
			}
			if success {
				m.deliveryStatus(job, "delivered")
			} else {
				m.deliveryStatus(job, "failed")
			}
		}
	}
}

// BroadcastClear instructs all trusted peers to clear their in-memory message buffers too.
func (m *MeshEngine) BroadcastClear() {
	body := []byte(`{"action":"clear"}`)
	for _, p := range m.identity.ListTrustedPeers() {
		if p.LastAddr == "" {
			continue
		}
		go func(peer crypto.TrustedPeer) {
			if resp, err := m.doSignedPost(peer.PeerID, peer.LastAddr, "/api/p2p/clear", body); err == nil {
				_ = resp.Body.Close()
			}
		}(p)
	}
}

func (m *MeshEngine) doSignedPost(targetPeerID string, addr string, path string, body []byte) (*http.Response, error) {
	ts := time.Now().UnixMilli()
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	nonce := crypto.GenerateSharedSecret()[:32]
	sig, err := m.identity.SignPeerRequest(targetPeerID, ts, http.MethodPost, path, nonce, bodyHash)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(m.ctx, http.MethodPost, fmt.Sprintf("https://%s%s", addr, path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LanChat-Peer", m.identity.PeerID())
	req.Header.Set("X-LanChat-Ts", strconv.FormatInt(ts, 10))
	req.Header.Set("X-LanChat-Sig", sig)
	req.Header.Set("X-LanChat-Port", strconv.Itoa(m.httpPort))
	req.Header.Set("X-LanChat-Nonce", nonce)
	client, err := m.identity.PeerClient(targetPeerID, 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	return client.Do(req)
}

// GetLANIPs returns all non-loopback IPv4 addresses of the current machine.
func GetLANIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{"127.0.0.1"}
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil || ip4.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ip4.String())
		}
	}
	if len(ips) == 0 {
		ips = append(ips, "127.0.0.1")
	}
	return ips
}

func selectBestIPForRemote(remoteIP net.IP) string {
	ips := GetLANIPs()
	if r4 := remoteIP.To4(); r4 != nil {
		prefix := fmt.Sprintf("%d.%d.%d.", r4[0], r4[1], r4[2])
		for _, ip := range ips {
			if strings.HasPrefix(ip, prefix) {
				return ip
			}
		}
	}
	return ips[0]
}

func getBroadcastAddrs(port int) []*net.UDPAddr {
	seen := make(map[string]bool)
	var out []*net.UDPAddr

	add := func(ip net.IP) {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, &net.UDPAddr{IP: ip, Port: port})
		}
	}
	add(net.IPv4bcast)

	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ip4 := ipnet.IP.To4()
				mask := ipnet.Mask
				if ip4 != nil && len(mask) == 4 {
					bcast := net.IPv4(
						ip4[0]|^mask[0],
						ip4[1]|^mask[1],
						ip4[2]|^mask[2],
						ip4[3]|^mask[3],
					)
					add(bcast)
				}
			}
		}
	}
	return out
}
