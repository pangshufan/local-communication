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
	DefaultHTTPPort  = 32520
	DefaultUDPPort   = 32525
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
	probes       chan struct{}
	onDelivery   func(string, map[string]string)
	stopOnce     sync.Once
	wg           sync.WaitGroup
	taskMu       sync.Mutex
	retryMu      sync.Mutex
	offline      map[string]peerRetry
	probePending map[string]bool
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
		ctx: ctx, cancel: cancel, jobs: make(chan deliveryJob, 256), probes: make(chan struct{}, 4),
		identity: im,
		offline:  make(map[string]peerRetry), probePending: make(map[string]bool),
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

// BeginShutdown stops scheduling work before HTTP servers are drained.
func (m *MeshEngine) BeginShutdown() {
	m.taskMu.Lock()
	defer m.taskMu.Unlock()
	m.stopOnce.Do(func() {
		close(m.stopCh)
		m.cancel()
		if m.udpConn != nil {
			m.udpConn.Close()
		}
	})
}
func (m *MeshEngine) Stop() { m.BeginShutdown(); m.wg.Wait(); m.identity.ClosePeerConnections() }
func (m *MeshEngine) startTask(fn func()) bool {
	m.taskMu.Lock()
	defer m.taskMu.Unlock()
	if m.ctx.Err() != nil {
		return false
	}
	m.wg.Add(1)
	go func() { defer m.wg.Done(); fn() }()
	return true
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
				m.startProbePing(senderPeerID, peerAddr)

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
	stop := context.AfterFunc(m.ctx, func() { conn.Close() })
	defer stop()
	if m.ctx.Err() != nil {
		return nil, m.ctx.Err()
	}

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

	if m.ctx.Err() != nil {
		return nil, m.ctx.Err()
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

	request, err := http.NewRequestWithContext(m.ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
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
		if m.ctx.Err() != nil {
			return
		}
		if !m.heartbeatDue(p.PeerID, time.Now()) {
			continue
		}
		wasOnline := p.Online
		ok := false
		if p.LastAddr != "" {
			ok = m.pingTrustedPeer(p.PeerID, p.LastAddr)
		}
		if !ok {
			m.recordHeartbeat(p.PeerID, false, time.Now())
			m.identity.SetPeerOnline(p.PeerID, p.LastAddr, false)
			// Send opaque 50-byte HMAC silent probe in case DHCP changed the trusted peer's IP
			m.sendSilentProbe(p.PeerID)
		}
		if ok {
			m.recordHeartbeat(p.PeerID, true, time.Now())
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
	if finishControlResponse(resp) != nil {
		return false
	}
	if resp.StatusCode == http.StatusOK {
		_, _, err := m.identity.UpdatePeerHeartbeat(crypto.TrustedPeer{PeerID: peerID, LastAddr: addr})
		return err == nil
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
					drainErr := finishControlResponse(resp)
					if resp.StatusCode == http.StatusOK && drainErr == nil {
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
		peer := p
		m.startTask(func() {
			select {
			case m.probes <- struct{}{}:
				defer func() { <-m.probes }()
			case <-m.ctx.Done():
				return
			}
			if resp, err := m.doSignedPost(peer.PeerID, peer.LastAddr, "/api/p2p/clear", body); err == nil {
				_ = finishControlResponse(resp)
			}
		})
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
	return client.Do(req)
}

func (m *MeshEngine) PeerAvailable(peerID string) {
	m.recordHeartbeat(peerID, true, time.Now())
	m.retryFailed(peerID)
}

// Bound error response draining; ordinary control replies are tiny. Oversized
// or stalled responses are closed instead of consuming unbounded resources.
func finishControlResponse(resp *http.Response) error {
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return err
	}
	if n > 64*1024 {
		return errors.New("control response exceeds limit")
	}
	return nil
}

type peerRetry struct {
	failures int
	next     time.Time
}

func retryDelay(failures int) time.Duration {
	d := 8 * time.Second
	for i := 1; i < failures && d < 2*time.Minute; i++ {
		d *= 2
	}
	if d > 2*time.Minute {
		d = 2 * time.Minute
	}
	return d
}
func (m *MeshEngine) heartbeatDue(peer string, now time.Time) bool {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	return !m.offline[peer].next.After(now)
}
func (m *MeshEngine) recordHeartbeat(peer string, success bool, now time.Time) {
	m.retryMu.Lock()
	defer m.retryMu.Unlock()
	if success {
		delete(m.offline, peer)
		return
	}
	r := m.offline[peer]
	if r.failures < 8 {
		r.failures++
	}
	r.next = now.Add(retryDelay(r.failures))
	m.offline[peer] = r
}
func (m *MeshEngine) startProbePing(id, addr string) {
	m.retryMu.Lock()
	if m.probePending[id] {
		m.retryMu.Unlock()
		return
	}
	m.probePending[id] = true
	m.retryMu.Unlock()
	release := func() { m.retryMu.Lock(); delete(m.probePending, id); m.retryMu.Unlock() }
	select {
	case m.probes <- struct{}{}:
	default:
		release()
		return
	}
	if !m.startTask(func() {
		defer release()
		defer func() { <-m.probes }()
		if m.pingTrustedPeer(id, addr) {
			m.PeerAvailable(id)
			if m.onPeerChange != nil {
				m.onPeerChange()
			}
		}
	}) {
		<-m.probes
		release()
	}
}
