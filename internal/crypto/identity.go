package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// TrustedPeer represents a paired device that is authorized to communicate and auto-connect silently.
type TrustedPeer struct {
	PeerID       string `json:"peer_id"`
	Name         string `json:"name"`
	OS           string `json:"os"`
	PublicKeyHex string `json:"public_key_hex"`
	SharedKeyHex string `json:"shared_key_hex"` // 32-byte symmetric shared secret established during pairing
	LastAddr     string `json:"last_addr"`      // Last known IP:Port
	PairedAt     int64  `json:"paired_at"`
	LastSeen     int64  `json:"last_seen"`
	Online       bool   `json:"online"`
}

type persistedIdentity struct {
	PeerID        string                  `json:"peer_id"`
	Name          string                  `json:"name"`
	PublicKeyHex  string                  `json:"public_key_hex"`
	PrivateKeyHex string                  `json:"private_key_hex"`
	MobileSecret  string                  `json:"mobile_secret"`
	TrustedPeers  map[string]*TrustedPeer `json:"trusted_peers"`
}

// IdentityManager manages device identity, the Discoverable Mode switch, pairing PIN, and trusted peers.
type IdentityManager struct {
	mu               sync.RWMutex
	configPath       string
	peerID           string
	name             string
	osName           string
	pubKey           ed25519.PublicKey
	privKey          ed25519.PrivateKey
	mobileSecret     []byte
	trustedPeers     map[string]*TrustedPeer
	discoverableTill time.Time
	pairingPIN       string
}

// LoadOrCreateIdentity initializes the node's identity and loads its trusted device list (if any).
func LoadOrCreateIdentity(configDir string, customName string) (*IdentityManager, error) {
	if configDir == "" {
		userCfg, err := os.UserConfigDir()
		if err != nil {
			userCfg = os.TempDir()
		}
		configDir = filepath.Join(userCfg, "lanchat")
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	cfgPath := filepath.Join(configDir, "identity.json")
	im := &IdentityManager{
		configPath:   cfgPath,
		osName:       runtime.GOOS,
		trustedPeers: make(map[string]*TrustedPeer),
	}

	if data, err := os.ReadFile(cfgPath); err == nil {
		var p persistedIdentity
		if json.Unmarshal(data, &p) == nil && p.PeerID != "" && p.PrivateKeyHex != "" {
			pub, err1 := hex.DecodeString(p.PublicKeyHex)
			priv, err2 := hex.DecodeString(p.PrivateKeyHex)
			mob, err3 := hex.DecodeString(p.MobileSecret)
			if err1 == nil && err2 == nil && err3 == nil && len(priv) == ed25519.PrivateKeySize {
				im.peerID = p.PeerID
				im.name = p.Name
				im.pubKey = ed25519.PublicKey(pub)
				im.privKey = ed25519.PrivateKey(priv)
				im.mobileSecret = mob
				if p.TrustedPeers != nil {
					for k, v := range p.TrustedPeers {
						v.Online = false
						im.trustedPeers[k] = v
					}
				}
				if customName != "" && customName != im.name {
					im.name = customName
					_ = im.saveLocked()
				}
				return im, nil
			}
		}
	}

	// Generate fresh identity
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(pub)
	im.peerID = hex.EncodeToString(hash[:8]) // 16-hex-char compact unique node ID
	im.pubKey = pub
	im.privKey = priv
	im.mobileSecret = make([]byte, 32)
	_, _ = rand.Read(im.mobileSecret)

	if customName != "" {
		im.name = customName
	} else {
		host, err := os.Hostname()
		if err != nil || host == "" {
			host = "Node-" + im.peerID[:6]
		}
		im.name = fmt.Sprintf("%s (%s)", host, runtime.GOOS)
	}

	if err := im.saveLocked(); err != nil {
		return nil, err
	}
	return im, nil
}

func (im *IdentityManager) saveLocked() error {
	p := persistedIdentity{
		PeerID:        im.peerID,
		Name:          im.name,
		PublicKeyHex:  hex.EncodeToString(im.pubKey),
		PrivateKeyHex: hex.EncodeToString(im.privKey),
		MobileSecret:  hex.EncodeToString(im.mobileSecret),
		TrustedPeers:  im.trustedPeers,
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(im.configPath, data, 0600)
}

func (im *IdentityManager) PeerID() string {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.peerID
}

func (im *IdentityManager) Name() string {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.name
}

func (im *IdentityManager) SetName(name string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if name != "" {
		im.name = name
		_ = im.saveLocked()
	}
}

func (im *IdentityManager) OS() string {
	return im.osName
}

func (im *IdentityManager) PublicKeyHex() string {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return hex.EncodeToString(im.pubKey)
}

// SetDiscoverable turns on or off the "Allow Discovery" switch.
// By default on startup, discoverable mode is OFF (0 public broadcast response).
func (im *IdentityManager) SetDiscoverable(enabled bool, duration time.Duration) (pin string, until time.Time) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if !enabled {
		im.discoverableTill = time.Time{}
		im.pairingPIN = ""
		return "", time.Time{}
	}
	if duration <= 0 {
		duration = 3 * time.Minute
	}
	im.discoverableTill = time.Now().Add(duration)
	if im.pairingPIN == "" {
		im.pairingPIN = generate6DigitPIN()
	}
	return im.pairingPIN, im.discoverableTill
}

// DiscoverableState returns whether the node is currently open for discovery, its pairing PIN, and remaining seconds.
// Note: A static pairing PIN is also available on the local UI for direct IP:Port#PIN connection even when UDP discovery is OFF.
func (im *IdentityManager) DiscoverableState() (enabled bool, pin string, remainingSec int64) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if im.pairingPIN == "" {
		im.pairingPIN = generate6DigitPIN()
	}
	now := time.Now()
	if im.discoverableTill.After(now) {
		return true, im.pairingPIN, int64(im.discoverableTill.Sub(now).Seconds())
	}
	return false, im.pairingPIN, 0
}

// RotatePIN generates a fresh 6-digit pairing PIN.
func (im *IdentityManager) RotatePIN() string {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.pairingPIN = generate6DigitPIN()
	return im.pairingPIN
}

// VerifyPIN checks whether a candidate PIN matches the current pairing PIN.
func (im *IdentityManager) VerifyPIN(candidate string) bool {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.pairingPIN != "" && hmac.Equal([]byte(im.pairingPIN), []byte(candidate))
}

func generate6DigitPIN() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "123456"
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

// AddOrUpdateTrustedPeer saves a paired peer and persists the trust list.
func (im *IdentityManager) AddOrUpdateTrustedPeer(p TrustedPeer) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	existing, ok := im.trustedPeers[p.PeerID]
	if ok {
		if p.Name != "" {
			existing.Name = p.Name
		}
		if p.OS != "" {
			existing.OS = p.OS
		}
		if p.PublicKeyHex != "" {
			existing.PublicKeyHex = p.PublicKeyHex
		}
		if p.SharedKeyHex != "" {
			existing.SharedKeyHex = p.SharedKeyHex
		}
		if p.LastAddr != "" {
			existing.LastAddr = p.LastAddr
		}
		existing.LastSeen = time.Now().UnixMilli()
		existing.Online = p.Online
	} else {
		if p.PairedAt == 0 {
			p.PairedAt = time.Now().UnixMilli()
		}
		p.LastSeen = time.Now().UnixMilli()
		im.trustedPeers[p.PeerID] = &p
	}
	return im.saveLocked()
}

// RemoveTrustedPeer unpairs and removes a peer from the trusted list.
func (im *IdentityManager) RemoveTrustedPeer(peerID string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	delete(im.trustedPeers, peerID)
	_ = im.saveLocked()
}

// SetPeerOnline updates the live online state and address of a trusted peer.
func (im *IdentityManager) SetPeerOnline(peerID string, addr string, online bool) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if p, ok := im.trustedPeers[peerID]; ok {
		p.Online = online
		if addr != "" {
			p.LastAddr = addr
		}
		if online {
			p.LastSeen = time.Now().UnixMilli()
		}
	}
}

// ListTrustedPeers returns a copy of all paired peers.
func (im *IdentityManager) ListTrustedPeers() []TrustedPeer {
	im.mu.RLock()
	defer im.mu.RUnlock()
	out := make([]TrustedPeer, 0, len(im.trustedPeers))
	for _, p := range im.trustedPeers {
		out = append(out, *p)
	}
	return out
}

// GetTrustedPeer returns a paired peer by ID.
func (im *IdentityManager) GetTrustedPeer(peerID string) (TrustedPeer, bool) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	p, ok := im.trustedPeers[peerID]
	if !ok {
		return TrustedPeer{}, false
	}
	return *p, true
}

// SignPeerRequest generates an HMAC-SHA256 authentication header for requests sent to a trusted peer.
func (im *IdentityManager) SignPeerRequest(targetPeerID string, timestampMs int64, bodyHash string) (string, error) {
	im.mu.RLock()
	peer, ok := im.trustedPeers[targetPeerID]
	myID := im.peerID
	im.mu.RUnlock()
	if !ok || peer.SharedKeyHex == "" {
		return "", errors.New("unknown or unpaired peer")
	}
	key, err := hex.DecodeString(peer.SharedKeyHex)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s:%s:%d:%s", myID, targetPeerID, timestampMs, bodyHash)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyPeerRequest verifies an incoming P2P request from a trusted peer within a +/- 5 minute clock skew window.
func (im *IdentityManager) VerifyPeerRequest(senderPeerID string, timestampMs int64, bodyHash string, signatureHex string) bool {
	diff := time.Now().UnixMilli() - timestampMs
	if diff < -5*60*1000 || diff > 5*60*1000 {
		return false
	}
	im.mu.RLock()
	peer, ok := im.trustedPeers[senderPeerID]
	myID := im.peerID
	im.mu.RUnlock()
	if !ok || peer.SharedKeyHex == "" {
		return false
	}
	key, err := hex.DecodeString(peer.SharedKeyHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s:%s:%d:%s", senderPeerID, myID, timestampMs, bodyHash)
	expected := mac.Sum(nil)
	got, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, got)
}

// MakeSilentProbePacket creates an opaque 48-byte UDP packet (`8B random nonce + 8B timestamp + 32B HMAC`)
// targeted at a specific trusted peer. Untrusted hosts on the LAN see only random noise.
func (im *IdentityManager) MakeSilentProbePacket(targetPeerID string, myPort int) ([]byte, error) {
	im.mu.RLock()
	peer, ok := im.trustedPeers[targetPeerID]
	myID := im.peerID
	im.mu.RUnlock()
	if !ok || peer.SharedKeyHex == "" {
		return nil, errors.New("peer not trusted")
	}
	key, err := hex.DecodeString(peer.SharedKeyHex)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 18+32)
	_, _ = rand.Read(buf[:8])
	binary.BigEndian.PutUint64(buf[8:16], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(buf[16:18], uint16(myPort))

	mac := hmac.New(sha256.New, key)
	mac.Write(buf[:18])
	mac.Write([]byte(myID + "->" + targetPeerID))
	copy(buf[18:], mac.Sum(nil))
	return buf, nil
}

// VerifySilentProbePacket checks if an incoming 50-byte opaque UDP packet was signed by one of our trusted peers.
func (im *IdentityManager) VerifySilentProbePacket(pkt []byte) (senderPeerID string, senderPort int, ok bool) {
	if len(pkt) != 50 {
		return "", 0, false
	}
	ts := int64(binary.BigEndian.Uint64(pkt[8:16]))
	now := time.Now().Unix()
	if now-ts > 60 || ts-now > 60 {
		return "", 0, false
	}
	port := int(binary.BigEndian.Uint16(pkt[16:18]))

	im.mu.RLock()
	defer im.mu.RUnlock()

	for pid, peer := range im.trustedPeers {
		key, err := hex.DecodeString(peer.SharedKeyHex)
		if err != nil {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(pkt[:18])
		mac.Write([]byte(pid + "->" + im.peerID))
		if hmac.Equal(pkt[18:], mac.Sum(nil)) {
			return pid, port, true
		}
	}
	return "", 0, false
}

// MobileAccessToken returns the HMAC token allowing a mobile browser (via QR scan) to connect to this node's WebUI.
func (im *IdentityManager) MobileAccessToken() string {
	im.mu.RLock()
	defer im.mu.RUnlock()
	mac := hmac.New(sha256.New, im.mobileSecret)
	mac.Write([]byte("lanchat-mobile-v1:" + im.peerID))
	return hex.EncodeToString(mac.Sum(nil))[:24]
}

// VerifyMobileToken checks if the mobile token from query/cookie/header is valid.
func (im *IdentityManager) VerifyMobileToken(token string) bool {
	if token == "" {
		return false
	}
	expected := im.MobileAccessToken()
	return hmac.Equal([]byte(expected), []byte(token))
}

// GenerateSharedSecret creates a new 32-byte hex-encoded shared secret during device pairing.
func GenerateSharedSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
