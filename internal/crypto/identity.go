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
	"net/http"
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
	pinExpires       time.Time
	seenProbes       map[[32]byte]time.Time
	peerClients      map[string]*http.Client
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
			if err1 == nil && err2 == nil && err3 == nil && len(priv) == ed25519.PrivateKeySize && len(pub) == ed25519.PublicKeySize && len(mob) == 32 && hmac.Equal(priv, ed25519.NewKeyFromSeed(priv[:32])) && hex.EncodeToString(sha256Sum(pub)[:8]) == p.PeerID && ed25519.PrivateKey(priv).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pub)) {
				im.peerID = p.PeerID
				im.name = p.Name
				im.pubKey = ed25519.PublicKey(pub)
				im.privKey = ed25519.PrivateKey(priv)
				im.mobileSecret = mob
				if p.TrustedPeers != nil {
					for k, v := range p.TrustedPeers {
						if v == nil || k != v.PeerID || !ValidPeerIdentity(v.PeerID, v.PublicKeyHex) || !validSecret(v.SharedKeyHex) {
							return nil, errors.New("invalid trusted peer in identity file")
						}
						v.Online = false
						im.trustedPeers[k] = v
					}
				}
				if customName != "" && customName != im.name {
					im.name = customName
					if err := im.saveLocked(); err != nil {
						return nil, err
					}
				}
				return im, nil
			}
		}
		return nil, errors.New("invalid identity file; restore a backup instead of silently replacing device identity")
	} else if !os.IsNotExist(err) {
		return nil, err
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
	f, err := os.CreateTemp(filepath.Dir(im.configPath), ".identity-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, im.configPath)
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
	if im.pairingPIN == "" || !im.pinExpires.After(time.Now()) {
		im.pairingPIN = generate6DigitPIN()
		im.pinExpires = time.Now().Add(3 * time.Minute)
	}
	return im.pairingPIN, im.discoverableTill
}

// DiscoverableState returns whether the node is currently open for discovery, its pairing PIN, and remaining seconds.
// Note: A static pairing PIN is also available on the local UI for direct IP:Port#PIN connection even when UDP discovery is OFF.
func (im *IdentityManager) DiscoverableState() (enabled bool, pin string, remainingSec int64) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if im.pairingPIN == "" || !im.pinExpires.After(time.Now()) {
		im.pairingPIN = generate6DigitPIN()
		im.pinExpires = time.Now().Add(3 * time.Minute)
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
	im.pinExpires = time.Now().Add(3 * time.Minute)
	return im.pairingPIN
}

// VerifyPIN checks whether a candidate PIN matches the current pairing PIN.
func (im *IdentityManager) VerifyPIN(candidate string) bool {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.pinExpires.After(time.Now()) && im.pairingPIN != "" && hmac.Equal([]byte(im.pairingPIN), []byte(candidate))
}

func generate6DigitPIN() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		panic("crypto/rand unavailable")
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

// AddOrUpdateTrustedPeer saves a paired peer and persists the trust list.
func (im *IdentityManager) AddOrUpdateTrustedPeer(p TrustedPeer) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	existing, ok := im.trustedPeers[p.PeerID]
	if len(p.Name) > 256 || len(p.OS) > 32 || len(p.LastAddr) > 256 {
		return errors.New("peer fields too long")
	}
	if !ok && (len(im.trustedPeers) >= 64 || !ValidPeerIdentity(p.PeerID, p.PublicKeyHex) || !validSecret(p.SharedKeyHex)) {
		return errors.New("invalid peer identity or device limit reached")
	}
	if p.PublicKeyHex != "" && !ValidPeerIdentity(p.PeerID, p.PublicKeyHex) {
		return errors.New("peer key mismatch")
	}
	if p.SharedKeyHex != "" && !validSecret(p.SharedKeyHex) {
		return errors.New("invalid shared secret")
	}
	var previous TrustedPeer
	if ok {
		previous = *existing
	}
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
	if err := im.saveLocked(); err != nil {
		if ok {
			*existing = previous
		} else {
			delete(im.trustedPeers, p.PeerID)
		}
		return err
	}
	if !ok || previous.PublicKeyHex != p.PublicKeyHex && p.PublicKeyHex != "" || previous.SharedKeyHex != p.SharedKeyHex && p.SharedKeyHex != "" {
		im.closePeerClientLocked(p.PeerID)
	}
	return nil
}

// RemoveTrustedPeer unpairs and removes a peer from the trusted list.
func (im *IdentityManager) RemoveTrustedPeer(peerID string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	delete(im.trustedPeers, peerID)
	im.closePeerClientLocked(peerID)
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

// SignPeerRequest binds authentication to the protocol, method, path, nonce and body.
func (im *IdentityManager) SignPeerRequest(targetPeerID string, timestampMs int64, method, path, nonce, bodyHash string) (string, error) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	peer, ok := im.trustedPeers[targetPeerID]
	if !ok || !validSecret(peer.SharedKeyHex) {
		return "", errors.New("unknown or invalid peer")
	}
	return requestMAC(peer.SharedKeyHex, im.peerID, targetPeerID, timestampMs, method, path, nonce, bodyHash), nil
}

func requestMAC(secret, sender, target string, ts int64, method, path, nonce, hash string) string {
	key, _ := hex.DecodeString(secret)
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "lanchat-v2\n%s\n%s\n%d\n%s\n%s\n%s\n%s", sender, target, ts, method, path, nonce, hash)
	return hex.EncodeToString(mac.Sum(nil))
}

func (im *IdentityManager) VerifyPeerRequest(sender string, ts int64, method, path, nonce, hash, sig string) bool {
	now := time.Now().UnixMilli()
	if ts < now-60000 || ts > now+60000 || len(nonce) != 32 {
		return false
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return false
	}
	im.mu.RLock()
	defer im.mu.RUnlock()
	peer, ok := im.trustedPeers[sender]
	if !ok || !validSecret(peer.SharedKeyHex) {
		return false
	}
	expected := requestMAC(peer.SharedKeyHex, sender, im.peerID, ts, method, path, nonce, hash)
	return hmac.Equal([]byte(expected), []byte(sig))
}

// ConsumePIN prevents concurrent reuse of a successful pairing code.
func (im *IdentityManager) ConsumePIN(pin string) bool {
	im.mu.Lock()
	defer im.mu.Unlock()
	if !im.pinExpires.After(time.Now()) || im.pairingPIN == "" || !hmac.Equal([]byte(pin), []byte(im.pairingPIN)) {
		return false
	}
	im.pairingPIN = ""
	im.pinExpires = time.Time{}
	return true
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func ValidPeerIdentity(id, pubHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	return err == nil && len(pub) == ed25519.PublicKeySize && hex.EncodeToString(sha256Sum(pub)[:8]) == id
}
func validSecret(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 32 }

// MakeSilentProbePacket creates an opaque 50-byte UDP packet (nonce, timestamp, port and HMAC)
// targeted at a specific trusted peer. Untrusted hosts on the LAN see only random noise.
func (im *IdentityManager) MakeSilentProbePacket(targetPeerID string, myPort int) ([]byte, error) {
	im.mu.RLock()
	peer, ok := im.trustedPeers[targetPeerID]
	myID := im.peerID
	defer im.mu.RUnlock()
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
	if ts < now-60 || ts > now+60 {
		return "", 0, false
	}
	port := int(binary.BigEndian.Uint16(pkt[16:18]))

	im.mu.Lock()
	defer im.mu.Unlock()

	for pid, peer := range im.trustedPeers {
		key, err := hex.DecodeString(peer.SharedKeyHex)
		if err != nil {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(pkt[:18])
		mac.Write([]byte(pid + "->" + im.peerID))
		if hmac.Equal(pkt[18:], mac.Sum(nil)) {
			if port < 1 {
				return "", 0, false
			}
			if im.seenProbes == nil {
				im.seenProbes = make(map[[32]byte]time.Time)
			}
			for k, expiry := range im.seenProbes {
				if !expiry.After(time.Now()) {
					delete(im.seenProbes, k)
				}
			}
			key := sha256.Sum256(pkt)
			if _, seen := im.seenProbes[key]; seen || len(im.seenProbes) >= 4096 {
				return "", 0, false
			}
			im.seenProbes[key] = time.Now().Add(121 * time.Second)
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
	mac.Write([]byte(fmt.Sprintf("lanchat-mobile-v2:%s:%d", im.peerID, time.Now().Unix()/3600)))
	return hex.EncodeToString(mac.Sum(nil))[:24]
}

// VerifyMobileToken checks if the mobile token from query/cookie/header is valid.
func (im *IdentityManager) VerifyMobileToken(token string) bool {
	if token == "" {
		return false
	}
	im.mu.RLock()
	defer im.mu.RUnlock()
	for i := int64(0); i < 8; i++ {
		mac := hmac.New(sha256.New, im.mobileSecret)
		mac.Write([]byte(fmt.Sprintf("lanchat-mobile-v2:%s:%d", im.peerID, time.Now().Unix()/3600-i)))
		expected := hex.EncodeToString(mac.Sum(nil))[:24]
		if hmac.Equal([]byte(expected), []byte(token)) {
			return true
		}
	}
	return false
}

// GenerateSharedSecret creates a new 32-byte hex-encoded shared secret during device pairing.
func GenerateSharedSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (im *IdentityManager) RevokeMobile() error {
	im.mu.Lock()
	defer im.mu.Unlock()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	im.mobileSecret = secret
	return im.saveLocked()
}

func (im *IdentityManager) ConfigDir() string { return filepath.Dir(im.configPath) }

func (im *IdentityManager) SignPairing(data []byte) string {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return hex.EncodeToString(ed25519.Sign(im.privKey, data))
}
func VerifyPairing(pubHex string, data []byte, sigHex string) bool {
	pub, e := hex.DecodeString(pubHex)
	sig, e2 := hex.DecodeString(sigHex)
	return e == nil && e2 == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), data, sig)
}

// UpdatePeerHeartbeat persists only meaningful changes. Online/LastSeen remain
// volatile, so an unchanged heartbeat does not rewrite identity.json.
func (im *IdentityManager) UpdatePeerHeartbeat(update TrustedPeer) (becameOnline, changed bool, err error) {
	im.mu.Lock()
	defer im.mu.Unlock()
	p, ok := im.trustedPeers[update.PeerID]
	if !ok {
		return false, false, errors.New("unknown peer")
	}
	if len(update.Name) > 256 || len(update.OS) > 32 || len(update.LastAddr) > 256 {
		return false, false, errors.New("peer fields too long")
	}
	previous := *p
	metadataChanged := false
	if update.Name != "" && update.Name != p.Name {
		p.Name = update.Name
		metadataChanged = true
	}
	if update.OS != "" && update.OS != p.OS {
		p.OS = update.OS
		metadataChanged = true
	}
	if update.LastAddr != "" && update.LastAddr != p.LastAddr {
		p.LastAddr = update.LastAddr
		metadataChanged = true
	}
	p.Online = true
	p.LastSeen = time.Now().UnixMilli()
	if metadataChanged {
		if err := im.saveLocked(); err != nil {
			*p = previous
			return false, false, err
		}
	}
	if p.LastAddr != previous.LastAddr {
		im.closePeerClientLocked(update.PeerID)
	}
	return !previous.Online, metadataChanged || !previous.Online, nil
}
