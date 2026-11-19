package crypto

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testIdentity(t *testing.T) *IdentityManager {
	t.Helper()
	im, e := LoadOrCreateIdentity(t.TempDir(), "test")
	if e != nil {
		t.Fatal(e)
	}
	return im
}
func trust(t *testing.T, a, b *IdentityManager) {
	t.Helper()
	key := GenerateSharedSecret()
	for _, pair := range [][2]*IdentityManager{{a, b}, {b, a}} {
		if e := pair[0].AddOrUpdateTrustedPeer(TrustedPeer{PeerID: pair[1].PeerID(), PublicKeyHex: pair[1].PublicKeyHex(), SharedKeyHex: key}); e != nil {
			t.Fatal(e)
		}
	}
}
func TestRequestAuthenticationScopeAndTime(t *testing.T) {
	a, b := testIdentity(t), testIdentity(t)
	trust(t, a, b)
	now := time.Now().UnixMilli()
	nonce := strings.Repeat("ab", 16)
	sig, e := a.SignPeerRequest(b.PeerID(), now, "POST", "/api/p2p/ping", nonce, "hash")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, method, path, nonce, hash string
		ts                              int64
		valid                           bool
	}{
		{"valid", "POST", "/api/p2p/ping", nonce, "hash", now, true},
		{"cross endpoint", "POST", "/api/p2p/clear", nonce, "hash", now, false},
		{"method", "GET", "/api/p2p/ping", nonce, "hash", now, false},
		{"nonce", "POST", "/api/p2p/ping", strings.Repeat("cd", 16), "hash", now, false},
		{"body", "POST", "/api/p2p/ping", nonce, "tamper", now, false},
		{"expired", "POST", "/api/p2p/ping", nonce, "hash", now - 61000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if b.VerifyPeerRequest(a.PeerID(), tc.ts, tc.method, tc.path, tc.nonce, tc.hash, sig) != tc.valid {
				t.Fatal("incorrect authentication result")
			}
		})
	}
}
func TestPINConsumedOnceAndExpires(t *testing.T) {
	im := testIdentity(t)
	_, pin, _ := im.DiscoverableState()
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if im.ConsumePIN(pin) {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("PIN consumed more than once")
	}
	pin = im.RotatePIN()
	im.mu.Lock()
	im.pinExpires = time.Now().Add(-time.Second)
	im.mu.Unlock()
	if im.VerifyPIN(pin) || im.ConsumePIN(pin) {
		t.Fatal("expired PIN accepted")
	}
}
func TestIdentityPersistenceRejectsCorruption(t *testing.T) {
	dir := t.TempDir()
	im, e := LoadOrCreateIdentity(dir, "original")
	if e != nil {
		t.Fatal(e)
	}
	other, e := LoadOrCreateIdentity(dir, "")
	if e != nil || other.PeerID() != im.PeerID() {
		t.Fatal("identity did not persist")
	}
	file := filepath.Join(dir, "identity.json")
	if e := os.WriteFile(file, []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadOrCreateIdentity(dir, ""); e == nil {
		t.Fatal("silently replaced corrupt identity")
	}
	data, _ := os.ReadFile(file)
	if string(data) != "broken" {
		t.Fatal("corrupt file overwritten")
	}
}
func TestMobileRevocationAndPairProof(t *testing.T) {
	im := testIdentity(t)
	tok := im.MobileAccessToken()
	if !im.VerifyMobileToken(tok) {
		t.Fatal("token invalid")
	}
	if e := im.RevokeMobile(); e != nil {
		t.Fatal(e)
	}
	if im.VerifyMobileToken(tok) {
		t.Fatal("revoked token accepted")
	}
	data, _ := json.Marshal(map[string]string{"pin": "123456"})
	sig := im.SignPairing(data)
	if !VerifyPairing(im.PublicKeyHex(), data, sig) || VerifyPairing(im.PublicKeyHex(), []byte("tampered"), sig) {
		t.Fatal("invalid pairing proof verification")
	}
}
func TestTLSRejectsWrongDeviceAndPlaintext(t *testing.T) {
	im := testIdentity(t)
	cfg, e := im.TLSConfig(nil)
	if e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()
	client, e := PinnedClient(im.Fingerprint(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	resp, e := client.Get(ts.URL)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	wrong, _ := PinnedClient(testIdentity(t).Fingerprint(), time.Second)
	defer wrong.CloseIdleConnections()
	if resp, e := wrong.Get(ts.URL); e == nil {
		resp.Body.Close()
		t.Fatal("wrong device accepted")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS minimum weakened")
	}
}

func TestSilentProbeAuthenticationAndReplay(t *testing.T) {
	a, b := testIdentity(t), testIdentity(t)
	trust(t, a, b)
	packet, e := a.MakeSilentProbePacket(b.PeerID(), 52520)
	if e != nil {
		t.Fatal(e)
	}
	tampered := append([]byte(nil), packet...)
	tampered[0] ^= 1
	if _, _, ok := b.VerifySilentProbePacket(tampered); ok {
		t.Fatal("tampered probe accepted")
	}
	id, port, ok := b.VerifySilentProbePacket(packet)
	if !ok || id != a.PeerID() || port != 52520 {
		t.Fatal("valid probe rejected")
	}
	if _, _, ok := b.VerifySilentProbePacket(packet); ok {
		t.Fatal("probe replay accepted")
	}
}
