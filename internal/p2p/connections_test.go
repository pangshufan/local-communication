package p2p

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lanchat/internal/crypto"
	"lanchat/internal/store"
)

func TestControlRequestsReuseTLSConnectionAndCloseOnStop(t *testing.T) {
	a, err := crypto.LoadOrCreateIdentity(t.TempDir(), "a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.LoadOrCreateIdentity(t.TempDir(), "b")
	if err != nil {
		t.Fatal(err)
	}
	var connections, closed atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"ok\":true}\n"))
	}))
	cfg, err := b.TLSConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = cfg
	ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
		if state == http.StateClosed {
			closed.Add(1)
		}
	}
	ts.StartTLS()
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "https://")
	if err := a.AddOrUpdateTrustedPeer(crypto.TrustedPeer{PeerID: b.PeerID(), PublicKeyHex: b.PublicKeyHex(), SharedKeyHex: crypto.GenerateSharedSecret(), LastAddr: addr}); err != nil {
		t.Fatal(err)
	}
	m := NewMeshEngine(a, store.NewRingBuffer(20, 1<<20, 1<<16, nil), 32520, 32525, nil, nil)
	defer m.Stop()
	control, _ := a.PeerClient(b.PeerID(), 4*time.Second)
	stream, _ := a.PeerClient(b.PeerID(), 0)
	if control.Transport != stream.Transport {
		t.Fatal("file and control requests do not share a transport")
	}
	transport := control.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("LAN transport uses system proxy")
	}
	for i := 0; i < 20; i++ {
		if !m.pingTrustedPeer(b.PeerID(), addr) {
			t.Fatal("heartbeat failed", i)
		}
	}
	m.BroadcastClear()
	m.wg.Wait()
	if connections.Load() != 1 {
		t.Fatalf("21 control requests opened %d TCP connections, want 1", connections.Load())
	}
	m.Stop()
	deadline := time.Now().Add(time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Fatal("Stop left idle TLS connection open")
	}
}
func TestStopCancelsInflightHeartbeat(t *testing.T) {
	a, _ := crypto.LoadOrCreateIdentity(t.TempDir(), "a")
	b, _ := crypto.LoadOrCreateIdentity(t.TempDir(), "b")
	started := make(chan struct{})
	canceled := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	cfg, _ := b.TLSConfig(nil)
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "https://")
	a.AddOrUpdateTrustedPeer(crypto.TrustedPeer{PeerID: b.PeerID(), PublicKeyHex: b.PublicKeyHex(), SharedKeyHex: crypto.GenerateSharedSecret(), LastAddr: addr})
	m := NewMeshEngine(a, store.NewRingBuffer(20, 1<<20, 1<<16, nil), 1, 32525, nil, nil)
	m.startTask(func() { m.pingTrustedPeer(b.PeerID(), addr) })
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat did not start")
	}
	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop waited for heartbeat timeout")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("remote request remained active after Stop")
	}
	if m.startTask(func() { t.Error("work scheduled after stop") }) {
		t.Fatal("accepted work after shutdown")
	}
}
func TestOversizedHeartbeatResponseIsRejected(t *testing.T) {
	a, _ := crypto.LoadOrCreateIdentity(t.TempDir(), "a")
	b, _ := crypto.LoadOrCreateIdentity(t.TempDir(), "b")
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 128*1024))) }))
	cfg, _ := b.TLSConfig(nil)
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "https://")
	a.AddOrUpdateTrustedPeer(crypto.TrustedPeer{PeerID: b.PeerID(), PublicKeyHex: b.PublicKeyHex(), SharedKeyHex: crypto.GenerateSharedSecret(), LastAddr: addr})
	m := NewMeshEngine(a, store.NewRingBuffer(20, 1<<20, 1<<16, nil), 1, 32525, nil, nil)
	defer m.Stop()
	if m.pingTrustedPeer(b.PeerID(), addr) {
		t.Fatal("oversized response marked peer online")
	}
}
