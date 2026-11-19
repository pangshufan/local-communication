package p2p

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lanchat/internal/crypto"
	"lanchat/internal/store"
)

func TestDeliveryFailureAndExplicitRetry(t *testing.T) {
	a, e := crypto.LoadOrCreateIdentity(t.TempDir(), "a")
	if e != nil {
		t.Fatal(e)
	}
	b, e := crypto.LoadOrCreateIdentity(t.TempDir(), "b")
	if e != nil {
		t.Fatal(e)
	}
	var allow atomic.Bool
	var attempts atomic.Int32
	cfg, e := b.TLSConfig(nil)
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if !allow.Load() {
			http.Error(w, "rejected", 403)
			return
		}
		w.Write([]byte(`{"added":true}`))
	})}
	go server.Serve(tls.NewListener(ln, cfg))
	defer server.Close()
	if e := a.AddOrUpdateTrustedPeer(crypto.TrustedPeer{PeerID: b.PeerID(), PublicKeyHex: b.PublicKeyHex(), SharedKeyHex: crypto.GenerateSharedSecret(), LastAddr: ln.Addr().String()}); e != nil {
		t.Fatal(e)
	}
	rb := store.NewRingBuffer(20, 1<<20, 1<<16, nil)
	m := NewMeshEngine(a, rb, 1, 0, nil, nil)
	m.Start()
	defer m.Stop()
	msg := &store.Message{ID: "msg_test", Kind: store.KindText, SenderID: a.PeerID(), Text: "retry"}
	m.PrepareDelivery(msg)
	rb.Add(msg)
	m.PushMessageToPeers(msg)
	wait := func(status string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if x, ok := rb.GetMessage(msg.ID); ok && x.Delivery[b.PeerID()] == status {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("delivery did not reach %s", status)
	}
	wait("failed")
	if p, _ := a.GetTrustedPeer(b.PeerID()); p.Online {
		t.Fatal("HTTP 403 marked peer online")
	}
	allow.Store(true)
	if !m.RetryMessage(msg.ID) {
		t.Fatal("retry rejected")
	}
	wait("delivered")
	if attempts.Load() < 2 {
		t.Fatal("retry not sent")
	}
	if m.RetryMessage("missing") {
		t.Fatal("retried missing message")
	}
	// Pairing without an out-of-band pin must fail before transmitting the PIN.
	if _, e := m.PairWithPeer(fmt.Sprintf("%s#123456", ln.Addr().String()), ""); e == nil || !strings.Contains(e.Error(), "fingerprint") {
		t.Fatal("missing fingerprint accepted", e)
	}
}
