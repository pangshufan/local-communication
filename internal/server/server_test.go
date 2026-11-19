package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lanchat/internal/crypto"
	"lanchat/internal/store"
	"lanchat/internal/web"
)

func startTestNode(t *testing.T, name string) (*AppServer, *crypto.IdentityManager, *store.RingBuffer, int, func()) {
	t.Helper()
	cfgDir := t.TempDir()
	spoolDir := t.TempDir()
	im, err := crypto.LoadOrCreateIdentity(cfgDir, name)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	rb := store.NewRingBuffer(50, 5*1024*1024, 1*1024*1024, nil)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	staticFS, err := web.StaticFS()
	if err != nil {
		t.Fatalf("StaticFS: %v", err)
	}
	srv := NewAppServer(im, rb, port, 0, spoolDir, staticFS)
	_ = srv.StartMesh()

	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() {
		cfg, err := im.TLSConfig(nil)
		if err != nil {
			t.Error(err)
			return
		}
		_ = httpSrv.Serve(tls.NewListener(ln, cfg))
	}()

	cleanup := func() {
		_ = httpSrv.Close()
		srv.Stop()
	}
	return srv, im, rb, port, cleanup
}

func TestTwoNodesPairingChatAndZeroCopyFileStream(t *testing.T) {
	_, imA, rbA, portA, cleanA := startTestNode(t, "Node-Mac")
	defer cleanA()

	srvB, imB, rbB, portB, cleanB := startTestNode(t, "Node-Linux")
	defer cleanB()
	clientA, err := crypto.PinnedClient(imA.Fingerprint(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientA.CloseIdleConnections()
	clientB, err := crypto.PinnedClient(imB.Fingerprint(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientB.CloseIdleConnections()

	// 1. Default stealth mode: verify discoverable is OFF by default
	enabledA, pinA, _ := imA.DiscoverableState()
	if enabledA {
		t.Fatalf("expected Node A discoverable mode to be OFF by default")
	}
	if len(pinA) != 6 {
		t.Fatalf("expected 6-digit PIN on Node A, got %q", pinA)
	}

	// 2. Pair Node B -> Node A using IP:Port#PIN (stealth direct pairing without broadcast)
	pairURI := fmt.Sprintf("127.0.0.1:%d#%s@%s", portA, pinA, imA.Fingerprint())
	peerA, err := srvB.mesh.PairWithPeer(pairURI, "")
	if err != nil {
		t.Fatalf("PairWithPeer failed: %v", err)
	}
	if peerA.PeerID != imA.PeerID() {
		t.Fatalf("expected paired PeerID %s, got %s", imA.PeerID(), peerA.PeerID)
	}

	// Verify mutual trust on both nodes
	if _, ok := imA.GetTrustedPeer(imB.PeerID()); !ok {
		t.Fatalf("expected Node A to trust Node B after pairing")
	}

	// 3. Send a public timeline text message on Node A and verify it arrives in Node B's ring buffer
	msgBody := []byte(`{"kind":"text","text":"Hello from Mac to Linux!"}`)
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/api/messages", portA), bytes.NewReader(msgBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := clientA.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("post message failed: err=%v status=%v", err, resp)
	}
	_ = resp.Body.Close()

	// Wait briefly for async P2P delivery
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(rbB.List(imB.PeerID())) == 1 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	msgsB := rbB.List(imB.PeerID())
	if len(msgsB) != 1 || msgsB[0].Text != "Hello from Mac to Linux!" {
		t.Fatalf("expected Node B to receive synced text message, got %+v", msgsB)
	}

	// 4. Test Zero-Copy Local File Registration on Node A and Stream Download via Node B Proxy
	sampleFile := filepath.Join(t.TempDir(), "test-archive.bin")
	sampleContent := bytes.Repeat([]byte("LANCHAT-ZERO-COPY-STREAM-TEST-"), 4096) // ~122 KB
	if err := os.WriteFile(sampleFile, sampleContent, 0600); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	regPayload, _ := json.Marshal(map[string]string{
		"file_path": sampleFile,
	})
	regResp, err := clientA.Post(fmt.Sprintf("https://127.0.0.1:%d/api/files/register-path", portA), "application/json", bytes.NewReader(regPayload))
	if err != nil || regResp.StatusCode != http.StatusOK {
		t.Fatalf("register local path failed: err=%v status=%v", err, regResp)
	}
	_ = regResp.Body.Close()

	// Wait for file card to sync to Node B
	var fileMsgB *store.Message
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range rbB.List(imB.PeerID()) {
			if m.Kind == store.KindFile && m.File != nil {
				fileMsgB = m
				break
			}
		}
		if fileMsgB != nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if fileMsgB == nil {
		t.Fatalf("expected file card to arrive on Node B")
	}

	// Download the file through Node B's proxy stream endpoint
	dlURL := fmt.Sprintf("https://127.0.0.1:%d%s", portB, fileMsgB.File.DownloadURL)
	dlResp, err := clientB.Get(dlURL)
	if err != nil || dlResp.StatusCode != http.StatusOK {
		t.Fatalf("proxy stream download failed: err=%v status=%v", err, dlResp)
	}
	downloaded, err := io.ReadAll(dlResp.Body)
	_ = dlResp.Body.Close()
	if err != nil || !bytes.Equal(downloaded, sampleContent) {
		t.Fatalf("downloaded file mismatch: got %d bytes, want %d bytes", len(downloaded), len(sampleContent))
	}

	// 5. Test All-Devices Memory Burn
	clearResp, err := clientA.Post(fmt.Sprintf("https://127.0.0.1:%d/api/messages/clear", portA), "application/json", bytes.NewReader([]byte(`{"all_devices":true}`)))
	if err != nil || clearResp.StatusCode != http.StatusOK {
		t.Fatalf("clear messages failed: %v", err)
	}
	_ = clearResp.Body.Close()

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rbA.Stats().CurrentMessages == 0 && rbB.Stats().CurrentMessages == 0 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if rbA.Stats().CurrentMessages != 0 || rbB.Stats().CurrentMessages != 0 {
		t.Fatalf("expected both nodes to have 0 messages after burn, got A=%d B=%d",
			rbA.Stats().CurrentMessages, rbB.Stats().CurrentMessages)
	}
}
