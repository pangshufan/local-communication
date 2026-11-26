package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lanchat/internal/crypto"
	"lanchat/internal/p2p"
	"lanchat/internal/store"
	"lanchat/internal/web"
)

func boundaryServer(t *testing.T) (*AppServer, *crypto.IdentityManager, *store.RingBuffer) {
	t.Helper()
	im, e := crypto.LoadOrCreateIdentity(t.TempDir(), "host")
	if e != nil {
		t.Fatal(e)
	}
	rb := store.NewRingBuffer(200, 20<<20, 2<<20, func(m *store.FileMeta) {
		if m.IsTempSpool {
			os.Remove(m.LocalPath)
		}
	})
	fs, _ := web.StaticFS()
	s := NewAppServer(im, rb, 12345, 0, t.TempDir(), fs)
	return s, im, rb
}
func request(t *testing.T, s *AppServer, method, path string, body []byte, remote bool, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "https://127.0.0.1:12345"+path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.TLS = &tls.ConnectionState{}
	if remote {
		r.RemoteAddr = "192.0.2.1:4567"
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func trustedSender(t *testing.T, im *crypto.IdentityManager) *crypto.IdentityManager {
	t.Helper()
	sender, e := crypto.LoadOrCreateIdentity(t.TempDir(), "sender")
	if e != nil {
		t.Fatal(e)
	}
	key := crypto.GenerateSharedSecret()
	for _, pair := range [][2]*crypto.IdentityManager{{im, sender}, {sender, im}} {
		if e := pair[0].AddOrUpdateTrustedPeer(crypto.TrustedPeer{PeerID: pair[1].PeerID(), Name: "sender", PublicKeyHex: pair[1].PublicKeyHex(), SharedKeyHex: key}); e != nil {
			t.Fatal(e)
		}
	}
	return sender
}
func signedHeaders(t *testing.T, from, to *crypto.IdentityManager, method, path string, body []byte) map[string]string {
	t.Helper()
	ts := time.Now().UnixMilli()
	nonce := crypto.GenerateSharedSecret()[:32]
	hash := bodyHash(body)
	if strings.HasPrefix(path, "/api/files/stream/") {
		hash = strings.TrimPrefix(path, "/api/files/stream/")
	}
	sig, e := from.SignPeerRequest(to.PeerID(), ts, method, path, nonce, hash)
	if e != nil {
		t.Fatal(e)
	}
	return map[string]string{"X-LanChat-Peer": from.PeerID(), "X-LanChat-Ts": strconv.FormatInt(ts, 10), "X-LanChat-Nonce": nonce, "X-LanChat-Sig": sig, "X-LanChat-Port": "23456"}
}
func TestUISecretsAndMobilePermissions(t *testing.T) {
	s, im, _ := boundaryServer(t)
	sender := trustedSender(t, im)
	peer, _ := im.GetTrustedPeer(sender.PeerID())
	state := request(t, s, "GET", "/api/state", nil, false, nil)
	if state.Code != 200 || strings.Contains(state.Body.String(), peer.SharedKeyHex) || strings.Contains(state.Body.String(), "shared_key") || strings.Contains(state.Body.String(), "pair_uri") {
		t.Fatal("secret exposed", state.Body.String())
	}
	hdr := map[string]string{"X-LanChat-Token": im.MobileAccessToken()}
	for _, path := range []string{"/api/files/register-path", "/api/peers/pair", "/api/peers/remove", "/api/discoverable", "/api/mobile-qr", "/api/pairing-info", "/api/mobile/revoke"} {
		w := request(t, s, "POST", path, []byte(`{}`), true, hdr)
		if w.Code != 403 {
			t.Errorf("mobile management %s: %d", path, w.Code)
		}
	}
	if w := request(t, s, "POST", "/api/messages", []byte(`{"kind":"text","text":"hello"}`), true, hdr); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestCrossOriginAndHostRejected(t *testing.T) {
	s, _, _ := boundaryServer(t)
	if w := request(t, s, "GET", "/api/state", nil, false, map[string]string{"Origin": "https://evil.example"}); w.Code != 403 {
		t.Fatal("cross origin accepted")
	}
	r := httptest.NewRequest("GET", "http://evil.example:12345/api/state", nil)
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("rebinding host accepted")
	}
	r = httptest.NewRequest("GET", "http://127.0.0.1:12345/api/state", nil)
	r.RemoteAddr = "192.0.2.1:1"
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 426 {
		t.Fatal("remote plaintext allowed")
	}
}
func TestP2PSignaturesCannotCrossEndpointsOrReplay(t *testing.T) {
	s, im, rb := boundaryServer(t)
	sender := trustedSender(t, im)
	rb.Add(&store.Message{ID: "keep", Text: "keep"})
	body := []byte(`{"name":"sender","http_port":23456}`)
	headers := signedHeaders(t, sender, im, "POST", "/api/p2p/ping", body)
	if w := request(t, s, "POST", "/api/p2p/clear", body, true, headers); w.Code != 403 || rb.Stats().CurrentMessages != 1 {
		t.Fatal("cross endpoint signature accepted")
	}
	if w := request(t, s, "POST", "/api/p2p/ping", body, true, headers); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(t, s, "POST", "/api/p2p/ping", body, true, headers); w.Code != 403 {
		t.Fatal("replay accepted")
	}
}
func TestForgedSenderRejectedAndImageSniffed(t *testing.T) {
	s, im, _ := boundaryServer(t)
	sender := trustedSender(t, im)
	msg := p2p.WireMessage{Message: &store.Message{ID: "msg_test", Kind: store.KindText, SenderID: "somebodyelse", Text: "forged"}}
	body, _ := json.Marshal(msg)
	if w := request(t, s, "POST", "/api/p2p/message", body, true, signedHeaders(t, sender, im, "POST", "/api/p2p/message", body)); w.Code != 403 {
		t.Fatal("forged sender accepted")
	}
	if w := request(t, s, "POST", "/api/messages", []byte(`{"kind":"image","image_base64":"PGh0bWw+","image_mime":"text/html"}`), false, nil); w.Code != 400 {
		t.Fatal("HTML image accepted")
	}
}
func TestUploadQuotaAndRecipientOrder(t *testing.T) {
	s, _, rb := boundaryServer(t)
	s.MaxUploadBytes = 32
	s.MaxSpoolBytes = 64
	for _, declare := range []bool{true, false} {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		if declare {
			mw.WriteField("target_peer_id", "")
		}
		part, _ := mw.CreateFormFile("file", "large.bin")
		part.Write(bytes.Repeat([]byte("x"), 100))
		mw.Close()
		w := request(t, s, "POST", "/api/files/upload", body.Bytes(), false, map[string]string{"Content-Type": mw.FormDataContentType()})
		if declare && w.Code != 413 {
			t.Fatal(w.Code, w.Body.String())
		}
		if !declare && w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	entries, _ := os.ReadDir(s.spoolDir)
	if len(entries) != 0 || rb.Stats().CurrentMessages != 0 {
		t.Fatal("failed upload left a file or message")
	}
}
func TestPrivateFileRecipientAuthorization(t *testing.T) {
	s, im, rb := boundaryServer(t)
	recipient := trustedSender(t, im)
	other := trustedSender(t, im)
	path := filepath.Join(t.TempDir(), "file")
	os.WriteFile(path, []byte("private"), 0600)
	rb.Add(&store.Message{ID: "private", Kind: store.KindFile, SenderID: im.PeerID(), TargetPeerID: recipient.PeerID(), File: &store.FileMeta{FileID: "file_private", OwnerPeerID: im.PeerID(), LocalPath: path}})
	endpoint := "/api/files/stream/file_private"
	for _, tc := range []struct {
		peer *crypto.IdentityManager
		want int
	}{{recipient, 200}, {other, 401}} {
		w := request(t, s, "GET", endpoint, nil, true, signedHeaders(t, tc.peer, im, "GET", endpoint, nil))
		if w.Code != tc.want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
func TestMalformedFramesReturnErrors(t *testing.T) {
	for i, frame := range [][]byte{{0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0x81, 0x00}, {0x09, 0x80, 0, 0, 0, 0}, {0x89, 0xfe, 0, 126, 0, 0, 0, 0}} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, _, e := readWSFrame(bufio.NewReader(bytes.NewReader(frame))); e == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
	frame := []byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}
	op, p, e := readWSFrame(bufio.NewReader(bytes.NewReader(frame)))
	if e != nil || op != 1 || string(p) != "hi" {
		t.Fatal("valid masked frame rejected")
	}
}
func TestStaleSpoolCleanup(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "old")
	active := filepath.Join(root, "active")
	os.Mkdir(old, 0700)
	os.Mkdir(active, 0700)
	ts := time.Now().Add(-25 * time.Hour)
	os.Chtimes(old, ts, ts)
	path, cleanup, e := CreateSpool(root)
	if e != nil {
		t.Fatal(e)
	}
	cleanup()
	if _, e := os.Stat(old); !os.IsNotExist(e) {
		t.Fatal("stale session retained")
	}
	if _, e := os.Stat(active); e != nil {
		t.Fatal("active session removed")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("current session not cleaned")
	}
}

func TestUploadSpoolDownloadRangeAndClear(t *testing.T) {
	s, _, rb := boundaryServer(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("target_peer_id", "")
	p, _ := mw.CreateFormFile("file", "sample.bin")
	p.Write([]byte("sample-content"))
	mw.Close()
	w := request(t, s, "POST", "/api/files/upload", body.Bytes(), false, map[string]string{"Content-Type": mw.FormDataContentType()})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		Messages []*store.Message `json:"messages"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil || len(result.Messages) != 1 {
		t.Fatal("missing file message", e)
	}
	file := result.Messages[0].File
	if file.SHA256 != bodyHash([]byte("sample-content")) {
		t.Fatal("incorrect SHA256")
	}
	dl := request(t, s, "GET", file.DownloadURL, nil, false, map[string]string{"Range": "bytes=0-5"})
	if dl.Code != 206 || dl.Body.String() != "sample" {
		t.Fatal("range download failed", dl.Code, dl.Body.String())
	}
	rb.Clear()
	entries, _ := os.ReadDir(s.spoolDir)
	if len(entries) != 0 {
		t.Fatal("clear left spool file")
	}
}

func TestShutdownCancelsActiveRemoteFileProxy(t *testing.T) {
	s, im, rb := boundaryServer(t)
	defer s.Stop()
	remote := trustedSender(t, im)
	started := make(chan struct{})
	finished := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("stream"))
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(finished)
	}))
	cfg, err := remote.TLSConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "https://")
	if err := im.UpdatePeerHeartbeat(crypto.TrustedPeer{PeerID: remote.PeerID(), LastAddr: addr}); err != nil {
		t.Fatal(err)
	}
	rb.Add(&store.Message{ID: "proxy_stop", Kind: store.KindFile, SenderID: remote.PeerID(), File: &store.FileMeta{FileID: "file_stop", OwnerPeerID: remote.PeerID(), OwnerAddr: addr}})
	local := httptest.NewServer(s.Handler())
	defer local.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Get(local.URL + "/api/files/proxy/file_stop")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not connect")
	}
	s.BeginShutdown()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("upstream stream was not canceled")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("local proxy handler did not terminate")
	}
	if w := request(t, s, "GET", "/api/state", nil, false, nil); w.Code != 503 {
		t.Fatal("new requests accepted during shutdown")
	}
}
