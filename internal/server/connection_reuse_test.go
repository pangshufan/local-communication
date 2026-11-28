package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"lanchat/internal/crypto"
)

func TestRealAppHeartbeatsReuseTLSConnection(t *testing.T) {
	s, im, _ := boundaryServer(t)
	defer s.Stop()
	sender := trustedSender(t, im)
	var connections atomic.Int32
	ts := httptest.NewUnstartedServer(s.Handler())
	cfg, err := im.TLSConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = cfg
	ts.Config.ReadHeaderTimeout = 10 * time.Second
	ts.Config.IdleTimeout = 60 * time.Second
	ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	ts.StartTLS()
	defer ts.Close()
	client, err := sender.PeerClient(im.PeerID(), 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.ClosePeerConnections()
	body := []byte(`{"name":"sender","os":"darwin","http_port":32520}`)
	for i := 0; i < 20; i++ {
		req, err := http.NewRequest("POST", ts.URL+"/api/p2p/ping", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		tsMs := time.Now().UnixMilli()
		nonce := crypto.GenerateSharedSecret()[:32]
		sig, err := sender.SignPeerRequest(im.PeerID(), tsMs, "POST", "/api/p2p/ping", nonce, bodyHash(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-LanChat-Peer", sender.PeerID())
		req.Header.Set("X-LanChat-Ts", strconv.FormatInt(tsMs, 10))
		req.Header.Set("X-LanChat-Nonce", nonce)
		req.Header.Set("X-LanChat-Sig", sig)
		req.Header.Set("X-LanChat-Port", "32520")
		var reused bool
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("ping %d: status %d body=%s err=%v", i, resp.StatusCode, data, err)
		}
		if i > 0 && !reused {
			t.Errorf("heartbeat %d did not reuse connection", i)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("20 full AppServer heartbeats opened %d TLS/TCP connections", connections.Load())
	}
}

func TestBodylessDownloadSurvivesRequestBodyDeadline(t *testing.T) {
	s, _, _ := boundaryServer(t)
	defer s.Stop()
	ts := httptest.NewServer(s.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.WriteString(w, "start"); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		// The old guard canceled a bodyless request after 15 seconds.
		select {
		case <-r.Context().Done():
			return
		case <-time.After(15250 * time.Millisecond):
			_, _ = io.WriteString(w, "end")
		}
	})))
	defer ts.Close()
	client := ts.Client()
	client.Timeout = 20 * time.Second
	resp, err := client.Get(ts.URL + "/api/files/proxy/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil || string(data) != "startend" {
		t.Fatalf("download interrupted: body=%q, error=%v", data, err)
	}
}

func TestPeerPresenceBroadcastsOnlyChanges(t *testing.T) {
	s, im, _ := boundaryServer(t)
	defer s.Stop()
	sender := trustedSender(t, im)
	client := &wsClient{queue: make(chan []byte, 4)}
	s.wsHub.clients[client] = struct{}{}
	defer delete(s.wsHub.clients, client)

	update := crypto.TrustedPeer{PeerID: sender.PeerID(), Name: "renamed", LastAddr: "192.0.2.1:32520"}
	for i := 0; i < 2; i++ {
		if err := s.observePeer(update); err != nil {
			t.Fatal(err)
		}
	}
	if len(client.queue) != 1 {
		t.Fatalf("expected one state update, got %d", len(client.queue))
	}
	var event struct {
		Type string
		Data struct {
			Peers []crypto.TrustedPeer
		}
	}
	if err := json.Unmarshal(<-client.queue, &event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "state_update" || len(event.Data.Peers) != 1 {
		t.Fatalf("unexpected event: %+v", event)
	}
	peer := event.Data.Peers[0]
	if !peer.Online || peer.Name != update.Name || peer.LastAddr != update.LastAddr {
		t.Fatalf("unexpected peer state: online=%t name=%q addr=%q", peer.Online, peer.Name, peer.LastAddr)
	}
}
