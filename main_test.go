package main

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestAutomaticTCPFallbackUsesRegisteredPort(t *testing.T) {
	occupied, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	ln, port, err := listenTCPWithFallback(occupied.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if port < 32520 || port >= 32768 {
		t.Fatal("automatic fallback selected an ephemeral-range port", port)
	}
	local, err := listenRegisteredTCP("127.0.0.1", 32521, 32521)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if local.Addr().(*net.TCPAddr).Port == 32521 || local.Addr().(*net.TCPAddr).Port >= 32768 {
		t.Fatal("local UI selected an excluded or ephemeral port")
	}
}
func TestShutdownForcesActiveHTTPConnectionClosed(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("active"))
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(finished)
	})}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	resp, err := http.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-started
	before := time.Now()
	shutdownHTTPServers(50*time.Millisecond, srv)
	if time.Since(before) > time.Second {
		t.Fatal("shutdown did not honor its deadline")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("handler remained active after shutdown timeout")
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("active stream was not interrupted")
	}
}
