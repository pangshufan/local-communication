package server

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestWebSocketShutdownSendsGoingAway(t *testing.T) {
	server, browser := net.Pipe()
	defer browser.Close()
	hub := NewWSHub()
	client := &wsClient{conn: server, done: make(chan struct{}), queue: make(chan []byte, 1)}
	hub.clients[client] = struct{}{}
	result := make(chan uint16, 1)
	go func() {
		var head [2]byte
		if _, err := io.ReadFull(browser, head[:]); err != nil {
			return
		}
		payload := make([]byte, int(head[1]))
		if _, err := io.ReadFull(browser, payload); err == nil && head[0] == 0x88 && len(payload) >= 2 {
			result <- binary.BigEndian.Uint16(payload)
		}
	}()
	hub.Shutdown()
	select {
	case code := <-result:
		if code != 1001 {
			t.Fatal("wrong shutdown close code", code)
		}
	case <-time.After(time.Second):
		t.Fatal("browser not told to stop reconnecting")
	}
}
func TestSlowWebSocketCannotBlockShutdown(t *testing.T) {
	server, browser := net.Pipe()
	defer browser.Close()
	hub := NewWSHub()
	client := &wsClient{conn: server, done: make(chan struct{}), queue: make(chan []byte, 1)}
	hub.clients[client] = struct{}{}
	before := time.Now()
	hub.Shutdown()
	if time.Since(before) > time.Second {
		t.Fatal("slow browser blocked shutdown")
	}
}
