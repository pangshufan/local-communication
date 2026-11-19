package server

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSEvent is the JSON envelope pushed to connected desktop and mobile browsers.
type WSEvent struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

type wsClient struct {
	valid func() bool
	conn  net.Conn
	mu    sync.Mutex
	queue chan []byte
	done  chan struct{}
}

func (c *wsClient) writeText(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	length := len(payload)
	var header []byte
	header = append(header, 0x81) // FIN=1, Opcode=1 (Text)
	switch {
	case length <= 125:
		header = append(header, byte(length))
	case length <= 65535:
		header = append(header, 126, byte(length>>8), byte(length))
	default:
		header = append(header, 127)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(length))
		header = append(header, b[:]...)
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

func (c *wsClient) writeControl(opcode byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	frame := []byte{0x80 | opcode, byte(len(payload) & 0x7f)}
	frame = append(frame, payload...)
	_, err := c.conn.Write(frame)
	return err
}

// WSHub manages active WebSocket connections for real-time UI updates.
type WSHub struct {
	mu      sync.RWMutex
	clients map[*wsClient]struct{}
}

func NewWSHub() *WSHub {
	return &WSHub{
		clients: make(map[*wsClient]struct{}),
	}
}

func (h *WSHub) Broadcast(eventType string, data any) {
	payload, err := json.Marshal(WSEvent{
		Type: eventType,
		Data: data,
	})
	if err != nil {
		return
	}

	h.mu.RLock()
	list := make([]*wsClient, 0, len(h.clients))
	for c := range h.clients {
		list = append(list, c)
	}
	h.mu.RUnlock()

	for _, c := range list {
		select {
		case c.queue <- payload:
		default:
			h.remove(c)
		}
	}

}

func (h *WSHub) remove(c *wsClient) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.done)
		_ = c.conn.Close()
	}
	h.mu.Unlock()
}

// ServeWS upgrades an HTTP request to a RFC 6455 WebSocket connection using pure Go stdlib.
func (h *WSHub) ServeWS(w http.ResponseWriter, r *http.Request, onConnect func(send func(eventType string, data any)), valid ...func() bool) {
	if r.Method != http.MethodGet || !sameOrigin(r) || r.Header.Get("Origin") == "" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !headerToken(r.Header.Get("Connection"), "upgrade") || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "invalid websocket handshake", 400)
		return
	}
	key := strings.TrimSpace(r.Header.Get("Sec-Websocket-Key"))
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}

	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		_ = conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return
	}

	client := &wsClient{conn: conn, queue: make(chan []byte, 32), done: make(chan struct{})}
	if len(valid) > 0 {
		client.valid = valid[0]
	}
	h.mu.Lock()
	if len(h.clients) >= 32 {
		h.mu.Unlock()
		conn.Close()
		return
	}
	h.clients[client] = struct{}{}
	h.mu.Unlock()

	if onConnect != nil {
		onConnect(func(eventType string, data any) {
			if payload, err := json.Marshal(WSEvent{Type: eventType, Data: data}); err == nil {
				_ = client.writeText(payload)
			}
		})
	}

	go h.writeLoop(client)
	go h.readLoop(client, rw.Reader)
}

func (h *WSHub) readLoop(c *wsClient, r *bufio.Reader) {
	defer h.remove(c)
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		opcode, payload, err := readWSFrame(r)
		if err != nil {
			return
		}
		switch opcode {
		case 0x8: // Close
			_ = c.writeControl(0x8, nil)
			return
		case 0x9: // Ping
			_ = c.writeControl(0xA, payload)
		}
	}
}

func readWSFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, nil, err
	}
	opcode = b[0] & 0x0f
	masked := (b[1] & 0x80) != 0
	if b[0]&0x70 != 0 || b[0]&0x80 == 0 || !masked || (opcode != 0x1 && opcode != 0x2 && opcode != 0x8 && opcode != 0x9 && opcode != 0xa) {
		return 0, nil, errors.New("invalid websocket frame")
	}
	length := uint64(b[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
		if length < 126 {
			return 0, nil, errors.New("noncanonical length")
		}
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		if length < 65536 {
			return 0, nil, errors.New("noncanonical length")
		}
	}
	if length > 4*1024*1024 || (opcode >= 8 && length > 125) {
		return 0, nil, errors.New("frame too large")
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return opcode, payload, nil
}

func headerToken(value, token string) bool {
	for _, v := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(v), token) {
			return true
		}
	}
	return false
}
func (h *WSHub) Close() {
	h.mu.RLock()
	clients := make([]*wsClient, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()
	for _, c := range clients {
		h.remove(c)
	}
}
func (h *WSHub) writeLoop(c *wsClient) {
	defer h.remove(c)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case payload := <-c.queue:
			if c.writeText(payload) != nil {
				return
			}
		case <-ticker.C:
			if c.valid != nil && !c.valid() {
				return
			}
			if c.writeControl(9, nil) != nil {
				return
			}
		}
	}
}
