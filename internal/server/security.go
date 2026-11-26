package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"lanchat/internal/p2p"
	"lanchat/internal/store"
)

func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return err == nil && u.Scheme == scheme && u.Host == r.Host && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
func (s *AppServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lifeMu.Lock()
		if s.stopping {
			s.lifeMu.Unlock()
			http.Error(w, "server shutting down", 503)
			return
		}
		s.handlers.Add(1)
		s.lifeMu.Unlock()
		defer s.handlers.Done()
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		callbackDone := make(chan struct{})
		stop := context.AfterFunc(s.ctx, func() {
			defer close(callbackDone)
			cancel()
			controller := http.NewResponseController(w)
			_ = controller.SetReadDeadline(time.Now())
			_ = controller.SetWriteDeadline(time.Now())
		})
		defer func() {
			if !stop() {
				<-callbackDone
			}
		}()
		r = r.WithContext(ctx)
		host, port, err := net.SplitHostPort(r.Host)
		valid := host == "localhost"
		if ip := net.ParseIP(host); ip != nil {
			valid = ip.IsLoopback()
			for _, local := range p2p.GetLANIPs() {
				if host == local {
					valid = true
				}
			}
		}
		if err != nil || !valid || !sameOrigin(r) {
			http.Error(w, "invalid host or origin", http.StatusForbidden)
			return
		}
		if local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
			_, lp, _ := net.SplitHostPort(local.String())
			if port != lp {
				http.Error(w, "invalid listener port", 403)
				return
			}
		}
		if !isLoopback(r) && r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
			return
		}
		select {
		case s.requests <- struct{}{}:
			defer func() { <-s.requests }()
		default:
			http.Error(w, "server busy", 429)
			return
		}
		timeout := 15 * time.Second
		if r.URL.Path == "/api/files/upload" {
			timeout = 30 * time.Minute
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(timeout))
		if r.URL.Path != "/api/files/upload" {
			r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}
func (s *AppServer) requireLocal(next http.HandlerFunc) http.HandlerFunc {
	return s.requireUIAuth(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopback(r) {
			http.Error(w, "host management requires local access", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
func (s *AppServer) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req) != nil || !s.identity.VerifyMobileToken(req.Token) {
		http.Error(w, "invalid token", 401)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "lanchat_token", Value: req.Token, Path: "/", MaxAge: 8 * 3600, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *AppServer) handlePairingInfo(w http.ResponseWriter, r *http.Request) {
	_, pin, _ := s.identity.DiscoverableState()
	ips := p2p.GetLANIPs()
	writeJSON(w, 200, map[string]any{"pin": pin, "pair_uri": net.JoinHostPort(ips[0], strconv.Itoa(s.httpPort)) + "#" + pin + "@" + s.identity.Fingerprint()})
}
func (s *AppServer) acceptNonce(peer, nonce string) bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	now := time.Now()
	for key, expiry := range s.nonces {
		if !expiry.After(now) {
			delete(s.nonces, key)
		}
	}
	key := peer + ":" + nonce
	if _, exists := s.nonces[key]; exists || len(s.nonces) >= 4096 {
		return false
	}
	// A request with a future timestamp can remain valid for two minutes.
	s.nonces[key] = now.Add(2*time.Minute + time.Second)
	return true
}
func (s *AppServer) allowPairAttempt() bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if time.Since(s.pairWindow) >= time.Minute {
		s.pairWindow = time.Now()
		s.pairAttempts = 0
	}
	s.pairAttempts++
	return s.pairAttempts <= 10
}
func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, max))
}
func bodyHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func validateMessage(m *store.Message) error {
	if m == nil || !validID(m.ID) || len(m.Text) > 256*1024 || len(m.SenderName) > 256 || len(m.SenderOS) > 32 || len(m.TargetName) > 256 || len(m.TargetPeerID) > 128 {
		return errors.New("invalid message fields")
	}
	switch m.Kind {
	case store.KindText:
		if strings.TrimSpace(m.Text) == "" {
			return errors.New("empty text")
		}
		m.File = nil
		m.InlineData = nil
		m.InlineURL = ""
	case store.KindImage:
		typ := http.DetectContentType(m.InlineData)
		if typ != "image/png" && typ != "image/jpeg" && typ != "image/gif" && typ != "image/webp" {
			return errors.New("unsupported image format")
		}
		m.InlineMime = typ
		m.InlineURL = "/api/inline/" + m.ID
		m.File = nil
	case store.KindFile:
		if m.File == nil || !validID(m.File.FileID) || len(m.File.FileName) > 255 || m.File.FileSize < 0 || len(m.File.MimeType) > 128 || len(m.File.SHA256) > 64 {
			return errors.New("invalid file metadata")
		}
		m.InlineData = nil
		m.InlineURL = ""
	default:
		return errors.New("unsupported message kind")
	}
	return nil
}

func validPort(s string) bool { p, e := strconv.Atoi(s); return e == nil && p > 0 && p <= 65535 }
func (s *AppServer) publicPeers() []map[string]any {
	out := []map[string]any{}
	for _, p := range s.identity.ListTrustedPeers() {
		out = append(out, map[string]any{"peer_id": p.PeerID, "name": p.Name, "os": p.OS, "last_addr": p.LastAddr, "online": p.Online, "last_seen": p.LastSeen})
	}
	return out
}
func (s *AppServer) broadcastStats() {
	ids := []string{}
	for _, m := range s.ring.List(s.identity.PeerID()) {
		ids = append(ids, m.ID)
	}
	s.wsHub.Broadcast("stats_update", map[string]any{"stats": s.ring.Stats(), "message_ids": ids})
}
