package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanchat/internal/crypto"
	"lanchat/internal/p2p"
	"lanchat/internal/qrcode"
	"lanchat/internal/store"
)

const streamChunkSize = 64 * 1024 // Fixed 64KB buffer for zero-RAM-bloat streaming

// Buffer pool for 64KB streaming buffers so GC never allocates per file transfer
var streamBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, streamChunkSize)
		return &b
	},
}

// AppServer serves both the local/mobile WebUI and the P2P HTTP transport endpoints.
type AppServer struct {
	identity *crypto.IdentityManager
	ring     *store.RingBuffer
	mesh     *p2p.MeshEngine
	wsHub    *WSHub
	httpPort int
	spoolDir string
	webFS    fs.FS
}

func NewAppServer(
	im *crypto.IdentityManager,
	rb *store.RingBuffer,
	httpPort int,
	udpPort int,
	spoolDir string,
	webFS fs.FS,
) *AppServer {
	s := &AppServer{
		identity: im,
		ring:     rb,
		wsHub:    NewWSHub(),
		httpPort: httpPort,
		spoolDir: spoolDir,
		webFS:    webFS,
	}
	s.mesh = p2p.NewMeshEngine(
		im,
		rb,
		httpPort,
		udpPort,
		func(msg *store.Message) {
			s.wsHub.Broadcast("new_message", msg)
			s.wsHub.Broadcast("stats_update", s.ring.Stats())
		},
		func() {
			s.wsHub.Broadcast("state_update", s.buildStateSnapshot())
		},
	)
	return s
}

func (s *AppServer) StartMesh() error {
	return s.mesh.Start()
}

func (s *AppServer) Stop() {
	s.mesh.Stop()
	if s.spoolDir != "" {
		_ = os.RemoveAll(s.spoolDir)
	}
}

func (s *AppServer) Handler() http.Handler {
	mux := http.NewServeMux()

	// WebSocket endpoint
	mux.HandleFunc("/ws", s.requireUIAuth(func(w http.ResponseWriter, r *http.Request) {
		s.wsHub.ServeWS(w, r, func(send func(eventType string, data any)) {
			send("init", map[string]any{
				"state":    s.buildStateSnapshot(),
				"messages": s.decorateMessagesForClient(s.ring.List(s.identity.PeerID()), r.Host),
			})
		})
	}))

	// UI API endpoints
	mux.HandleFunc("/api/state", s.requireUIAuth(s.handleGetState))
	mux.HandleFunc("/api/messages", s.requireUIAuth(s.handleMessages))
	mux.HandleFunc("/api/messages/clear", s.requireUIAuth(s.handleClearMessages))
	mux.HandleFunc("/api/discoverable", s.requireUIAuth(s.handleSetDiscoverable))
	mux.HandleFunc("/api/peers/scan", s.requireUIAuth(s.handleScanPeers))
	mux.HandleFunc("/api/peers/pair", s.requireUIAuth(s.handlePairPeer))
	mux.HandleFunc("/api/peers/remove", s.requireUIAuth(s.handleRemovePeer))
	mux.HandleFunc("/api/mobile-qr", s.requireUIAuth(s.handleMobileQR))
	mux.HandleFunc("/api/files/upload", s.requireUIAuth(s.handleFileUpload))
	mux.HandleFunc("/api/files/register-path", s.requireUIAuth(s.handleRegisterLocalPath))

	// Media & Streaming endpoints (accessible by authorized UI or trusted peers)
	mux.HandleFunc("/api/inline/", s.handleServeInline)
	mux.HandleFunc("/api/files/stream/", s.handleStreamFile)
	mux.HandleFunc("/api/files/proxy/", s.requireUIAuth(s.handleProxyRemoteFile))

	// P2P Node-to-Node endpoints
	mux.HandleFunc("/api/p2p/pair", s.handleP2PPair)
	mux.HandleFunc("/api/p2p/ping", s.requireP2PAuth(s.handleP2PPing))
	mux.HandleFunc("/api/p2p/message", s.requireP2PAuth(s.handleP2PMessage))
	mux.HandleFunc("/api/p2p/clear", s.requireP2PAuth(s.handleP2PClear))

	// Static WebUI + PWA assets
	fileServer := http.FileServer(http.FS(s.webFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If mobile connects with ?token=..., set persistent HttpOnly cookie and serve UI
		if tok := r.URL.Query().Get("token"); tok != "" && s.identity.VerifyMobileToken(tok) {
			http.SetCookie(w, &http.Cookie{
				Name:     "lanchat_token",
				Value:    tok,
				Path:     "/",
				MaxAge:   30 * 24 * 3600,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}
		if !s.isAuthorizedUIRequest(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LanChat - Private Node</title><style>body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}.box{max-width:380px;padding:28px;background:#1e293b;border-radius:16px;border:1px solid #334155}input{width:100%;padding:10px;margin:12px 0;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#fff;box-sizing:border-box}button{width:100%;padding:10px;border-radius:8px;border:0;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}</style></head><body><div class="box"><h3>🔒 私有节点 (默认隐身)</h3><p style="font-size:14px;color:#94a3b8">此设备仅允许本机或已扫码授权的手机访问。请在电脑端点击「手机连接」扫码，或在下方输入访问令牌：</p><form method="GET" action="/"><input name="token" placeholder="输入访问 Token..." required><button type="submit">验证进入</button></form></div></body></html>`))
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	return mux
}

func (s *AppServer) isAuthorizedUIRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	if tok := r.URL.Query().Get("token"); tok != "" && s.identity.VerifyMobileToken(tok) {
		return true
	}
	if c, err := r.Cookie("lanchat_token"); err == nil && s.identity.VerifyMobileToken(c.Value) {
		return true
	}
	if tok := r.Header.Get("X-LanChat-Token"); tok != "" && s.identity.VerifyMobileToken(tok) {
		return true
	}
	return false
}

func (s *AppServer) requireUIAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthorizedUIRequest(r) {
			http.Error(w, "unauthorized: scan the QR code on the host computer first", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *AppServer) requireP2PAuth(next func(w http.ResponseWriter, r *http.Request, senderPeerID string, body []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		senderID := r.Header.Get("X-LanChat-Peer")
		tsStr := r.Header.Get("X-LanChat-Ts")
		sig := r.Header.Get("X-LanChat-Sig")
		portStr := r.Header.Get("X-LanChat-Port")

		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil || senderID == "" || sig == "" {
			http.Error(w, "missing p2p auth headers", http.StatusUnauthorized)
			return
		}

		// Limit P2P control/inline message body to 4MB max (large files always stream via GET /api/files/stream/)
		body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(body)
		bodyHash := hex.EncodeToString(sum[:])

		if !s.identity.VerifyPeerRequest(senderID, ts, bodyHash, sig) {
			http.Error(w, "invalid p2p signature", http.StatusForbidden)
			return
		}

		// Update peer's latest IP:Port automatically if DHCP changed its IP
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && portStr != "" {
			s.identity.SetPeerOnline(senderID, net.JoinHostPort(host, portStr), true)
		}
		next(w, r, senderID, body)
	}
}

func (s *AppServer) buildStateSnapshot() map[string]any {
	discEnabled, pin, remSec := s.identity.DiscoverableState()
	ips := p2p.GetLANIPs()
	primaryIP := ips[0]
	return map[string]any{
		"self": map[string]any{
			"peer_id":      s.identity.PeerID(),
			"name":         s.identity.Name(),
			"os":           s.identity.OS(),
			"ips":          ips,
			"http_port":    s.httpPort,
			"primary_addr": fmt.Sprintf("%s:%d", primaryIP, s.httpPort),
		},
		"discoverable": map[string]any{
			"enabled":       discEnabled,
			"pin":           pin,
			"remaining_sec": remSec,
			"pair_uri":      fmt.Sprintf("%s:%d#%s", primaryIP, s.httpPort, pin),
		},
		"peers": s.identity.ListTrustedPeers(),
		"stats": s.ring.Stats(),
	}
}

func (s *AppServer) handleGetState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.buildStateSnapshot())
}

func (s *AppServer) handleMessages(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		msgs := s.ring.List(s.identity.PeerID())
		writeJSON(w, http.StatusOK, s.decorateMessagesForClient(msgs, r.Host))

	case http.MethodPost:
		var req struct {
			Kind         store.MessageKind `json:"kind"`
			Text         string            `json:"text"`
			TargetPeerID string            `json:"target_peer_id"`
			TargetName   string            `json:"target_name"`
			ImageBase64  string            `json:"image_base64"`
			ImageMime    string            `json:"image_mime"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024*1024)).Decode(&req); err != nil {
			http.Error(w, "invalid request JSON", http.StatusBadRequest)
			return
		}

		msgID := generateID("msg")
		msg := &store.Message{
			ID:           msgID,
			Kind:         req.Kind,
			SenderID:     s.identity.PeerID(),
			SenderName:   s.identity.Name(),
			SenderOS:     s.identity.OS(),
			TargetPeerID: req.TargetPeerID,
			TargetName:   req.TargetName,
			Text:         strings.TrimSpace(req.Text),
			CreatedAt:    time.Now().UnixMilli(),
		}
		if msg.Kind == "" {
			msg.Kind = store.KindText
		}

		if msg.Kind == store.KindImage {
			raw, err := base64.StdEncoding.DecodeString(req.ImageBase64)
			if err != nil || len(raw) == 0 {
				http.Error(w, "invalid clipboard image data", http.StatusBadRequest)
				return
			}
			msg.InlineData = raw
			msg.InlineMime = req.ImageMime
			if msg.InlineMime == "" {
				msg.InlineMime = "image/png"
			}
			msg.InlineURL = "/api/inline/" + msg.ID
		} else if msg.Text == "" {
			http.Error(w, "empty message", http.StatusBadRequest)
			return
		}

		if _, err := s.ring.Add(msg); err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}

		s.wsHub.Broadcast("new_message", msg)
		s.wsHub.Broadcast("stats_update", s.ring.Stats())
		s.mesh.PushMessageToPeers(msg)
		writeJSON(w, http.StatusOK, msg)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *AppServer) handleClearMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AllDevices bool `json:"all_devices"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.ring.Clear()
	s.wsHub.Broadcast("clear_messages", nil)
	s.wsHub.Broadcast("stats_update", s.ring.Stats())
	if req.AllDevices {
		s.mesh.BroadcastClear()
	}
	writeJSON(w, http.StatusOK, s.ring.Stats())
}

func (s *AppServer) handleSetDiscoverable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled     bool `json:"enabled"`
		DurationSec int  `json:"duration_sec"`
		RotatePIN   bool `json:"rotate_pin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.RotatePIN {
		s.identity.RotatePIN()
	} else {
		dur := time.Duration(req.DurationSec) * time.Second
		if dur <= 0 {
			dur = 3 * time.Minute
		}
		s.identity.SetDiscoverable(req.Enabled, dur)
	}
	state := s.buildStateSnapshot()
	s.wsHub.Broadcast("state_update", state)
	writeJSON(w, http.StatusOK, state)
}

func (s *AppServer) handleScanPeers(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.mesh.ScanDiscoverablePeers(1200 * time.Millisecond)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"discovered": nodes})
}

func (s *AppServer) handlePairPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Addr string `json:"addr"`
		PIN  string `json:"pin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	peer, err := s.mesh.PairWithPeer(req.Addr, req.PIN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state := s.buildStateSnapshot()
	s.wsHub.Broadcast("state_update", state)
	writeJSON(w, http.StatusOK, map[string]any{"peer": peer, "state": state})
}

func (s *AppServer) handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PeerID string `json:"peer_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.PeerID != "" {
		s.identity.RemoveTrustedPeer(req.PeerID)
	}
	state := s.buildStateSnapshot()
	s.wsHub.Broadcast("state_update", state)
	writeJSON(w, http.StatusOK, state)
}

func (s *AppServer) handleMobileQR(w http.ResponseWriter, r *http.Request) {
	ips := p2p.GetLANIPs()
	selectedIP := r.URL.Query().Get("ip")
	if selectedIP == "" {
		selectedIP = ips[0]
	}
	token := s.identity.MobileAccessToken()
	mobileURL := fmt.Sprintf("http://%s:%d/?token=%s", selectedIP, s.httpPort, token)
	svg, err := qrcode.RenderSVG(mobileURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url":   mobileURL,
		"svg":   svg,
		"ips":   ips,
		"token": token,
	})
}

// handleRegisterLocalPath registers a local file on disk for zero-copy streaming without copying or uploading it.
func (s *AppServer) handleRegisterLocalPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		FilePath     string `json:"file_path"`
		TargetPeerID string `json:"target_peer_id"`
		TargetName   string `json:"target_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cleanPath := filepath.Clean(strings.TrimSpace(req.FilePath))
	info, err := os.Stat(cleanPath)
	if err != nil || info.IsDir() {
		http.Error(w, "file not found or is a directory", http.StatusBadRequest)
		return
	}

	fileID := generateID("file")
	ext := filepath.Ext(info.Name())
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	ips := p2p.GetLANIPs()
	meta := &store.FileMeta{
		FileID:      fileID,
		FileName:    info.Name(),
		FileSize:    info.Size(),
		MimeType:    mimeType,
		OwnerPeerID: s.identity.PeerID(),
		OwnerAddr:   fmt.Sprintf("%s:%d", ips[0], s.httpPort),
		DownloadURL: "/api/files/stream/" + fileID,
		LocalPath:   cleanPath,
		IsTempSpool: false,
	}

	msg := &store.Message{
		ID:           generateID("msg"),
		Kind:         store.KindFile,
		SenderID:     s.identity.PeerID(),
		SenderName:   s.identity.Name(),
		SenderOS:     s.identity.OS(),
		TargetPeerID: req.TargetPeerID,
		TargetName:   req.TargetName,
		File:         meta,
		CreatedAt:    time.Now().UnixMilli(),
	}
	if _, err := s.ring.Add(msg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.wsHub.Broadcast("new_message", msg)
	s.wsHub.Broadcast("stats_update", s.ring.Stats())
	s.mesh.PushMessageToPeers(msg)
	writeJSON(w, http.StatusOK, msg)
}

// handleFileUpload streams a multipart file upload directly to disk spool in 64KB chunks (0 RAM buffering)
// while computing SHA-256 on the fly.
func (s *AppServer) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart/form-data", http.StatusBadRequest)
		return
	}

	var targetPeerID, targetName string
	var createdMsgs []*store.Message

	if err := os.MkdirAll(s.spoolDir, 0700); err != nil {
		http.Error(w, "failed to create spool dir", http.StatusInternalServerError)
		return
	}

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "read multipart error: "+err.Error(), http.StatusBadRequest)
			return
		}
		formName := part.FormName()
		if formName == "target_peer_id" {
			b, _ := io.ReadAll(io.LimitReader(part, 256))
			targetPeerID = strings.TrimSpace(string(b))
			_ = part.Close()
			continue
		}
		if formName == "target_name" {
			b, _ := io.ReadAll(io.LimitReader(part, 256))
			targetName = strings.TrimSpace(string(b))
			_ = part.Close()
			continue
		}
		fileName := filepath.Base(part.FileName())
		if fileName == "" || fileName == "." {
			_ = part.Close()
			continue
		}

		fileID := generateID("file")
		spoolPath := filepath.Join(s.spoolDir, fileID+"_"+fileName)
		outFile, err := os.OpenFile(spoolPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			_ = part.Close()
			http.Error(w, "create spool file failed", http.StatusInternalServerError)
			return
		}

		hasher := sha256.New()
		bufPtr := streamBufPool.Get().(*[]byte)
		written, copyErr := io.CopyBuffer(io.MultiWriter(outFile, hasher), part, *bufPtr)
		streamBufPool.Put(bufPtr)
		_ = outFile.Close()
		_ = part.Close()

		if copyErr != nil {
			_ = os.Remove(spoolPath)
			http.Error(w, "stream upload failed: "+copyErr.Error(), http.StatusInternalServerError)
			return
		}

		mimeType := part.Header.Get("Content-Type")
		if mimeType == "" {
			mimeType = mime.TypeByExtension(filepath.Ext(fileName))
			if mimeType == "" {
				mimeType = "application/octet-stream"
			}
		}

		ips := p2p.GetLANIPs()
		meta := &store.FileMeta{
			FileID:      fileID,
			FileName:    fileName,
			FileSize:    written,
			MimeType:    mimeType,
			SHA256:      hex.EncodeToString(hasher.Sum(nil)),
			OwnerPeerID: s.identity.PeerID(),
			OwnerAddr:   fmt.Sprintf("%s:%d", ips[0], s.httpPort),
			DownloadURL: "/api/files/stream/" + fileID,
			LocalPath:   spoolPath,
			IsTempSpool: true,
		}

		msg := &store.Message{
			ID:           generateID("msg"),
			Kind:         store.KindFile,
			SenderID:     s.identity.PeerID(),
			SenderName:   s.identity.Name(),
			SenderOS:     s.identity.OS(),
			TargetPeerID: targetPeerID,
			TargetName:   targetName,
			File:         meta,
			CreatedAt:    time.Now().UnixMilli(),
		}
		if _, err := s.ring.Add(msg); err == nil {
			createdMsgs = append(createdMsgs, msg)
			s.wsHub.Broadcast("new_message", msg)
			s.mesh.PushMessageToPeers(msg)
		} else {
			_ = os.Remove(spoolPath)
		}
	}

	s.wsHub.Broadcast("stats_update", s.ring.Stats())
	writeJSON(w, http.StatusOK, map[string]any{"messages": createdMsgs})
}

func (s *AppServer) handleServeInline(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorizedUIRequest(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	msgID := strings.TrimPrefix(r.URL.Path, "/api/inline/")
	msg, ok := s.ring.GetMessage(msgID)
	if !ok || len(msg.InlineData) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", msg.InlineMime)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	_, _ = w.Write(msg.InlineData)
}

// handleStreamFile streams a file directly from disk in 64KB chunks without buffering into RAM.
func (s *AppServer) handleStreamFile(w http.ResponseWriter, r *http.Request) {
	// Authorized if UI client OR signed by a trusted peer
	if !s.isAuthorizedUIRequest(r) && !s.isAuthorizedPeerStream(r) {
		http.Error(w, "unauthorized file stream access", http.StatusUnauthorized)
		return
	}
	fileID := strings.TrimPrefix(r.URL.Path, "/api/files/stream/")
	meta, ok := s.ring.GetFile(fileID)
	if !ok || meta.LocalPath == "" {
		http.NotFound(w, r)
		return
	}

	f, err := os.Open(meta.LocalPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", meta.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`,
		strings.ReplaceAll(meta.FileName, `"`, `'`), url.PathEscape(meta.FileName)))
	if meta.SHA256 != "" {
		w.Header().Set("X-File-SHA256", meta.SHA256)
	}
	http.ServeContent(w, r, meta.FileName, info.ModTime(), f)
}

// handleProxyRemoteFile streams a file from a remote trusted peer to the local browser/mobile client in 64KB chunks.
func (s *AppServer) handleProxyRemoteFile(w http.ResponseWriter, r *http.Request) {
	fileID := strings.TrimPrefix(r.URL.Path, "/api/files/proxy/")
	meta, ok := s.ring.GetFile(fileID)
	if !ok || meta.OwnerAddr == "" {
		http.NotFound(w, r)
		return
	}
	peer, trusted := s.identity.GetTrustedPeer(meta.OwnerPeerID)
	addr := meta.OwnerAddr
	if trusted && peer.LastAddr != "" {
		addr = peer.LastAddr
	}

	ts := time.Now().UnixMilli()
	sig, err := s.identity.SignPeerRequest(meta.OwnerPeerID, ts, fileID)
	if err != nil {
		http.Error(w, "untrusted file owner", http.StatusForbidden)
		return
	}

	remoteURL := fmt.Sprintf("http://%s/api/files/stream/%s", addr, fileID)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, remoteURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-LanChat-Peer", s.identity.PeerID())
	req.Header.Set("X-LanChat-Ts", strconv.FormatInt(ts, 10))
	req.Header.Set("X-LanChat-Sig", sig)
	if rng := r.Header.Get("Range"); rng != "" {
		req.Header.Set("Range", rng)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "remote node unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for _, k := range []string{"Content-Type", "Content-Length", "Content-Disposition", "Content-Range", "Accept-Ranges", "X-File-SHA256"} {
		if v := resp.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	bufPtr := streamBufPool.Get().(*[]byte)
	_, _ = io.CopyBuffer(w, resp.Body, *bufPtr)
	streamBufPool.Put(bufPtr)
}

func (s *AppServer) isAuthorizedPeerStream(r *http.Request) bool {
	senderID := r.Header.Get("X-LanChat-Peer")
	tsStr := r.Header.Get("X-LanChat-Ts")
	sig := r.Header.Get("X-LanChat-Sig")
	fileID := strings.TrimPrefix(r.URL.Path, "/api/files/stream/")
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || senderID == "" || sig == "" {
		return false
	}
	return s.identity.VerifyPeerRequest(senderID, ts, fileID, sig)
}

// --- P2P Protocol Handlers ---

func (s *AppServer) handleP2PPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req p2p.PairRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req); err != nil {
		http.Error(w, "invalid pair request", http.StatusBadRequest)
		return
	}
	if !s.identity.VerifyPIN(req.PIN) {
		http.Error(w, "invalid or expired 6-digit pairing PIN", http.StatusForbidden)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peerAddr := fmt.Sprintf("%s:%d", host, req.HTTPPort)

	peer := crypto.TrustedPeer{
		PeerID:       req.PeerID,
		Name:         req.Name,
		OS:           req.OS,
		PublicKeyHex: req.PublicKeyHex,
		SharedKeyHex: req.SharedKeyHex,
		LastAddr:     peerAddr,
		PairedAt:     time.Now().UnixMilli(),
		LastSeen:     time.Now().UnixMilli(),
		Online:       true,
	}
	if err := s.identity.AddOrUpdateTrustedPeer(peer); err != nil {
		http.Error(w, "failed to save peer", http.StatusInternalServerError)
		return
	}

	// Rotate PIN after successful pairing to prevent replay
	s.identity.RotatePIN()
	s.wsHub.Broadcast("state_update", s.buildStateSnapshot())

	writeJSON(w, http.StatusOK, p2p.PairResponse{
		PeerID:       s.identity.PeerID(),
		Name:         s.identity.Name(),
		OS:           s.identity.OS(),
		PublicKeyHex: s.identity.PublicKeyHex(),
		HTTPPort:     s.httpPort,
	})
}

func (s *AppServer) handleP2PPing(w http.ResponseWriter, r *http.Request, senderPeerID string, body []byte) {
	var ping struct {
		Name     string `json:"name"`
		OS       string `json:"os"`
		HTTPPort int    `json:"http_port"`
	}
	if json.Unmarshal(body, &ping) == nil && ping.HTTPPort > 0 {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			_ = s.identity.AddOrUpdateTrustedPeer(crypto.TrustedPeer{
				PeerID:   senderPeerID,
				Name:     ping.Name,
				OS:       ping.OS,
				LastAddr: fmt.Sprintf("%s:%d", host, ping.HTTPPort),
				Online:   true,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *AppServer) handleP2PMessage(w http.ResponseWriter, r *http.Request, senderPeerID string, body []byte) {
	var wire p2p.WireMessage
	if err := json.Unmarshal(body, &wire); err != nil || wire.Message == nil {
		http.Error(w, "invalid wire message", http.StatusBadRequest)
		return
	}
	msg := wire.Message
	if msg.Kind == store.KindImage && wire.InlineDataBase64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(wire.InlineDataBase64); err == nil {
			msg.InlineData = raw
			msg.InlineURL = "/api/inline/" + msg.ID
		}
	}
	if msg.Kind == store.KindFile && msg.File != nil {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			if portStr := r.Header.Get("X-LanChat-Port"); portStr != "" {
				msg.File.OwnerAddr = net.JoinHostPort(host, portStr)
			}
		}
		msg.File.DownloadURL = "/api/files/proxy/" + msg.File.FileID
	}

	added, err := s.ring.Add(msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	if added {
		s.wsHub.Broadcast("new_message", msg)
		s.wsHub.Broadcast("stats_update", s.ring.Stats())
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added})
}

func (s *AppServer) handleP2PClear(w http.ResponseWriter, r *http.Request, senderPeerID string, body []byte) {
	s.ring.Clear()
	s.wsHub.Broadcast("clear_messages", nil)
	s.wsHub.Broadcast("stats_update", s.ring.Stats())
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

func (s *AppServer) decorateMessagesForClient(msgs []*store.Message, host string) []*store.Message {
	return msgs
}

func generateID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s_%d_%s", prefix, time.Now().UnixMilli(), hex.EncodeToString(b[:4]))
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
