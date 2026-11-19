package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// CreateSpool cleans abandoned sessions after 24 hours. A heartbeat protects live sessions.
func CreateSpool(root string) (string, func(), error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			info, err := e.Info()
			if err == nil && time.Since(info.ModTime()) > 24*time.Hour {
				_ = os.RemoveAll(filepath.Join(root, e.Name()))
			}
		}
	}
	path, err := os.MkdirTemp(root, "session-")
	if err != nil {
		return "", nil, err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				_ = os.Chtimes(path, now, now)
			}
		}
	}()
	cleanup := func() { close(stop); <-done; _ = os.RemoveAll(path) }
	return path, cleanup, nil
}

// quotaWriter rejects data before writing past a request's disk allowance.
type quotaWriter struct {
	w         io.Writer
	remaining int64
}

func (q *quotaWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > q.remaining {
		return 0, errors.New("upload or spool quota exceeded")
	}
	n, err := q.w.Write(p)
	q.remaining -= int64(n)
	return n, err
}
func (s *AppServer) beginUpload(w http.ResponseWriter, r *http.Request) (int64, bool) {
	select {
	case s.uploads <- struct{}{}:
	default:
		http.Error(w, "too many uploads", 429)
		return 0, false
	}
	// Serialize disk reservations, including every file in a multipart request.
	s.spoolMu.Lock()
	entries, err := os.ReadDir(s.spoolDir)
	if err != nil && !os.IsNotExist(err) {
		s.spoolMu.Unlock()
		<-s.uploads
		http.Error(w, "spool unavailable", 500)
		return 0, false
	}
	var used int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() {
			used += info.Size()
		}
	}
	free := s.MaxSpoolBytes - used
	if free > s.MaxUploadBytes {
		free = s.MaxUploadBytes
	}
	if free <= 0 {
		s.spoolMu.Unlock()
		<-s.uploads
		http.Error(w, "spool quota exceeded", 507)
		return 0, false
	}
	return free, true
}
