package store

import (
	"errors"
	"sync"
	"time"
)

// MessageKind defines the type of message stored in the timeline.
type MessageKind string

const (
	KindText  MessageKind = "text"
	KindImage MessageKind = "image" // Small inline clipboard/image preview stored in bounded RAM
	KindFile  MessageKind = "file"  // Zero-RAM-buffering file metadata card (streamed on demand)
)

// FileMeta holds metadata for a shared file. The file payload itself is NEVER loaded into memory;
// it is streamed directly from LocalPath (or temporary spool path) in fixed 64KB chunks.
type FileMeta struct {
	FileID      string `json:"file_id"`
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	MimeType    string `json:"mime_type"`
	SHA256      string `json:"sha256,omitempty"`
	OwnerPeerID string `json:"owner_peer_id"`
	OwnerAddr   string `json:"owner_addr,omitempty"` // IP:Port of the node hosting the stream
	DownloadURL string `json:"download_url"`
	LocalPath   string `json:"-"` // Never serialized to remote peers
	IsTempSpool bool   `json:"-"` // True if uploaded from browser/mobile into temp spool dir
}

// Message represents a chat or file-sharing item in the unified timeline or 1-to-1 channel.
type Message struct {
	ID           string      `json:"id"`
	Kind         MessageKind `json:"kind"`
	SenderID     string      `json:"sender_id"`
	SenderName   string      `json:"sender_name"`
	SenderOS     string      `json:"sender_os"`
	TargetPeerID string      `json:"target_peer_id,omitempty"` // Empty = All Devices (Public Timeline); non-empty = 1v1 private
	TargetName   string      `json:"target_name,omitempty"`
	Text         string      `json:"text,omitempty"`
	InlineData   []byte      `json:"-"`                        // Raw inline bytes for KindImage (kept in bounded memory pool)
	InlineMime   string      `json:"inline_mime,omitempty"`    // e.g., image/png
	InlineURL    string      `json:"inline_url,omitempty"`     // e.g., /api/inline/{id}
	File         *FileMeta   `json:"file,omitempty"`           // Present when Kind == KindFile
	CreatedAt    int64       `json:"created_at"`               // Unix milliseconds
	MemoryBytes  int64       `json:"memory_bytes"`             // Accounted bytes in the ring buffer
}

// Stats reports real-time memory watermark metrics of the in-memory store.
type Stats struct {
	CurrentMessages int   `json:"current_messages"`
	MaxMessages     int   `json:"max_messages"`
	CurrentBytes    int64 `json:"current_bytes"`
	MaxBytes        int64 `json:"max_bytes"`
	EvictedCount    int64 `json:"evicted_count"`
}

var (
	ErrPayloadTooLarge = errors.New("inline payload exceeds single-item memory limit; use file streaming instead")
)

// RingBuffer implements a thread-safe, strictly bounded in-memory message & file registry.
// When either MaxMessages or MaxBytes is exceeded, the oldest messages are evicted (FIFO).
type RingBuffer struct {
	mu             sync.RWMutex
	maxMessages    int
	maxBytes       int64
	maxInlineBytes int64
	messages       []*Message
	byID           map[string]*Message
	filesByID      map[string]*FileMeta
	currentBytes   int64
	evictedCount   int64
	onEvictFile    func(meta *FileMeta)
}

// NewRingBuffer creates a bounded in-memory store.
// Default recommendation: maxMessages = 200, maxBytes = 20 * 1024 * 1024 (20MB), maxInlineBytes = 2 * 1024 * 1024 (2MB).
func NewRingBuffer(maxMessages int, maxBytes int64, maxInlineBytes int64, onEvictFile func(meta *FileMeta)) *RingBuffer {
	if maxMessages <= 0 {
		maxMessages = 200
	}
	if maxBytes <= 0 {
		maxBytes = 20 * 1024 * 1024
	}
	if maxInlineBytes <= 0 || maxInlineBytes > maxBytes/2 {
		maxInlineBytes = 2 * 1024 * 1024
		if maxInlineBytes > maxBytes/2 {
			maxInlineBytes = maxBytes / 2
		}
	}
	return &RingBuffer{
		maxMessages:    maxMessages,
		maxBytes:       maxBytes,
		maxInlineBytes: maxInlineBytes,
		messages:       make([]*Message, 0, maxMessages),
		byID:           make(map[string]*Message),
		filesByID:      make(map[string]*FileMeta),
		onEvictFile:    onEvictFile,
	}
}

// computeMessageFootprint estimates the exact RAM occupied by a Message in the ring buffer.
func computeMessageFootprint(m *Message) int64 {
	const baseStructOverhead = 256
	size := int64(baseStructOverhead + len(m.ID) + len(m.SenderID) + len(m.SenderName) + len(m.Text) + len(m.InlineData))
	if m.File != nil {
		size += int64(128 + len(m.File.FileID) + len(m.File.FileName) + len(m.File.LocalPath) + len(m.File.DownloadURL))
	}
	return size
}

// Add inserts a message into the ring buffer, evicting oldest entries if needed to stay strictly under watermarks.
// If the message ID already exists (deduplication across P2P mesh), it returns false without duplicating.
func (rb *RingBuffer) Add(msg *Message) (added bool, err error) {
	if int64(len(msg.InlineData)) > rb.maxInlineBytes {
		return false, ErrPayloadTooLarge
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if _, exists := rb.byID[msg.ID]; exists {
		return false, nil
	}

	if msg.CreatedAt == 0 {
		msg.CreatedAt = time.Now().UnixMilli()
	}
	msg.MemoryBytes = computeMessageFootprint(msg)

	if msg.MemoryBytes > rb.maxBytes {
		return false, ErrPayloadTooLarge
	}

	// Evict oldest messages until both message count and byte watermarks have room
	for len(rb.messages) > 0 && (len(rb.messages) >= rb.maxMessages || rb.currentBytes+msg.MemoryBytes > rb.maxBytes) {
		rb.evictOldestLocked()
	}

	rb.messages = append(rb.messages, msg)
	rb.byID[msg.ID] = msg
	if msg.File != nil && msg.File.FileID != "" {
		rb.filesByID[msg.File.FileID] = msg.File
	}
	rb.currentBytes += msg.MemoryBytes
	return true, nil
}

func (rb *RingBuffer) evictOldestLocked() {
	if len(rb.messages) == 0 {
		return
	}
	oldest := rb.messages[0]
	// Nil out the slot before slicing so GC can reclaim the underlying pointer immediately
	rb.messages[0] = nil
	rb.messages = rb.messages[1:]

	delete(rb.byID, oldest.ID)
	rb.currentBytes -= oldest.MemoryBytes
	if rb.currentBytes < 0 {
		rb.currentBytes = 0
	}
	oldest.InlineData = nil

	if oldest.File != nil {
		delete(rb.filesByID, oldest.File.FileID)
		if rb.onEvictFile != nil {
			rb.onEvictFile(oldest.File)
		}
	}
	rb.evictedCount++

	// Compact backing slice array periodically to avoid capacity retention
	if cap(rb.messages) > rb.maxMessages*2 && len(rb.messages) <= rb.maxMessages {
		compacted := make([]*Message, len(rb.messages), rb.maxMessages)
		copy(compacted, rb.messages)
		rb.messages = compacted
	}
}

// List returns a snapshot of messages visible to the local node (public timeline + messages involving localPeerID).
func (rb *RingBuffer) List(localPeerID string) []*Message {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	out := make([]*Message, 0, len(rb.messages))
	for _, m := range rb.messages {
		if m.TargetPeerID == "" || m.TargetPeerID == localPeerID || m.SenderID == localPeerID {
			out = append(out, m)
		}
	}
	return out
}

// GetMessage retrieves a message by ID (used for serving inline clipboard images).
func (rb *RingBuffer) GetMessage(id string) (*Message, bool) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	m, ok := rb.byID[id]
	return m, ok
}

// GetFile retrieves file metadata by FileID (used for streaming file downloads).
func (rb *RingBuffer) GetFile(fileID string) (*FileMeta, bool) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	f, ok := rb.filesByID[fileID]
	return f, ok
}

// Clear wipes all messages and invokes cleanup callbacks for any temporary spooled files.
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for i, m := range rb.messages {
		if m != nil && m.File != nil && rb.onEvictFile != nil {
			rb.onEvictFile(m.File)
		}
		if m != nil {
			m.InlineData = nil
		}
		rb.messages[i] = nil
	}
	rb.messages = make([]*Message, 0, rb.maxMessages)
	rb.byID = make(map[string]*Message)
	rb.filesByID = make(map[string]*FileMeta)
	rb.currentBytes = 0
}

// Stats returns the current memory and count usage of the ring buffer.
func (rb *RingBuffer) Stats() Stats {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return Stats{
		CurrentMessages: len(rb.messages),
		MaxMessages:     rb.maxMessages,
		CurrentBytes:    rb.currentBytes,
		MaxBytes:        rb.maxBytes,
		EvictedCount:    rb.evictedCount,
	}
}
