package store

import (
	"fmt"
	"testing"
)

func TestRingBufferCountAndByteEviction(t *testing.T) {
	var evictedFiles []string
	rb := NewRingBuffer(5, 4096, 2048, func(meta *FileMeta) {
		evictedFiles = append(evictedFiles, meta.FileID)
	})

	// 1. Test count cap (max 5 messages)
	for i := 1; i <= 7; i++ {
		added, err := rb.Add(&Message{
			ID:         fmt.Sprintf("msg-%d", i),
			Kind:       KindText,
			SenderID:   "peer-a",
			SenderName: "Mac",
			Text:       fmt.Sprintf("hello %d", i),
		})
		if err != nil || !added {
			t.Fatalf("expected message %d to be added, got added=%v err=%v", i, added, err)
		}
	}

	stats := rb.Stats()
	if stats.CurrentMessages != 5 {
		t.Fatalf("expected 5 messages after count eviction, got %d", stats.CurrentMessages)
	}
	if stats.EvictedCount != 2 {
		t.Fatalf("expected 2 evicted messages, got %d", stats.EvictedCount)
	}
	if _, ok := rb.GetMessage("msg-1"); ok {
		t.Fatalf("expected msg-1 to be evicted")
	}
	if _, ok := rb.GetMessage("msg-7"); !ok {
		t.Fatalf("expected msg-7 to be present")
	}

	// 2. Test byte watermark eviction (add 2 messages with 1.5KB inline image each into 4KB max pool)
	payload := make([]byte, 1500)
	for i := 1; i <= 3; i++ {
		_, err := rb.Add(&Message{
			ID:         fmt.Sprintf("img-%d", i),
			Kind:       KindImage,
			SenderID:   "peer-a",
			InlineData: payload,
			File: &FileMeta{
				FileID: fmt.Sprintf("f-%d", i),
			},
		})
		if err != nil {
			t.Fatalf("unexpected error adding inline image %d: %v", i, err)
		}
	}

	stats = rb.Stats()
	if stats.CurrentBytes > stats.MaxBytes {
		t.Fatalf("memory watermark exceeded: %d > %d", stats.CurrentBytes, stats.MaxBytes)
	}
	if _, ok := rb.GetMessage("img-1"); ok {
		t.Fatalf("expected img-1 to be evicted due to 4096-byte cap")
	}
	if len(evictedFiles) == 0 || evictedFiles[0] != "f-1" {
		t.Fatalf("expected file cleanup callback for f-1, got %v", evictedFiles)
	}

	// 3. Test single inline limit rejection
	tooBig := make([]byte, 2500)
	if _, err := rb.Add(&Message{
		ID:         "too-big",
		Kind:       KindImage,
		InlineData: tooBig,
	}); err != ErrPayloadTooLarge {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}
