package stream

import (
	"io"
	"strings"
	"testing"
)

// TestSSEReaderMultilineData verifies multiline SSE data parsing.
func TestSSEReaderMultilineData(t *testing.T) {
	reader := NewSSEReader(strings.NewReader("event: message\nid: 42\ndata: one\ndata: two\n\n"))
	event, err := reader.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent() error = %v", err)
	}
	if event.Event != "message" || event.ID != "42" {
		t.Fatalf("unexpected event metadata: %#v", event)
	}
	if event.Data != "one\ntwo" {
		t.Fatalf("unexpected data: %q", event.Data)
	}
}

// TestSSEReaderDone verifies [DONE] detection.
func TestSSEReaderDone(t *testing.T) {
	reader := NewSSEReader(strings.NewReader("data: [DONE]\n\n"))
	event, err := reader.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent() error = %v", err)
	}
	if !event.Done {
		t.Fatal("expected done event")
	}
	_, err = reader.ReadEvent()
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}
