package stream

import "strings"

// Event represents a single SSE event.
type Event struct {
	Raw   []byte
	Event string
	ID    string
	Data  string
	Done  bool
}

// EncodeWithData rebuilds the event using replacement data.
func (e Event) EncodeWithData(data string) []byte {
	var builder strings.Builder
	if e.Event != "" {
		builder.WriteString("event: ")
		builder.WriteString(e.Event)
		builder.WriteString("\n")
	}
	if e.ID != "" {
		builder.WriteString("id: ")
		builder.WriteString(e.ID)
		builder.WriteString("\n")
	}
	for _, line := range strings.Split(data, "\n") {
		builder.WriteString("data: ")
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	builder.WriteString("\n")
	return []byte(builder.String())
}

// Reader reads stream events one-by-one from an SSE response body.
type Reader interface {
	ReadEvent() (Event, error)
}
