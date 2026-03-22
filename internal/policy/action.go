package policy

// Action describes how a chunk should be handled.
type Action string

const (
	// ActionAllow forwards the chunk unchanged.
	ActionAllow Action = "allow"
	// ActionRedact masks sensitive substrings before forwarding.
	ActionRedact Action = "redact"
	// ActionBlock terminates the stream and suppresses unsafe output.
	ActionBlock Action = "block"
)
