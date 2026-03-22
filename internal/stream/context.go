package stream

import (
	"strings"

	"cencurity-engine/internal/detect"
)

// ContextTracker keeps shallow code/plain state across streamed chunks.
type ContextTracker struct {
	inFence  bool
	inInline bool
}

// Classify returns the current shallow context before state is updated.
func (c *ContextTracker) Classify(text string) detect.ContentContext {
	if c.inFence || isCodeLike(text) {
		return detect.ContentContextCodeBlock
	}
	if c.inInline || strings.Contains(text, "`") {
		return detect.ContentContextInlineCode
	}
	return detect.ContentContextPlain
}

// Advance updates state after a chunk has been processed.
func (c *ContextTracker) Advance(text string) {
	fenceCount := strings.Count(text, "```")
	if fenceCount%2 == 1 {
		c.inFence = !c.inFence
	}
	inlineCount := countInlineBackticks(text)
	if inlineCount%2 == 1 {
		c.inInline = !c.inInline
	}
	if c.inFence {
		c.inInline = false
	}
}

func countInlineBackticks(text string) int {
	return strings.Count(strings.ReplaceAll(text, "```", ""), "`")
}

func isCodeLike(text string) bool {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "def "):
		return true
	case strings.Contains(lower, "function "):
		return true
	case strings.Contains(lower, "class "):
		return true
	case strings.Contains(lower, "return "):
		return true
	case strings.Contains(lower, "eval("):
		return true
	case strings.Contains(lower, "exec("):
		return true
	case strings.Contains(lower, "os.system"):
		return true
	case strings.Contains(lower, "subprocess"):
		return true
	case strings.Contains(lower, "db.query"):
		return true
	case strings.Contains(lower, "select "):
		return true
	case strings.Contains(lower, "requests.get("):
		return true
	case strings.Contains(lower, "innerhtml"):
		return true
	case strings.Contains(lower, "csrf().disable"):
		return true
	case strings.Contains(lower, "permitall"):
		return true
	case strings.Contains(lower, "curl ") && strings.Contains(lower, "| sh"):
		return true
	case strings.Contains(lower, "```"):
		return true
	default:
		return false
	}
}
