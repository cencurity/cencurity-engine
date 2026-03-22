package stream

import "cencurity-engine/internal/detect"

const defaultCodeBufferSize = 8192

// CodeBuffer keeps a larger rolling code-unit context for CAST analysis.
type CodeBuffer struct {
	window *Window
}

// NewCodeBuffer creates a bounded code accumulator.
func NewCodeBuffer(size int) *CodeBuffer {
	return &CodeBuffer{window: NewWindow(size)}
}

// ContextFor returns accumulated code-like text.
func (b *CodeBuffer) ContextFor() string {
	if b == nil {
		return ""
	}
	return b.window.ContextFor()
}

// Add appends text only when it looks like generated code.
func (b *CodeBuffer) Add(text string, context detect.ContentContext) {
	if b == nil || text == "" || context == detect.ContentContextPlain {
		return
	}
	b.window.Add(text)
}
