package stream

// Window keeps a short sliding context for cross-chunk scanning.
type Window struct {
	size   int
	buf    []byte
	start  int
	length int
}

// NewWindow creates a fixed-size sliding buffer.
func NewWindow(size int) *Window {
	if size < 0 {
		size = 0
	}
	return &Window{size: size, buf: make([]byte, max(1, size))}
}

// Add appends text and keeps only the most recent bytes.
func (w *Window) Add(text string) {
	if w.size == 0 || text == "" {
		return
	}
	for index := 0; index < len(text); index++ {
		writeIndex := (w.start + w.length) % w.size
		w.buf[writeIndex] = text[index]
		if w.length < w.size {
			w.length++
			continue
		}
		w.start = (w.start + 1) % w.size
	}
}

// ContextFor returns the current raw prefix buffer.
func (w *Window) ContextFor() string {
	if w.length == 0 {
		return ""
	}
	if w.length < w.size && w.start == 0 {
		return string(w.buf[:w.length])
	}
	result := make([]byte, w.length)
	for index := 0; index < w.length; index++ {
		result[index] = w.buf[(w.start+index)%w.size]
	}
	return string(result)
}

// Tail returns up to the last limit bytes of buffered context.
func (w *Window) Tail(limit int) string {
	if limit <= 0 || w.length == 0 {
		return ""
	}
	if limit > w.length {
		limit = w.length
	}
	start := w.length - limit
	result := make([]byte, limit)
	for index := 0; index < limit; index++ {
		result[index] = w.buf[(w.start+start+index)%w.size]
	}
	return string(result)
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
