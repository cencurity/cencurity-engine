package stream

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// SSEReader parses text/event-stream payloads into discrete events.
type SSEReader struct {
	reader *bufio.Reader
}

// NewSSEReader creates a reader for OpenAI-compatible SSE responses.
func NewSSEReader(source io.Reader) *SSEReader {
	return &SSEReader{reader: bufio.NewReader(source)}
}

// ReadEvent reads the next SSE event until a blank-line boundary.
func (r *SSEReader) ReadEvent() (Event, error) {
	var raw bytes.Buffer
	var dataLines []string
	var eventName string
	var eventID string

	for {
		line, err := r.reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return Event{}, err
		}

		if line != "" {
			raw.WriteString(line)
		}

		trimmedLine := strings.TrimRight(line, "\r\n")
		isBoundary := trimmedLine == ""
		isEOF := err == io.EOF

		if !isBoundary && trimmedLine != "" && !strings.HasPrefix(trimmedLine, ":") {
			field, value, found := strings.Cut(trimmedLine, ":")
			if found {
				if strings.HasPrefix(value, " ") {
					value = value[1:]
				}
				switch field {
				case "data":
					dataLines = append(dataLines, value)
				case "event":
					eventName = value
				case "id":
					eventID = value
				}
			}
		}

		if isBoundary || isEOF {
			if raw.Len() == 0 && isEOF {
				return Event{}, io.EOF
			}

			if raw.Len() == 0 {
				if isEOF {
					return Event{}, io.EOF
				}
				continue
			}

			data := strings.Join(dataLines, "\n")
			return Event{
				Raw:   raw.Bytes(),
				Event: eventName,
				ID:    eventID,
				Data:  data,
				Done:  strings.TrimSpace(data) == "[DONE]",
			}, nil
		}
	}
}
