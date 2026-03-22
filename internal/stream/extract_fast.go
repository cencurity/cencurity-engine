package stream

import (
	"io"
	"strconv"
	"strings"
)

var fastExtractMarkers = []string{`"content":"`, `"text":"`, `"completion":"`}

// extractTextValues parses common streaming payloads with a low-allocation fast path.
func extractTextValues(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, io.EOF
	}
	texts := make([]string, 0, 2)
	searchFrom := 0
	for searchFrom < len(raw) {
		markerStart, markerLen := nextMarker(raw, searchFrom)
		if markerStart < 0 {
			break
		}
		valueStart := markerStart + markerLen
		value, end, ok := scanJSONString(raw, valueStart)
		if !ok {
			searchFrom = valueStart
			continue
		}
		texts = append(texts, value)
		searchFrom = end
	}
	if len(texts) == 0 {
		return nil, strconv.ErrSyntax
	}
	return texts, nil
}

func nextMarker(raw string, from int) (int, int) {
	best := -1
	bestLen := 0
	for _, marker := range fastExtractMarkers {
		index := strings.Index(raw[from:], marker)
		if index < 0 {
			continue
		}
		absolute := from + index
		if best == -1 || absolute < best {
			best = absolute
			bestLen = len(marker)
		}
	}
	return best, bestLen
}

func scanJSONString(raw string, start int) (string, int, bool) {
	escaped := false
	for index := start; index < len(raw); index++ {
		switch raw[index] {
		case '\\':
			escaped = !escaped
		case '"':
			if escaped {
				escaped = false
				continue
			}
			segment := raw[start:index]
			if strings.IndexByte(segment, '\\') == -1 {
				return segment, index + 1, true
			}
			decoded, err := strconv.Unquote(`"` + segment + `"`)
			if err != nil {
				return "", index + 1, false
			}
			return decoded, index + 1, true
		default:
			escaped = false
		}
	}
	return "", len(raw), false
}
