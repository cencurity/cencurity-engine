package policy

import (
	"sort"

	"cencurity-engine/internal/detect"
)

const redactedText = "[REDACTED]"

type span struct {
	start int
	end   int
}

// ApplyRedactions masks redactable ranges in the current chunk.
func ApplyRedactions(chunk string, detections []detect.Detection) string {
	if chunk == "" {
		return chunk
	}

	spans := make([]span, 0, len(detections))
	for _, detection := range detections {
		if detection.Start < 0 || detection.End > len(chunk) || detection.Start >= detection.End {
			continue
		}
		spans = append(spans, span{start: detection.Start, end: detection.End})
	}

	if len(spans) == 0 {
		return chunk
	}

	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end < spans[j].end
		}
		return spans[i].start < spans[j].start
	})

	merged := make([]span, 0, len(spans))
	for _, current := range spans {
		if len(merged) == 0 || current.start > merged[len(merged)-1].end {
			merged = append(merged, current)
			continue
		}
		if current.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = current.end
		}
	}

	result := chunk
	for index := len(merged) - 1; index >= 0; index-- {
		current := merged[index]
		result = result[:current.start] + redactedText + result[current.end:]
	}

	return result
}
