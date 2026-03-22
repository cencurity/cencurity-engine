package detect

import "strings"

// NormalizedText stores a compacted view and its byte-offset mapping.
type NormalizedText struct {
	Text   string
	Offset []int
}

// CompactNormalize removes separators and lowercases text for resilient matching.
func CompactNormalize(text string) NormalizedText {
	var builder strings.Builder
	builder.Grow(len(text))
	offsets := make([]int, 0, len(text))
	for index := 0; index < len(text); index++ {
		current := text[index]
		if !isCompactToken(current) {
			continue
		}
		builder.WriteByte(toLowerASCII(current))
		offsets = append(offsets, index)
	}
	return NormalizedText{Text: builder.String(), Offset: offsets}
}

func isCompactToken(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func toLowerASCII(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}
