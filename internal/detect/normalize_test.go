package detect

import "testing"

// TestCompactNormalize verifies separator-tolerant normalization.
func TestCompactNormalize(t *testing.T) {
	normalized := CompactNormalize("s k-12_34\n56")
	if normalized.Text != "sk123456" {
		t.Fatalf("unexpected normalized text: %q", normalized.Text)
	}
	if len(normalized.Offset) != len(normalized.Text) {
		t.Fatalf("unexpected offset count: %d", len(normalized.Offset))
	}
}
