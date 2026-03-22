package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestManagerReloadsFile verifies external rule reload after file changes.
func TestManagerReloadsFile(t *testing.T) {
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(policyPath, []byte(`{"rules":[{"id":"secret.openai-key","action":"block","enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	manager, err := NewManager(policyPath, time.Millisecond, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if manager.ActionFor("secret.openai-key") != "block" {
		t.Fatalf("unexpected action: %s", manager.ActionFor("secret.openai-key"))
	}

	time.Sleep(5 * time.Millisecond)
	if err := os.WriteFile(policyPath, []byte(`{"rules":[{"id":"secret.openai-key","action":"redact","enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	for attempt := 0; attempt < 20; attempt++ {
		if manager.ActionFor("secret.openai-key") == "redact" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected reloaded action, got %s", manager.ActionFor("secret.openai-key"))
}
