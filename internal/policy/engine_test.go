package policy

import (
	"testing"
	"time"

	"cencurity-engine/internal/detect"
	"cencurity-engine/internal/rules"
)

func TestDecideDowngradesPlainTextBlockToRedact(t *testing.T) {
	manager, err := rules.NewManager("", time.Hour, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	engine := NewEngine(manager)
	decision := engine.Decide([]detect.Detection{{RuleID: "vuln.xss.raw-html", Category: "app-vulnerability"}}, detect.ContentContextPlain)
	if decision.Action != ActionRedact {
		t.Fatalf("expected redact for plain text explanation, got %s", decision.Action)
	}
}

func TestDecideBlocksCodeLikeAppVulnerability(t *testing.T) {
	manager, err := rules.NewManager("", time.Hour, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	engine := NewEngine(manager)
	decision := engine.Decide([]detect.Detection{{RuleID: "vuln.sqli.concat-query", Category: "app-vulnerability"}}, detect.ContentContextCodeBlock)
	if decision.Action != ActionBlock {
		t.Fatalf("expected block for code-like vulnerability, got %s", decision.Action)
	}
}
