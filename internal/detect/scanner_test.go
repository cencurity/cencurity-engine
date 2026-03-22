package detect

import (
	"testing"
	"time"

	"cencurity-engine/internal/rules"
)

// TestScannerCrossChunkAPIKey verifies detection across chunk boundaries.
func TestScannerCrossChunkAPIKey(t *testing.T) {
	manager, err := rules.NewManager("", time.Hour, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	scanner := NewScanner(manager)
	detections := scanner.Scan("print(\"sk-1234567890", "abcdef\")")
	if len(detections) == 0 {
		t.Fatal("expected cross-chunk detection")
	}
	if detections[0].RuleID != "secret.openai-key" {
		t.Fatalf("unexpected rule id: %s", detections[0].RuleID)
	}
}

// TestScannerObfuscatedEval verifies simple whitespace-obfuscated code detection.
func TestScannerObfuscatedEval(t *testing.T) {
	manager, err := rules.NewManager("", time.Hour, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	scanner := NewScanner(manager)
	detections := scanner.Scan("", "e v a l(")
	if len(detections) == 0 {
		t.Fatal("expected eval detection")
	}
	if detections[0].RuleID != "code.eval" {
		t.Fatalf("unexpected rule id: %s", detections[0].RuleID)
	}
}

func TestScannerAppVulnerabilityRules(t *testing.T) {
	manager, err := rules.NewManager("", time.Hour, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	scanner := NewScanner(manager)
	tests := []struct {
		name   string
		chunk  string
		ruleID string
	}{
		{name: "sqli concat", chunk: `db.Query("SELECT * FROM users WHERE id = " + request.args["id"])`, ruleID: "vuln.sqli.concat-query"},
		{name: "xss raw html", chunk: `element.innerHTML = req.query.content`, ruleID: "vuln.xss.raw-html"},
		{name: "csrf disabled", chunk: `http.csrf().disable()`, ruleID: "vuln.csrf.disabled"},
		{name: "ssrf user url", chunk: `requests.get(request.args.get("url"))`, ruleID: "vuln.ssrf.user-url-fetch"},
		{name: "path traversal user path", chunk: `os.Open(request.args.get("path"))`, ruleID: "vuln.path-traversal.user-path"},
		{name: "auth permit all", chunk: `http.authorizeHttpRequests().anyRequest().permitAll()`, ruleID: "vuln.authz.permit-all"},
		{name: "framework insecure tls", chunk: `tls.Config{InsecureSkipVerify: true}`, ruleID: "vuln.framework.insecure-tls"},
		{name: "business logic admin bypass", chunk: `if isAdmin or True: allow_access()`, ruleID: "vuln.business-logic.admin-bypass"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detections := scanner.Scan("", test.chunk)
			if len(detections) == 0 {
				t.Fatalf("expected detection for %s", test.name)
			}
			for _, detection := range detections {
				if detection.RuleID == test.ruleID {
					return
				}
			}
			t.Fatalf("expected rule %s, got %#v", test.ruleID, detections)
		})
	}
}
