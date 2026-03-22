package detect

import "regexp"

type pattern struct {
	RuleID   string
	Category string
	Severity string
	Regex    *regexp.Regexp
}

var compiledPatterns = []pattern{
	{
		RuleID:   "api-key.openai",
		Category: "secret",
		Severity: "high",
		Regex:    regexp.MustCompile(`sk-[A-Za-z0-9_-]{10,}`),
	},
	{
		RuleID:   "code.eval",
		Category: "dangerous-code",
		Severity: "high",
		Regex:    regexp.MustCompile(`(?i)\beval\s*\(`),
	},
	{
		RuleID:   "code.exec",
		Category: "dangerous-code",
		Severity: "high",
		Regex:    regexp.MustCompile(`(?i)\bexec\s*\(`),
	},
	{
		RuleID:   "secret.private-key",
		Category: "secret",
		Severity: "critical",
		Regex:    regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----|BEGIN PRIVATE KEY`),
	},
	{
		RuleID:   "code.shell",
		Category: "dangerous-code",
		Severity: "high",
		Regex: regexp.MustCompile(
			`(?i)\bos\.system\b|\bsubprocess\.(run|Popen|call)\b|shell\s*=\s*True|/bin/sh|cmd\.exe\s*/c|powershell\.exe\b`,
		),
	},
}
