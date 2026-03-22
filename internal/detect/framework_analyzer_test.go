package detect

import "testing"

func TestFrameworkAnalyzerFlaskSSRFFinding(t *testing.T) {
	analyzer := NewFrameworkAnalyzer()
	unit := "```python\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.get(\"/fetch\")\ndef fetch_remote():\n    target = request.args.get(\"url\")\n    return requests.get(target).text\n```"
	findings := analyzer.Analyze(unit, ContentContextCodeBlock)
	assertFrameworkFinding(t, findings, "cast.flask.ssrf", LanguagePython, "flask")
}

func TestFrameworkAnalyzerReactXSSFinding(t *testing.T) {
	analyzer := NewFrameworkAnalyzer()
	unit := "```tsx\nimport React from 'react'\nexport function Page({ searchParams }) {\n  return <div dangerouslySetInnerHTML={{ __html: searchParams.html }} />\n}\n```"
	findings := analyzer.Analyze(unit, ContentContextCodeBlock)
	assertFrameworkFinding(t, findings, "cast.react.xss", LanguageJavaScript, "react")
}

func TestFrameworkAnalyzerSpringAuthFinding(t *testing.T) {
	analyzer := NewFrameworkAnalyzer()
	unit := "```java\nimport org.springframework.security.config.annotation.web.builders.HttpSecurity;\nhttp.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());\n```"
	findings := analyzer.Analyze(unit, ContentContextCodeBlock)
	assertFrameworkFinding(t, findings, "cast.spring.authz", LanguageJava, "spring")
}

func assertFrameworkFinding(t *testing.T, findings []Finding, ruleID string, language Language, framework string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			if finding.Language != language {
				t.Fatalf("expected language %s, got %s", language, finding.Language)
			}
			if finding.Framework != framework {
				t.Fatalf("expected framework %s, got %s", framework, finding.Framework)
			}
			return
		}
	}
	t.Fatalf("expected rule %s, got %#v", ruleID, findings)
}
