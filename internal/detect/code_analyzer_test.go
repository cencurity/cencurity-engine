package detect

import "testing"

func TestCodeAnalyzerFindsSQLInjectionSourceSink(t *testing.T) {
	analyzer := NewCodeAnalyzer()
	unit := "```python\nuser_id = request.args[\"id\"]\ndb.Query(\"SELECT * FROM users WHERE id = \" + user_id)\n```"
	findings := analyzer.AnalyzeCodeUnit(unit, ContentContextCodeBlock)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, finding := range findings {
		if finding.RuleID == "cast.sqli.source-sink" {
			if finding.Language != LanguagePython {
				t.Fatalf("expected python language, got %s", finding.Language)
			}
			return
		}
	}
	t.Fatalf("expected cast.sqli.source-sink, got %#v", findings)
}

func TestCodeAnalyzerFindsSSRFFromTaintedVariable(t *testing.T) {
	analyzer := NewCodeAnalyzer()
	unit := "```python\ntarget = request.args[\"url\"]\nrequests.get(target)\n```"
	findings := analyzer.AnalyzeCodeUnit(unit, ContentContextCodeBlock)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, finding := range findings {
		if finding.RuleID == "cast.ssrf.source-sink" {
			if finding.Language != LanguagePython {
				t.Fatalf("expected python language, got %s", finding.Language)
			}
			return
		}
	}
	t.Fatalf("expected cast.ssrf.source-sink, got %#v", findings)
}
