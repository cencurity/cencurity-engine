package detect

import "testing"

func TestLangGraphFrameworkFindings(t *testing.T) {
	analyzer := NewFrameworkAnalyzer()
	tests := []struct {
		name   string
		unit   string
		ruleID string
	}{
		{
			name: "exec from messages",
			unit: "```python\nfrom langgraph.graph import StateGraph\ndef node(state):\n    return subprocess.run(state['messages'][-1].content, shell=True)\n```",
			ruleID: "cast.langgraph.exec-from-messages",
		},
		{
			name: "command from state",
			unit: "```python\nfrom langgraph.graph import StateGraph\ndef node(state):\n    cmd = state['command']\n    return subprocess.run(cmd, shell=True)\n```",
			ruleID: "cast.langgraph.command-from-state",
		},
		{
			name: "toolnode untrusted state",
			unit: "```python\nfrom langgraph.prebuilt import ToolNode\ndef node(state):\n    return ToolNode(state['tools'])\n```",
			ruleID: "cast.langgraph.toolnode-untrusted-state",
		},
		{
			name: "command goto from input",
			unit: "```python\nfrom langgraph.types import Command\ndef node(state):\n    return Command(goto=state['next'])\n```",
			ruleID: "cast.langgraph.command-goto-from-input",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := analyzer.Analyze(test.unit, ContentContextCodeBlock)
			assertFrameworkFinding(t, findings, test.ruleID, LanguagePython, "langgraph")
		})
	}
}
