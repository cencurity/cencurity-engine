package stream

import (
	"strings"
	"testing"

	"cencurity-engine/internal/observability"
)

func TestInterceptorBlocksLangGraphAccumulatedFindings(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
	}{
		{
			name: "langgraph command from state",
			parts: []string{
				"```python\nfrom langgraph.graph import StateGraph\ndef node(state):\n    cmd = state['command']\n",
				"    return subprocess.run(cmd, shell=True)\n```",
			},
		},
		{
			name: "langgraph command goto from input",
			parts: []string{
				"```python\nfrom langgraph.types import Command\ndef node(state):\n",
				"    return Command(goto=state['next'])\n```",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interceptor := newTestInterceptor(t)
			writer := newFlushRecorder()
			cancelled := false
			var payload strings.Builder
			for _, part := range test.parts {
				payload.WriteString("data: {\"choices\":[{\"delta\":{\"content\":")
				payload.WriteString(quoteJSONString(part))
				payload.WriteString("}}]}\n\n")
			}
			logger := observability.NewLogger("error")
			if err := interceptor.Stream(writer, strings.NewReader(payload.String()), func() { cancelled = true }, RequestMeta{RequestID: test.name, Vendor: "test", Model: "test-model"}, logger); err != nil {
				t.Fatalf("Stream() error = %v", err)
			}
			if !cancelled {
				t.Fatal("expected cancel to be called")
			}
			if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
				t.Fatalf("expected block output, got %s", writer.buffer.String())
			}
		})
	}
}
