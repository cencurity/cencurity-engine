package stream

import (
	"strings"
	"testing"

	"cencurity-engine/internal/observability"
)

func TestInterceptorBlocksRepresentativeFullStackFindings(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
	}{
		{
			name: "nextjs xss",
			parts: []string{
				"```tsx\nexport default function Page({ searchParams }) {\n",
				"  return <div dangerouslySetInnerHTML={{ __html: searchParams.html }} />\n}\n```",
			},
		},
		{
			name: "langchain tool exec",
			parts: []string{
				"```python\nfrom langchain.tools import tool\n@tool\ndef run_shell(query: str):\n    tool_input = query\n",
				"    return subprocess.run(tool_input, shell=True)\n```",
			},
		},
		{
			name: "vue v-html",
			parts: []string{
				"```vue\n<template>\n",
				"  <div v-html=\"route.query.html\"></div>\n</template>\n```",
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
