package loadtest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveShadowProvider(t *testing.T) {
	tests := []struct {
		name     string
		override string
		upstream string
		want     shadowProvider
	}{
		{name: "default openai", upstream: "https://api.openai.com", want: shadowProviderOpenAI},
		{name: "anthropic host", upstream: "https://api.anthropic.com", want: shadowProviderAnthropic},
		{name: "gemini host", upstream: "https://generativelanguage.googleapis.com", want: shadowProviderGemini},
		{name: "override gemini", override: "gemini", upstream: "https://example.com", want: shadowProviderGemini},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveShadowProvider(test.override, test.upstream)
			if err != nil {
				t.Fatalf("resolveShadowProvider() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("resolveShadowProvider() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBuildShadowRequestSpec(t *testing.T) {
	tests := []struct {
		name            string
		provider        shadowProvider
		wantPath        string
		wantHeaderKey   string
		wantHeaderValue string
		wantBody        string
		wantQuery       string
	}{
		{name: "openai", provider: shadowProviderOpenAI, wantPath: "/v1/chat/completions", wantHeaderKey: "Authorization", wantHeaderValue: "Bearer test-key", wantBody: `"messages"`},
		{name: "anthropic", provider: shadowProviderAnthropic, wantPath: "/v1/messages", wantHeaderKey: "x-api-key", wantHeaderValue: "test-key", wantBody: `"max_tokens":1024`},
		{name: "gemini", provider: shadowProviderGemini, wantPath: "/v1beta/models/gemini-2.5-pro:streamGenerateContent", wantHeaderKey: "x-goog-api-key", wantHeaderValue: "test-key", wantBody: `"contents"`, wantQuery: "alt=sse"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, err := buildShadowRequestSpec(test.provider, "gemini-2.5-pro", "test-key", "hello")
			if err != nil {
				t.Fatalf("buildShadowRequestSpec() error = %v", err)
			}
			if spec.path != test.wantPath {
				t.Fatalf("path = %q, want %q", spec.path, test.wantPath)
			}
			if spec.headers[test.wantHeaderKey] != test.wantHeaderValue {
				t.Fatalf("header %s = %q, want %q", test.wantHeaderKey, spec.headers[test.wantHeaderKey], test.wantHeaderValue)
			}
			if !strings.Contains(string(spec.body), test.wantBody) {
				t.Fatalf("body = %s, want substring %s", string(spec.body), test.wantBody)
			}
			if test.wantQuery != "" && spec.query.Encode() != test.wantQuery {
				t.Fatalf("query = %q, want %q", spec.query.Encode(), test.wantQuery)
			}
		})
	}
}

func TestDoRealStreamingRequestProviderParsing(t *testing.T) {
	tests := []struct {
		name     string
		provider shadowProvider
		body     string
		want     string
	}{
		{name: "openai done allow", provider: shadowProviderOpenAI, body: "data: {\"choices\":[{\"delta\":{\"content\":\"safe\"}}]}\n\ndata: [DONE]\n\n", want: "allow"},
		{name: "anthropic redact", provider: shadowProviderAnthropic, body: "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"[REDACTED]\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", want: "redact"},
		{name: "gemini block", provider: shadowProviderGemini, body: "data: {\"error\":{\"status\":\"PERMISSION_DENIED\",\"message\":\"blocked by cencurity\"}}\n\n", want: "block"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "text/event-stream")
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()

			outcome, err := doRealStreamingRequest(server.Client(), server.URL, test.provider, "test-key", "test-model", "hello")
			if err != nil {
				t.Fatalf("doRealStreamingRequest() error = %v", err)
			}
			if outcome != test.want {
				t.Fatalf("outcome = %q, want %q", outcome, test.want)
			}
		})
	}
}