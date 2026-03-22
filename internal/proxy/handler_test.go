package proxy

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestClassifyError verifies stable error type labels.
func TestClassifyError(t *testing.T) {
	tests := map[string]error{
		"timeout":           errors.New("request timeout"),
		"client_disconnect": errors.New("broken pipe"),
		"io_error":          errors.New("random failure"),
	}
	for expected, input := range tests {
		if actual := classifyError(input); actual != expected {
			t.Fatalf("classifyError() = %s, want %s", actual, expected)
		}
	}
}

// TestEnsureRequestID verifies request id reuse and generation.
func TestEnsureRequestID(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("X-Request-Id", "abc")
	if value := ensureRequestID(request); value != "abc" {
		t.Fatalf("unexpected request id: %s", value)
	}
}

func TestExtractRequestModel(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{name: "openai body model", path: "/v1/chat/completions", body: `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`, want: "gpt-4o-mini"},
		{name: "claude messages model", path: "/v1/messages", body: `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}],"stream":true}`, want: "claude-sonnet-4-5"},
		{name: "gemini path model", path: "/v1beta/models/gemini-2.5-pro:streamGenerateContent", body: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`, want: "gemini-2.5-pro"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, "http://localhost"+test.path, strings.NewReader(test.body))
			if err != nil {
				t.Fatalf("NewRequest() error = %v", err)
			}
			if got := extractRequestModel(request); got != test.want {
				t.Fatalf("extractRequestModel() = %q, want %q", got, test.want)
			}
		})
	}
}
