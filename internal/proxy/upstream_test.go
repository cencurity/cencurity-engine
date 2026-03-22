package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cencurity-engine/internal/config"
)

// TestUpstreamTimeout verifies timeout classification at the upstream boundary.
func TestUpstreamTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		time.Sleep(100 * time.Millisecond)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	upstream, err := NewUpstream(config.Config{UpstreamURL: server.URL, RequestTimeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewUpstream() error = %v", err)
	}

	request, err := http.NewRequest(http.MethodGet, "http://localhost/test", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	_, err = upstream.Do(request)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
