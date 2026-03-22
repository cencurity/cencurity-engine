package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"cencurity-engine/internal/config"
)

// Upstream sends proxied requests to the LLM provider.
type Upstream struct {
	baseURL *url.URL
	client  *http.Client
}

// NewUpstream creates an upstream client from runtime configuration.
func NewUpstream(cfg config.Config) (*Upstream, error) {
	baseURL, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream url: %w", err)
	}

	return &Upstream{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
	}, nil
}

// Do forwards the incoming HTTP request to the configured upstream.
func (u *Upstream) Do(incoming *http.Request) (*http.Response, error) {
	outgoingURL := *u.baseURL
	outgoingURL.Path = joinURLPath(u.baseURL.Path, incoming.URL.Path)
	outgoingURL.RawQuery = incoming.URL.RawQuery

	body, err := cloneBody(incoming.Body)
	if err != nil {
		return nil, fmt.Errorf("clone request body: %w", err)
	}

	request, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, outgoingURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}

	copyRequestHeaders(request.Header, incoming.Header)
	request.Host = u.baseURL.Host
	request.ContentLength = incoming.ContentLength

	response, err := u.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("execute upstream request: %w", err)
	}

	return response, nil
}

// Vendor returns a stable upstream vendor label for logging.
func (u *Upstream) Vendor() string {
	host := strings.ToLower(u.baseURL.Host)
	switch {
	case strings.Contains(host, "openai"):
		return "openai"
	case strings.Contains(host, "x.ai") || strings.Contains(host, "xai"):
		return "xai"
	case strings.Contains(host, "anthropic"):
		return "anthropic"
	case strings.Contains(host, "google") || strings.Contains(host, "gemini"):
		return "google"
	default:
		return host
	}
}

func cloneBody(source io.ReadCloser) (io.ReadCloser, error) {
	if source == nil {
		return http.NoBody, nil
	}

	payload, err := io.ReadAll(source)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(string(payload))), nil
}

func copyRequestHeaders(destination, source http.Header) {
	for key, values := range source {
		if isHopByHopHeader(key) || strings.EqualFold(key, "Host") {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func joinURLPath(basePath, requestPath string) string {
	switch {
	case basePath == "":
		return requestPath
	case requestPath == "":
		return basePath
	default:
		joined := path.Join(basePath, requestPath)
		if strings.HasSuffix(requestPath, "/") && !strings.HasSuffix(joined, "/") {
			return joined + "/"
		}
		return joined
	}
}

func isHopByHopHeader(key string) bool {
	switch {
	case strings.EqualFold(key, "Connection"):
		return true
	case strings.EqualFold(key, "Proxy-Connection"):
		return true
	case strings.EqualFold(key, "Keep-Alive"):
		return true
	case strings.EqualFold(key, "Proxy-Authenticate"):
		return true
	case strings.EqualFold(key, "Proxy-Authorization"):
		return true
	case strings.EqualFold(key, "Te"):
		return true
	case strings.EqualFold(key, "Trailer"):
		return true
	case strings.EqualFold(key, "Transfer-Encoding"):
		return true
	case strings.EqualFold(key, "Upgrade"):
		return true
	default:
		return false
	}
}
