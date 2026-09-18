package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTransport(t *testing.T) {
	cases := []struct {
		in      string
		want    Transport
		wantErr bool
	}{
		{in: "", want: DefaultTransport},
		{in: "sse", want: TransportSSE},
		{in: "SSE", want: TransportSSE},
		{in: " stdio ", want: TransportStdio},
		{in: "streamable", want: TransportStreamable},
		{in: "streamable-http", want: TransportStreamable},
		{in: "streamable_http", want: TransportStreamable},
		{in: "http", want: TransportStreamable},
		{in: "both", want: TransportBoth},
		{in: "gopher", wantErr: true},
	}
	for _, tc := range cases {
		got, err := ParseTransport(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseTransport(%q): want error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTransport(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseTransport(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The default must keep legacy SSE clients working while modern clients get
// Streamable HTTP, so it serves both endpoints on one listener.
func TestDefaultTransportServesBoth(t *testing.T) {
	if DefaultTransport != TransportBoth {
		t.Fatalf("DefaultTransport = %q, want %q", DefaultTransport, TransportBoth)
	}
}

// HTTPHandler must refuse stdio: that transport has no HTTP surface.
func TestHTTPHandlerRejectsStdio(t *testing.T) {
	s := New(nil, "http://vshell.test", "test")
	if _, err := s.HTTPHandler(TransportStdio, "", "secret"); err == nil {
		t.Fatal("HTTPHandler(stdio) returned no error")
	}
}

// The bearer check must cover the Streamable HTTP endpoint as well as SSE.
func TestStreamableEndpointRequiresBearer(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	ts := serverFor(t, TransportStreamable, token)

	resp := postInitialize(t, ts.URL+StreamablePath, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated initialize: status %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
		t.Fatalf("unauthorized response lacks a Bearer challenge: %q", got)
	}
	resp.Body.Close()

	resp = postInitialize(t, ts.URL+StreamablePath, "Bearer "+token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated initialize: status %d, want 200", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "vshell-mcp") {
		t.Fatalf("initialize reply does not name the server: %q", truncate(body))
	}
}

// One listener serving both transports: /mcp and /sse are distinct endpoints
// behind the same auth wrapper.
func TestBothTransportRoutes(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	ts := serverFor(t, TransportBoth, token)

	if code := sseStatus(t, ts.URL+"/sse", ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /sse: status %d, want 401", code)
	}
	if code := sseStatus(t, ts.URL+"/sse", "Bearer "+token); code != http.StatusOK {
		t.Fatalf("authenticated /sse: status %d, want 200", code)
	}

	resp := postInitialize(t, ts.URL+StreamablePath, "Bearer "+token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /mcp: status %d, want 200", resp.StatusCode)
	}
}

// -noauth (authToken == "") leaves both endpoints open by design.
func TestBothTransportWithoutAuthToken(t *testing.T) {
	ts := serverFor(t, TransportBoth, "")

	resp := postInitialize(t, ts.URL+StreamablePath, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unauthenticated /mcp with no token configured: status %d, want 200", resp.StatusCode)
	}
	if code := sseStatus(t, ts.URL+"/sse", ""); code != http.StatusOK {
		t.Fatalf("unauthenticated /sse with no token configured: status %d, want 200", code)
	}
}

// serverFor starts an httptest server exposing one transport behind the bearer
// check; the tool handlers are never reached, so the v_shell client stays nil.
func serverFor(t *testing.T, transport Transport, authToken string) *httptest.Server {
	t.Helper()
	s := New(nil, "http://vshell.test", "test")
	handler, err := s.HTTPHandler(transport, "", authToken)
	if err != nil {
		t.Fatalf("HTTPHandler(%q): %v", transport, err)
	}
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func postInitialize(t *testing.T, url, authorization string) *http.Response {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "transport-test", "version": "1"},
		},
	})
	if err != nil {
		t.Fatalf("marshal initialize: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build initialize request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// sseStatus opens the SSE stream far enough to read the status line, then
// cancels the request so the handler's stream is torn down.
func sseStatus(t *testing.T, url, authorization string) int {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build SSE request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	status := resp.StatusCode
	cancel()
	resp.Body.Close()
	return status
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return buf.String()
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
