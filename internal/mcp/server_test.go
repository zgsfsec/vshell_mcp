package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chinaran404/vshell-mcp/internal/vshell"
)

// newTestServer spins up the MCP HTTP handler without touching v_shell: the
// MCP handshake and tool listing never call the upstream API.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	vs := vshell.NewClient(vshell.Config{
		BaseURL:  "http://127.0.0.1:1",
		Prefix:   "/api",
		Username: "user",
		Password: "pass",
		Timeout:  time.Second,
	})
	ts := httptest.NewServer(New(vs, "http://127.0.0.1:1", "test").HTTPHandler(""))
	t.Cleanup(ts.Close)
	return ts
}

func postJSON(t *testing.T, url, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}

func TestHTTPHandlerServesStreamableHTTP(t *testing.T) {
	ts := newTestServer(t)

	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"go-test","version":"1.0"}}}`
	resp := postJSON(t, ts.URL+"/mcp", initBody, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("initialize status = %d, body = %s", resp.StatusCode, raw)
	}
	session := resp.Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("initialize response is missing Mcp-Session-Id")
	}
	var initResp struct {
		Result struct {
			ServerInfo struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		t.Fatalf("decode initialize response: %v", err)
	}
	if initResp.Result.ServerInfo.Name != "vshell-mcp" {
		t.Fatalf("serverInfo.name = %q, want %q", initResp.Result.ServerInfo.Name, "vshell-mcp")
	}

	listResp := postJSON(t, ts.URL+"/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, map[string]string{
		"Mcp-Session-Id": session,
	})
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(listResp.Body)
		t.Fatalf("tools/list status = %d, body = %s", listResp.StatusCode, raw)
	}
	raw, err := io.ReadAll(listResp.Body)
	if err != nil {
		t.Fatalf("read tools/list body: %v", err)
	}
	if !strings.Contains(string(raw), `"list_hosts"`) || !strings.Contains(string(raw), `"execute_command"`) {
		t.Fatalf("tools/list does not contain expected tools: %s", raw)
	}
}

func TestHTTPHandlerServesSSE(t *testing.T) {
	ts := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get /sse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sse status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("GET /sse content-type = %q", ct)
	}

	var seen strings.Builder
	buf := make([]byte, 256)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(seen.String(), "event: endpoint") {
		n, err := resp.Body.Read(buf)
		seen.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if !strings.Contains(seen.String(), "event: endpoint") {
		t.Fatalf("SSE stream missing endpoint event: %q", seen.String())
	}
}

func TestHTTPHandlerUnknownPathReturns404(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/nope")
	if err != nil {
		t.Fatalf("get /nope: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /nope status = %d, want 404", resp.StatusCode)
	}
}
