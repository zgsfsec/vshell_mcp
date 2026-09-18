package mcp

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chinaran404/vshell-mcp/internal/vshell"
	"github.com/mark3labs/mcp-go/mcp"
)

// mockAPI serves canned v_shell envelopes keyed by request path and counts how
// often each path was called, so a test can assert that an idempotent tool
// avoided calling the server at all.
func mockAPI(t *testing.T, routes map[string]string) (*vshell.Client, func(string) int) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls[r.URL.Path]++
		body, ok := routes[r.URL.Path]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	c := vshell.NewClient(vshell.Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})
	return c, func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return calls[path]
	}
}

// toolRequest builds the CallToolRequest a handler receives.
func toolRequest(name string, args map[string]any) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	return req
}
