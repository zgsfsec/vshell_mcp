package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chinaran404/vshell-mcp/internal/vshell"
	"github.com/mark3labs/mcp-go/mcp"
)

// listenerHarness runs one listener-management handler against a stubbed v_shell
// API and returns the tool result plus what the API received.
//
// /listener/list is answered with one listener (Id 7) whose Status is the
// opposite of what the action asks for, so start/stop actually call through;
// every other path answers with envelope.
func listenerHarness(t *testing.T, tool string, args map[string]any, envelope string) (*mcp.CallToolResult, string, map[string]any) {
	t.Helper()
	var (
		mu   sync.Mutex
		path string
		body map[string]any
	)
	listEnvelope := fmt.Sprintf(`{"code":0,"message":"ok","result":{"items":[{"Id":7,"Mode":"tcp",`+
		`"ListenAddr":"0.0.0.0:21480","Status":%v,"DisconnectTimeout":30,"PingInterval":10,`+
		`"Vkey":"v","EncryptSalt":"s"}],"total":1},"type":"success"}`, tool != "start_listener")

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &body)
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/listener/list") {
			_, _ = w.Write([]byte(listEnvelope))
			return
		}
		_, _ = w.Write([]byte(envelope))
	}))
	t.Cleanup(api.Close)

	s := New(vshell.NewClient(vshell.Config{BaseURL: api.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second}), "http://vshell.test", "test")
	req := mcp.CallToolRequest{}
	req.Params.Name = tool
	req.Params.Arguments = args

	var (
		res *mcp.CallToolResult
		err error
	)
	switch tool {
	case "start_listener":
		res, err = s.handlerStartListener(context.Background(), req)
	case "stop_listener":
		res, err = s.handlerStopListener(context.Background(), req)
	case "edit_listener":
		res, err = s.handlerEditListener(context.Background(), req)
	case "set_listener_remark":
		res, err = s.handlerSetListenerRemark(context.Background(), req)
	default:
		t.Fatalf("unknown tool %q", tool)
	}
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return res, path, body
}

func TestStartStopListenerTools(t *testing.T) {
	for _, tc := range []struct{ tool, wantPath, wantStatus string }{
		{"start_listener", "/api/listener/start", "started"},
		{"stop_listener", "/api/listener/stop", "stopped"},
	} {
		res, path, body := listenerHarness(t, tc.tool, map[string]any{"id": float64(7)}, `{"code":0,"message":"ok","result":null}`)
		if res.IsError {
			t.Fatalf("%s: unexpected error: %s", tc.tool, resultText(t, res))
		}
		if path != tc.wantPath {
			t.Errorf("%s: path = %q, want %q", tc.tool, path, tc.wantPath)
		}
		if body["id"] != float64(7) {
			t.Errorf("%s: body = %v", tc.tool, body)
		}
		if !strings.Contains(resultText(t, res), `"status": "`+tc.wantStatus+`"`) {
			t.Errorf("%s: result = %s", tc.tool, resultText(t, res))
		}
	}
}

func TestSetListenerRemarkTool(t *testing.T) {
	res, path, body := listenerHarness(t, "set_listener_remark",
		map[string]any{"id": float64(7), "remark": "生产隧道"}, `{"code":0,"message":"ok","result":null}`)
	if res.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, res))
	}
	if path != "/api/listener/editremark" || body["remark"] != "生产隧道" {
		t.Errorf("path=%q body=%v", path, body)
	}

	// remark is required: the tool must not silently clear it.
	res, path, _ = listenerHarness(t, "set_listener_remark", map[string]any{"id": float64(7)}, `{"code":0,"message":"ok","result":null}`)
	if !res.IsError || path != "" {
		t.Errorf("missing remark should fail before the API: isError=%v path=%q", res.IsError, path)
	}
}

func TestEditListenerTool(t *testing.T) {
	args := map[string]any{
		"id": float64(9), "mode": "tcp", "listen_addr": "0.0.0.0:21480",
		"connect_addr": "1.2.3.4:21480", "vkey": "v", "encrypt_salt": "s", "remark": "改过的",
	}
	res, path, body := listenerHarness(t, "edit_listener", args, `{"code":0,"message":"ok","result":null}`)
	if res.IsError {
		t.Fatalf("unexpected error: %s", resultText(t, res))
	}
	if path != "/api/listener/edit" {
		t.Errorf("path = %q, want /api/listener/edit", path)
	}
	if body["Id"] != float64(9) || body["ConnectAddr"] != "1.2.3.4:21480" {
		t.Errorf("body = %v", body)
	}

	// Missing credentials would rewrite the listener with empty ones: reject.
	res, path, _ = listenerHarness(t, "edit_listener",
		map[string]any{"id": float64(9), "listen_addr": "0.0.0.0:21480"}, `{"code":0,"message":"ok","result":null}`)
	if !res.IsError || path != "" {
		t.Errorf("missing vkey/salt should fail before the API: isError=%v path=%q", res.IsError, path)
	}
	if !strings.Contains(resultText(t, res), "list_listeners") {
		t.Errorf("error should point at list_listeners: %s", resultText(t, res))
	}
}

// A server-side failure while starting/stopping an existing listener is surfaced
// with v_shell's message plus the state the call was made against.
func TestListenerLifecycleAPIError(t *testing.T) {
	res, path, _ := listenerHarness(t, "stop_listener", map[string]any{"id": float64(7)},
		`{"code":-1,"message":"not found","result":null,"type":"error"}`)
	if !res.IsError || !strings.Contains(resultText(t, res), "not found") {
		t.Errorf("expected the server message as a tool error, got %s", resultText(t, res))
	}
	if path != "/api/listener/stop" {
		t.Errorf("path = %q", path)
	}
	if !strings.Contains(resultText(t, res), "Id=7") {
		t.Errorf("the error should identify the listener: %s", resultText(t, res))
	}
}
