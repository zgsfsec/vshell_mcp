package mcp

import (
	"context"
	"encoding/json"
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

// registerClientHarness runs the register_client handler against a stubbed
// v_shell API and returns the tool result, the body POSTed to /client/add and the
// per-path call counts (the handler also lists hosts to report duplicate records).
func registerClientHarness(t *testing.T, addEnvelope, listEnvelope string, args map[string]any) (*mcp.CallToolResult, map[string]any, map[string]int) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls = map[string]int{}
		addBody map[string]any
	)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls[r.URL.Path]++
		raw, _ := io.ReadAll(r.Body)
		envelope := addEnvelope
		if strings.HasSuffix(r.URL.Path, "/client/list") {
			envelope = listEnvelope
		} else if len(raw) > 0 {
			_ = json.Unmarshal(raw, &addBody)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(envelope))
	}))
	t.Cleanup(api.Close)

	c := vshell.NewClient(vshell.Config{BaseURL: api.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})
	s := New(c, "http://vshell.test", "test")

	req := mcp.CallToolRequest{}
	req.Params.Name = "register_client"
	req.Params.Arguments = args
	res, err := s.handlerRegisterClient(context.Background(), req)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	counts := make(map[string]int, len(calls))
	for k, v := range calls {
		counts[k] = v
	}
	return res, addBody, counts
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("tool result has no content")
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", res.Content[0])
	}
	return text.Text
}

const emptyHostList = `{"code":0,"message":"ok","result":{"items":[],"total":0},"type":"success"}`

// A successful registration posts the console's payload and reports what it did
// without echoing the credentials back.
func TestRegisterClientSuccess(t *testing.T) {
	res, body, calls := registerClientHarness(t, `{"code":0,"message":"ok","result":null}`, emptyHostList, map[string]any{
		"tp":    "tcp",
		"ip":    "192.168.111.20",
		"port":  float64(49319),
		"vkey":  "super-secret-vkey",
		"salt":  "super-secret-salt",
		"proxy": "socks5://127.0.0.1:1080",
	})
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", resultText(t, res))
	}
	if calls["/api/client/add"] != 1 {
		t.Errorf("calls = %v, want one POST to /api/client/add", calls)
	}
	if body["tp"] != "tcp" || body["ip"] != "192.168.111.20" || body["port"] != float64(49319) {
		t.Errorf("api body = %v", body)
	}
	if body["vkey"] != "super-secret-vkey" || body["salt"] != "super-secret-salt" {
		t.Errorf("credentials must be forwarded to v_shell, body = %v", body)
	}

	text := resultText(t, res)
	if !strings.Contains(text, `"registered": true`) || !strings.Contains(text, "192.168.111.20:49319") {
		t.Errorf("result should confirm the registration: %s", text)
	}
	if strings.Contains(text, "super-secret") {
		t.Errorf("credentials must not be echoed back to the model: %s", text)
	}
}

// Validation failures are reported as tool errors and never reach the API.
func TestRegisterClientValidation(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"missing vkey", map[string]any{"tp": "tcp", "ip": "1.2.3.4", "port": float64(1), "salt": "s"}, "vkey"},
		{"missing host for ws", map[string]any{"tp": "ws", "vkey": "v", "salt": "s"}, "host"},
		{"bad tp", map[string]any{"tp": "udp", "ip": "1.2.3.4", "port": float64(1), "vkey": "v", "salt": "s"}, "tcp / kcp / ws"},
	}
	for _, tc := range cases {
		res, body, calls := registerClientHarness(t, `{"code":0,"message":"ok","result":null}`, emptyHostList, tc.args)
		if !res.IsError {
			t.Errorf("%s: expected a tool error, got %s", tc.name, resultText(t, res))
			continue
		}
		if !strings.Contains(resultText(t, res), tc.want) {
			t.Errorf("%s: message %q does not mention %q", tc.name, resultText(t, res), tc.want)
		}
		if len(calls) != 0 || body != nil {
			t.Errorf("%s: must not call the API (calls=%v)", tc.name, calls)
		}
	}
}

// A rejected registration becomes a tool error carrying v_shell's message.
func TestRegisterClientAPIError(t *testing.T) {
	res, _, calls := registerClientHarness(t, `{"code":-1,"message":"连接失败","result":null,"type":"error"}`, emptyHostList, map[string]any{
		"tp": "tcp", "ip": "127.0.0.1", "port": float64(9), "vkey": "v", "salt": "s",
	})
	if !res.IsError {
		t.Fatal("expected a tool error when v_shell rejects the registration")
	}
	if !strings.Contains(resultText(t, res), "连接失败") {
		t.Errorf("message = %q", resultText(t, res))
	}
	if calls["/api/client/add"] != 1 {
		t.Errorf("calls = %v", calls)
	}
}

// Registration is add-only, so repeated calls pile up records. The result counts
// how many records already carry this address so the caller can clean up.
func TestRegisterClientReportsDuplicateRecords(t *testing.T) {
	list := `{"code":0,"message":"ok","result":{"items":[` +
		`{"Id":10,"Addr":"127.0.0.1","LocalIP":"10.0.0.9","IsConnect":true},` +
		`{"Id":11,"Addr":"127.0.0.1","LocalIP":"10.0.0.9","IsConnect":false}` +
		`],"total":2},"type":"success"}`
	res, _, _ := registerClientHarness(t, `{"code":0,"message":"ok","result":null}`, list, map[string]any{
		"tp": "tcp", "ip": "127.0.0.1", "port": float64(19998), "vkey": "v", "salt": "s",
	})
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", resultText(t, res))
	}
	text := resultText(t, res)
	for _, want := range []string{`"records_matching_target": 2`, `"records_matching_target_offline": 1`, "duplicate_note"} {
		if !strings.Contains(text, want) {
			t.Errorf("result should contain %q: %s", want, text)
		}
	}
}
