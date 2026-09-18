package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chinaran404/vshell-mcp/internal/vshell"
	"github.com/mark3labs/mcp-go/mcp"
)

// infoHarness serves the two endpoints get_server_info touches, with a password
// in the client config, and returns the tool result text.
func infoHarness(t *testing.T, args map[string]any) string {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUserInfo"):
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"username":"admin","realName":"管理员"}}`))
		case strings.HasSuffix(r.URL.Path, "/dashboard/info"):
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"version":"4.9.3","web_port":"8082","vip":false,"clientNum":"99"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)

	c := vshell.NewClient(vshell.Config{
		BaseURL: api.URL, Prefix: "/api", Token: "t",
		Username: "admin", Password: "super-secret-password", Timeout: 5 * time.Second,
	})
	s := New(c, "http://vshell.test", "test")

	req := mcp.CallToolRequest{}
	req.Params.Name = "get_server_info"
	req.Params.Arguments = args
	res, err := s.handlerServerInfo(context.Background(), req)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return resultText(t, res)
}

// The login password is a credential and must not land in a transcript by default.
func TestServerInfoMasksPassword(t *testing.T) {
	text := infoHarness(t, nil)
	if strings.Contains(text, "super-secret-password") {
		t.Errorf("password leaked into the tool result: %s", text)
	}
	if !strings.Contains(text, `"password": "******"`) {
		t.Errorf("password should be masked: %s", text)
	}
	if !strings.Contains(text, `"password_masked": true`) {
		t.Errorf("the result should say the password was masked: %s", text)
	}
}

// ...but an explicit opt-in still returns it.
func TestServerInfoRevealsPasswordOnRequest(t *testing.T) {
	text := infoHarness(t, map[string]any{"reveal_password": true})
	if !strings.Contains(text, "super-secret-password") {
		t.Errorf("reveal_password=true should return the plaintext password: %s", text)
	}
	if !strings.Contains(text, `"password_masked": false`) {
		t.Errorf("masking flag should be false: %s", text)
	}
}

// read_file surfaces the server-side encoding damage instead of returning
// mojibake that looks like a successful read.
func TestReadFileReportsEncodingDamage(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"content":"\uFFFD\uFFFD\uFFFD中文"}}`))
	}))
	t.Cleanup(api.Close)

	s := New(vshell.NewClient(vshell.Config{BaseURL: api.URL, Prefix: "/api", Token: "t"}), "http://vshell.test", "test")
	req := mcp.CallToolRequest{}
	req.Params.Name = "read_file"
	req.Params.Arguments = map[string]any{"host_id": "2", "path": "/tmp", "filename": "gbk.txt"}
	res, err := s.handlerReadFile(context.Background(), req)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	for _, want := range []string{`"bytes_replaced": 3`, "encoding_warning", "download_file"} {
		if !strings.Contains(text, want) {
			t.Errorf("result should mention %q: %s", want, text)
		}
	}
}

// A clean file carries no warning at all.
func TestReadFileCleanHasNoWarning(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"content":"plain text"}}`))
	}))
	t.Cleanup(api.Close)

	s := New(vshell.NewClient(vshell.Config{BaseURL: api.URL, Prefix: "/api", Token: "t"}), "http://vshell.test", "test")
	req := mcp.CallToolRequest{}
	req.Params.Name = "read_file"
	req.Params.Arguments = map[string]any{"host_id": "2", "path": "/tmp", "filename": "ok.txt"}
	res, err := s.handlerReadFile(context.Background(), req)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if strings.Contains(text, "encoding_warning") || strings.Contains(text, "bytes_replaced") {
		t.Errorf("clean content must not carry an encoding warning: %s", text)
	}
}
