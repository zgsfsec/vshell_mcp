package mcp

import (
	"context"
	"strings"
	"testing"
)

const oneRunningTunnel = `{"code":0,"message":"ok","result":{"items":[` +
	`{"Id":6,"ClientId":9,"Mode":"socks5","Port":1081,"Target":"","RunStatus":true,"IsConnect":true}` +
	`],"total":1},"type":"success"}`

const oneStoppedTunnel = `{"code":0,"message":"ok","result":{"items":[` +
	`{"Id":8,"ClientId":10,"Mode":"tcp","Port":19999,"Target":"10.0.0.9:8444","RunStatus":false,"IsConnect":false}` +
	`],"total":1},"type":"success"}`

// v_shell answers "start error" when a tunnel is already running, which reads as
// a failure to a caller that merely wants it up. The tool checks first and
// reports success without calling the server.
func TestStartTunnelIsIdempotent(t *testing.T) {
	c, calls := mockAPI(t, map[string]string{"/api/tunnel/list": oneRunningTunnel})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerStartTunnel(context.Background(), toolRequest("start_tunnel", map[string]any{"id": float64(6)}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if res.IsError {
		t.Fatalf("already-running start must not be an error: %s", text)
	}
	for _, want := range []string{`"status": "already_running"`, `"changed": false`, `"client_online": true`} {
		if !strings.Contains(text, want) {
			t.Errorf("result should contain %q: %s", want, text)
		}
	}
	if n := calls("/api/tunnel/start"); n != 0 {
		t.Errorf("start endpoint called %d times, want 0", n)
	}
}

func TestStopTunnelIsIdempotent(t *testing.T) {
	c, calls := mockAPI(t, map[string]string{"/api/tunnel/list": oneStoppedTunnel})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerStopTunnel(context.Background(), toolRequest("stop_tunnel", map[string]any{"id": float64(8)}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if res.IsError || !strings.Contains(text, `"status": "already_stopped"`) {
		t.Errorf("result = %s", text)
	}
	if n := calls("/api/tunnel/stop"); n != 0 {
		t.Errorf("stop endpoint called %d times, want 0", n)
	}
}

// A tunnel that really needs starting still goes through.
func TestStartTunnelCallsTheServerWhenNeeded(t *testing.T) {
	c, calls := mockAPI(t, map[string]string{
		"/api/tunnel/list":  oneStoppedTunnel,
		"/api/tunnel/start": `{"code":0,"message":"ok","result":null}`,
	})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerStartTunnel(context.Background(), toolRequest("start_tunnel", map[string]any{"id": float64(8)}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if res.IsError || !strings.Contains(text, `"status": "started"`) || !strings.Contains(text, `"changed": true`) {
		t.Errorf("result = %s", text)
	}
	if n := calls("/api/tunnel/start"); n != 1 {
		t.Errorf("start endpoint called %d times, want 1", n)
	}
}

func TestTunnelStatusUnknownID(t *testing.T) {
	c, calls := mockAPI(t, map[string]string{"/api/tunnel/list": oneRunningTunnel})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerStartTunnel(context.Background(), toolRequest("start_tunnel", map[string]any{"id": float64(42)}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if !res.IsError || !strings.Contains(text, "list_tunnels") {
		t.Errorf("expected a local not-found error: %s", text)
	}
	if n := calls("/api/tunnel/start"); n != 0 {
		t.Errorf("start endpoint called %d times, want 0", n)
	}
}

// When the call still fails, the message carries the state that makes it
// diagnosable (tunnel state, port, client online).
func TestTunnelStatusErrorCarriesState(t *testing.T) {
	c, _ := mockAPI(t, map[string]string{
		"/api/tunnel/list":  oneStoppedTunnel,
		"/api/tunnel/start": `{"code":-1,"message":"start error","result":null,"type":"error"}`,
	})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerStartTunnel(context.Background(), toolRequest("start_tunnel", map[string]any{"id": float64(8)}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if !res.IsError {
		t.Fatalf("expected a tool error: %s", text)
	}
	for _, want := range []string{"start error", "Id=8", "RunStatus=false", "客户端在线=false", "probe_tunnel"} {
		if !strings.Contains(text, want) {
			t.Errorf("error should contain %q: %s", want, text)
		}
	}
}
