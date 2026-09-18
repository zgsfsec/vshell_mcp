package mcp

import (
	"context"
	"strings"
	"testing"
)

// A malformed listen_addr is rejected locally: the server would only answer
// "open failed" with no context.
func TestAddListenerRejectsMalformedListenAddr(t *testing.T) {
	for _, addr := range []string{"192.168.1.1", "0.0.0.0:", "0.0.0.0:99999", "0.0.0.0:http"} {
		c, calls := mockAPI(t, map[string]string{"/api/listener/add": `{"code":0,"message":"ok","result":null}`})
		s := New(c, "http://vshell.test", "test")

		args := map[string]any{"listen_addr": addr, "vkey": "v", "encrypt_salt": "s"}
		res, err := s.handlerAddListener(context.Background(), toolRequest("add_listener", args))
		if err != nil {
			t.Fatalf("handler: %v", err)
		}
		if !res.IsError {
			t.Errorf("listen_addr %q should be rejected, got %s", addr, resultText(t, res))
		}
		if n := calls("/api/listener/add"); n != 0 {
			t.Errorf("listen_addr %q should not reach the server (called %d times)", addr, n)
		}
	}
}

// A server-side bind failure is re-reported with the address, mode and the fact
// that the bind target is the v_shell server host.
func TestAddListenerErrorCarriesContext(t *testing.T) {
	c, _ := mockAPI(t, map[string]string{
		"/api/listener/add": `{"code":-1,"message":"open failed","result":null,"type":"error"}`,
	})
	s := New(c, "http://vshell.test", "test")

	args := map[string]any{"listen_addr": "10.0.0.9:9443", "mode": "tcp", "vkey": "v", "encrypt_salt": "s"}
	res, err := s.handlerAddListener(context.Background(), toolRequest("add_listener", args))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if !res.IsError {
		t.Fatalf("expected a tool error: %s", text)
	}
	for _, want := range []string{"10.0.0.9:9443", "open failed", "服务端主机", "register_client"} {
		if !strings.Contains(text, want) {
			t.Errorf("error should contain %q: %s", want, text)
		}
	}
}

// The client_id field does not move the listener onto the target host; the
// response says so instead of letting the caller assume it did.
func TestAddListenerWarnsThatClientIDDoesNotMoveTheBind(t *testing.T) {
	c, _ := mockAPI(t, map[string]string{"/api/listener/add": `{"code":0,"message":"ok","result":null}`})
	s := New(c, "http://vshell.test", "test")

	args := map[string]any{
		"listen_addr": "0.0.0.0:9443", "mode": "tcp", "vkey": "v", "encrypt_salt": "s",
		"client_id": float64(9),
	}
	res, err := s.handlerAddListener(context.Background(), toolRequest("add_listener", args))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if res.IsError {
		t.Fatalf("unexpected error: %s", text)
	}
	for _, want := range []string{`"bind_location": "v_shell 服务端主机"`, "client_id_note", "generate_client(kind=listen)", "register_client"} {
		if !strings.Contains(text, want) {
			t.Errorf("result should contain %q: %s", want, text)
		}
	}

	// Without a client_id the note is unnecessary noise.
	args["client_id"] = float64(0)
	res, err = s.handlerAddListener(context.Background(), toolRequest("add_listener", args))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if strings.Contains(resultText(t, res), "client_id_note") {
		t.Errorf("no client_id_note expected when client_id=0: %s", resultText(t, res))
	}
}
