package mcp

import (
	"context"
	"strings"
	"testing"
)

const twoListeners = `{"code":0,"message":"ok","result":{"items":[` +
	`{"Id":6,"Mode":"tcp","ListenAddr":"0.0.0.0:9443","Status":true,"Vkey":"v","EncryptSalt":"s"},` +
	`{"Id":7,"Mode":"ws","ListenAddr":"0.0.0.0:9444","Status":false,"Vkey":"v","EncryptSalt":"s"}` +
	`],"total":2},"type":"success"}`

// The server ignores the status filter (a request with status=false still comes
// back with running listeners), so the filtering happens locally and the counts
// make "no listeners" distinguishable from "everything was filtered out".
func TestListListenersFiltersLocally(t *testing.T) {
	c, _ := mockAPI(t, map[string]string{"/api/listener/list": twoListeners})
	s := New(c, "http://vshell.test", "test")

	call := func(args map[string]any) string {
		t.Helper()
		res, err := s.handlerListListeners(context.Background(), toolRequest("list_listeners", args))
		if err != nil {
			t.Fatalf("handler: %v", err)
		}
		return resultText(t, res)
	}

	all := call(nil)
	for _, want := range []string{`"total": 2`, `"total_unfiltered": 2`, `"filtered_out": 0`} {
		if !strings.Contains(all, want) {
			t.Errorf("unfiltered result should contain %q: %s", want, all)
		}
	}

	stopped := call(map[string]any{"status": "false"})
	for _, want := range []string{`"total": 1`, `"total_unfiltered": 2`, `"filtered_out": 1`, `"Id": 7`} {
		if !strings.Contains(stopped, want) {
			t.Errorf("status=false result should contain %q: %s", want, stopped)
		}
	}
	if strings.Contains(stopped, `"Id": 6`) {
		t.Errorf("running listener should have been filtered out: %s", stopped)
	}

	// A boolean argument works as well as the documented string form.
	stoppedBool := call(map[string]any{"status": false})
	if !strings.Contains(stoppedBool, `"total": 1`) || strings.Contains(stoppedBool, `"Id": 6`) {
		t.Errorf("boolean status should filter too: %s", stoppedBool)
	}

	none := call(map[string]any{"mode": "kcp"})
	if !strings.Contains(none, `"total": 0`) || !strings.Contains(none, `"total_unfiltered": 2`) {
		t.Errorf("empty filtered result should still report the unfiltered count: %s", none)
	}
	if !strings.Contains(none, "被 status/mode 过滤掉") {
		t.Errorf("an empty-but-filtered result must say so: %s", none)
	}
}

// An account with no listeners at all gets a different message than a filtered
// miss.
func TestListListenersEmptyServerHasItsOwnMessage(t *testing.T) {
	c, _ := mockAPI(t, map[string]string{
		"/api/listener/list": `{"code":0,"message":"ok","result":{"items":[],"total":0},"type":"success"}`,
	})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerListListeners(context.Background(), toolRequest("list_listeners", nil))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if !strings.Contains(text, "当前没有任何监听器") {
		t.Errorf("expected the empty-server note: %s", text)
	}
	if strings.Contains(text, "被 status/mode 过滤掉") {
		t.Errorf("an empty server list is not a filtered miss: %s", text)
	}
}

// start_listener/stop_listener are idempotent: a listener that is already in the
// requested state is not toggled, and the server is not called at all.
func TestListenerStatusIsIdempotent(t *testing.T) {
	for _, tc := range []struct {
		tool        string
		status      string
		wantState   string
		wantAPIPath string
	}{
		{"start_listener", "true", "already_running", "/api/listener/start"},
		{"stop_listener", "false", "already_stopped", "/api/listener/stop"},
	} {
		c, calls := mockAPI(t, map[string]string{"/api/listener/list": twoListeners})
		s := New(c, "http://vshell.test", "test")

		handler := s.handlerStartListener
		if tc.tool == "stop_listener" {
			handler = s.handlerStopListener
		}
		id := float64(7)
		if tc.status == "true" {
			id = 6
		}
		res, err := handler(context.Background(), toolRequest(tc.tool, map[string]any{"id": id}))
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		text := resultText(t, res)
		if res.IsError {
			t.Fatalf("%s: unexpected tool error: %s", tc.tool, text)
		}
		if !strings.Contains(text, `"status": "`+tc.wantState+`"`) || !strings.Contains(text, `"changed": false`) {
			t.Errorf("%s: result = %s", tc.tool, text)
		}
		if n := calls(tc.wantAPIPath); n != 0 {
			t.Errorf("%s: server endpoint was called %d times, want 0", tc.tool, n)
		}
	}
}

// A listener id that does not exist fails locally with a pointer to the list,
// instead of surfacing the server's bare "not found".
func TestListenerStatusUnknownID(t *testing.T) {
	c, calls := mockAPI(t, map[string]string{"/api/listener/list": twoListeners})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerStartListener(context.Background(), toolRequest("start_listener", map[string]any{"id": float64(999)}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if !res.IsError || !strings.Contains(text, "list_listeners") {
		t.Errorf("expected a local not-found error pointing at list_listeners: %s", text)
	}
	if n := calls("/api/listener/start"); n != 0 {
		t.Errorf("start must not be attempted for a missing id (called %d times)", n)
	}
}
