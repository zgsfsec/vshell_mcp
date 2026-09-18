package mcp

import (
	"context"
	"strings"
	"testing"
)

// v_shell reports hostCount=0 while hosts are online (verified against 4.9.3:
// hostCount 0, clientCount 3, clientOnlineCount 3). An agent that reads hostCount
// to decide "is anything up?" would conclude nothing is, so the tool derives the
// counts and says why the server field disagrees.
func TestDashboardDerivesHostCounts(t *testing.T) {
	c, _ := mockAPI(t, map[string]string{
		"/api/dashboard/info": `{"code":0,"message":"ok","result":{"clientCount":3,"clientOnlineCount":3,` +
			`"hostCount":0,"version":"4.9.3"},"type":"success"}`,
	})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerDashboard(context.Background(), toolRequest("get_dashboard", nil))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	for _, want := range []string{`"hosts_total": 3`, `"hosts_online": 3`, "hostCount_warning", "list_hosts"} {
		if !strings.Contains(text, want) {
			t.Errorf("dashboard result should contain %q: %s", want, text)
		}
	}
	// The server's own fields are still passed through unchanged.
	if !strings.Contains(text, `"clientOnlineCount": 3`) {
		t.Errorf("raw dashboard fields should survive: %s", text)
	}
}

// When the server agrees, no warning is emitted.
func TestDashboardNoWarningWhenCountsAgree(t *testing.T) {
	c, _ := mockAPI(t, map[string]string{
		"/api/dashboard/info": `{"code":0,"message":"ok","result":{"clientCount":2,"clientOnlineCount":1,` +
			`"hostCount":2},"type":"success"}`,
	})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerDashboard(context.Background(), toolRequest("get_dashboard", nil))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if strings.Contains(text, "hostCount_warning") {
		t.Errorf("no warning expected when hostCount is non-zero: %s", text)
	}
	if !strings.Contains(text, `"hosts_online": 1`) {
		t.Errorf("derived counts missing: %s", text)
	}
}
