package mcp

import (
	"sort"
	"testing"

	"github.com/chinaran404/vshell-mcp/internal/vshell"
)

// The tool inventory is part of the public surface: README documents it and the
// model sees it. Pinning the names here makes an accidental rename or a tool
// that silently failed to register show up as a test failure.
func TestToolInventory(t *testing.T) {
	s := New(vshell.NewClient(vshell.Config{BaseURL: "http://vshell.test", Token: "t"}), "http://vshell.test", "test")
	tools := s.Handler().ListTools()

	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)

	const wantCount = 33
	if len(names) != wantCount {
		t.Errorf("registered %d tools, want %d: %v", len(names), wantCount, names)
	}
	for _, required := range []string{
		"register_client", "generate_client", "execute_command", "list_hosts",
		"start_listener", "stop_listener", "edit_listener", "set_listener_remark",
		"add_tunnel", "list_tunnels", "probe_tunnel", "list_listeners", "get_server_info",
	} {
		if _, ok := tools[required]; !ok {
			t.Errorf("tool %q is not registered", required)
		}
	}
	// Deletion of listeners is intentionally not exposed.
	for _, forbidden := range []string{"delete_listener", "delete_listeners", "remove_listener"} {
		if _, ok := tools[forbidden]; ok {
			t.Errorf("tool %q must not be registered (listener deletion is out of scope)", forbidden)
		}
	}
}
