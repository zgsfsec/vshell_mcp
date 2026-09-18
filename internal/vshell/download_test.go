package vshell

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Staging a large file server-side takes minutes, so it must not run on the
// interactive client. This stub makes the staging call slower than the
// configured interactive timeout but still fast for a bulk client, which is
// exactly the asymmetry that used to fail 3 MB downloads while 4.7 MB uploads
// succeeded.
func TestDownloadFileStagingIgnoresInteractiveTimeout(t *testing.T) {
	const stagingDelay = 700 * time.Millisecond
	payload := strings.Repeat("payload-bytes\n", 64)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/file/downloadtoserver"):
			time.Sleep(stagingDelay)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":null}`))
		case strings.HasSuffix(r.URL.Path, "/file/getdownloadper"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"pre":100}}`))
		case strings.HasSuffix(r.URL.Path, "/file/downloadtobrowser"):
			_, _ = w.Write([]byte(payload))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	// The interactive budget is far below the staging delay.
	c := NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 200 * time.Millisecond})

	dir := t.TempDir()
	out := filepath.Join(dir, "beifen.rar")
	n, err := c.DownloadFile(context.Background(), 4, `C:\Users\Public`, "beifen.rar", out, 0)
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("wrote %d bytes, want %d", n, len(payload))
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != payload {
		t.Errorf("downloaded content differs from the served payload")
	}
}

// The bulk budget itself must be generous (it is what makes the staging call
// survivable) while the interactive one stays at the configured value.
func TestClientTimeoutBudgets(t *testing.T) {
	c := NewClient(Config{BaseURL: "http://vshell.test", Prefix: "/api", Timeout: 3 * time.Second})
	if c.http.Timeout != 3*time.Second {
		t.Errorf("interactive timeout = %v, want 3s", c.http.Timeout)
	}
	if c.longHTTP.Timeout != bulkTimeout || bulkTimeout < time.Hour {
		t.Errorf("bulk timeout = %v (%v), want >= 1h", c.longHTTP.Timeout, bulkTimeout)
	}
}
