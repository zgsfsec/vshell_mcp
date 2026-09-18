package vshell

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// catServer answers /file/cat with the given raw JSON result payload.
func catServer(t *testing.T, resultJSON string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/file/cat") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":` + resultJSON + `}`))
	}))
	t.Cleanup(srv.Close)
	return NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})
}

// A GBK file comes back from v_shell already sanitized: /file/cat decodes as
// UTF-8 and substitutes U+FFFD (0xEF 0xBF 0xBD) for every undecodable byte, so
// the payload is *valid* UTF-8 by the time we see it. Counting the replacement
// characters is the only way to tell the caller the content is damaged.
func TestReadFileCountsReplacedRunes(t *testing.T) {
	// What the live server returned for a GBK file "中文测试内容GBK编码".
	payload := `{"content":"\uFFFD\uFFFD\uFFFD\uFFFD\uFFFD\uFFFD\uFFFD\uFFFDGBK\uFFFD\uFFFD  \r\n"}`
	c := catServer(t, payload)

	fc, err := c.ReadFile(context.Background(), 2, `C:\Windows\Temp`, "gbk.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if fc.ReplacedRunes != 10 {
		t.Errorf("ReplacedRunes = %d, want 10", fc.ReplacedRunes)
	}
	if fc.Base64Encoded {
		t.Error("sanitized content is valid UTF-8, so it is not base64-encoded")
	}
	if !strings.Contains(fc.Content, "GBK") {
		t.Errorf("content = %q", fc.Content)
	}
}

// Clean UTF-8 reports no damage.
func TestReadFileCleanContent(t *testing.T) {
	c := catServer(t, `{"content":"hello 世界\n"}`)
	fc, err := c.ReadFile(context.Background(), 2, "/tmp", "ok.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if fc.ReplacedRunes != 0 || fc.Base64Encoded || fc.Content != "hello 世界\n" {
		t.Errorf("got %+v", fc)
	}
}

// Even a hand-crafted body carrying invalid UTF-8 cannot reach the base64 path:
// encoding/json (like the server's own decoder) substitutes U+FFFD while
// decoding, so utf8.ValidString is already true by then. This documents why
// base64_encoded almost never fires — and why bytes_replaced is the signal.
//
// Note the trap this hides: a byte pair that *happens* to be valid UTF-8
// survives as a wrong character instead of U+FFFD (the live GBK sample came back
// with "\xc4\xb2" intact, decoding to "Ĳ"), and that damage is undetectable.
func TestReadFileRawBytesAreSanitizedByJSON(t *testing.T) {
	c := catServer(t, "{\"content\":\"\xb2\xe2\"}") // GBK "测", not valid UTF-8
	fc, err := c.ReadFile(context.Background(), 2, "/tmp", "gbk.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if fc.Base64Encoded {
		t.Error("invalid bytes are replaced during decoding, so this cannot be base64")
	}
	if fc.ReplacedRunes == 0 {
		t.Errorf("expected the undecodable bytes to be reported as replacements: %+v", fc)
	}
}
