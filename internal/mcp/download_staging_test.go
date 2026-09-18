package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const lsassListing = `{"code":0,"message":"ok","result":{"items":[{"name":"lsass.dmp","size":39541328}],"total":1},"type":"success"}`

// A staging that has not finished must come back as a *result* (not an error)
// carrying the progress and the cheap-retry guidance: that is what turns "两次
// timeout, 不知道发生了什么" into a next step.
func TestDownloadFileReportsUnfinishedStaging(t *testing.T) {
	c, calls := mockAPI(t, map[string]string{
		"/api/file/ls":               lsassListing,
		"/api/file/downloadtoserver": `{"code":0,"message":"ok","result":null}`,
		"/api/file/getdownloadper":   `{"code":0,"message":"ok","result":{"pre":42}}`,
	})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerDownloadFile(context.Background(), toolRequest("download_file", map[string]any{
		"host_id": "11", "path": `C:\Windows\Temp`, "filename": "lsass.dmp",
		"stage_wait_seconds": float64(1),
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if res.IsError {
		t.Fatalf("an unfinished staging is a state, not a tool failure: %s", text)
	}
	for _, want := range []string{`"staged": false`, `"staging_percent": 42`, `"size_bytes": 39541328`, "重试", "HTTP"} {
		if !strings.Contains(text, want) {
			t.Errorf("result should contain %q: %s", want, text)
		}
	}
	if strings.Contains(text, `"downloaded": true`) {
		t.Errorf("nothing was downloaded, so downloaded must not be true: %s", text)
	}
	if n := calls("/api/file/downloadtobrowser"); n != 0 {
		t.Errorf("a partial staging must not be fetched (%d calls)", n)
	}
}

// Once the server holds the file, the tool fetches it and reports the size. An
// already-complete staged copy is reused instead of being transferred again.
func TestDownloadFileFetchesCompletedStaging(t *testing.T) {
	const payload = "dump-bytes"
	c, calls := mockAPI(t, map[string]string{
		"/api/file/ls":                `{"code":0,"message":"ok","result":{"items":[{"name":"lsass.dmp","size":10}],"total":1},"type":"success"}`,
		"/api/file/downloadtoserver":  `{"code":0,"message":"ok","result":null}`,
		"/api/file/getdownloadper":    `{"code":0,"message":"ok","result":{"pre":100}}`,
		"/api/file/downloadtobrowser": payload,
	})
	s := New(c, "http://vshell.test", "test")

	local := filepath.Join(t.TempDir(), "lsass.dmp")
	res, err := s.handlerDownloadFile(context.Background(), toolRequest("download_file", map[string]any{
		"host_id": "11", "path": `C:\Windows\Temp`, "filename": "lsass.dmp",
		"local_path": local,
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", text)
	}
	for _, want := range []string{`"downloaded": true`, `"staged": true`, `"bytes": 10`, `"staged_reused": true`} {
		if !strings.Contains(text, want) {
			t.Errorf("result should contain %q: %s", want, text)
		}
	}
	if n := calls("/api/file/downloadtoserver"); n != 0 {
		t.Errorf("an already-staged file must not be re-transferred (%d calls)", n)
	}
	if got, err := os.ReadFile(local); err != nil || string(got) != payload {
		t.Errorf("local file = %q (err %v), want %q", got, err, payload)
	}
}

// A staging request that the server rejects (target offline, unreadable file)
// carries the diagnostic pointers.
func TestDownloadFileStagingFailureHints(t *testing.T) {
	c, _ := mockAPI(t, map[string]string{
		"/api/file/ls":               lsassListing,
		"/api/file/downloadtoserver": `{"code":-1,"message":"connection error","result":null,"type":"error"}`,
	})
	s := New(c, "http://vshell.test", "test")

	res, err := s.handlerDownloadFile(context.Background(), toolRequest("download_file", map[string]any{
		"host_id": "11", "path": `C:\Windows\Temp`, "filename": "lsass.dmp",
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if !res.IsError {
		t.Fatalf("expected a tool error: %s", text)
	}
	for _, want := range []string{"connection error", "list_hosts", "list_directory"} {
		if !strings.Contains(text, want) {
			t.Errorf("error should contain %q: %s", want, text)
		}
	}
}
