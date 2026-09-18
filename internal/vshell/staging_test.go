package vshell

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// stagingServer serves the download endpoints with a scripted progress
// sequence; values are returned in order and the last one repeats. listingSize
// is what /file/ls reports for the file (a negative value means "not listed").
func stagingServer(t *testing.T, payload string, listingSize int64, progress []int) (*httptest.Server, func(string) int) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls = map[string]int{}
		i     int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls[r.URL.Path]++
		mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/file/ls"):
			w.Header().Set("Content-Type", "application/json")
			if listingSize < 0 {
				_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"items":[],"total":0},"type":"success"}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"items":[{"name":"lsass.dmp","size":` +
				strconv.FormatInt(listingSize, 10) + `}],"total":1},"type":"success"}`))
		case strings.HasSuffix(r.URL.Path, "/file/downloadtoserver"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":null}`))
		case strings.HasSuffix(r.URL.Path, "/file/getdownloadper"):
			mu.Lock()
			pre := progress[len(progress)-1]
			if i < len(progress) {
				pre = progress[i]
				i++
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"pre":` + strconv.Itoa(pre) + `}}`))
		case strings.HasSuffix(r.URL.Path, "/file/downloadtobrowser"):
			_, _ = w.Write([]byte(payload))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return calls[path]
	}
}

func TestHostFileSizeLooksUpTheListing(t *testing.T) {
	srv, _ := stagingServer(t, "", 39541328, []int{100})
	c := NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})

	size, err := c.HostFileSize(context.Background(), 11, `C:\Users\Public`, "LSASS.DMP") // case-insensitive
	if err != nil || size != 39541328 {
		t.Errorf("size = %d, err = %v", size, err)
	}
	missing, err := c.HostFileSize(context.Background(), 11, `C:\Users\Public`, "nope.dmp")
	if err != nil || missing != -1 {
		t.Errorf("missing entry should report -1, got %d (%v)", missing, err)
	}
}

// A staging that finishes hands the file over unchanged.
func TestStageFileCompletesAndFetches(t *testing.T) {
	const payload = "lsass-dump-bytes"
	srv, _ := stagingServer(t, payload, int64(len(payload)), []int{50, 100})
	c := NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})

	stage, err := c.StageFile(context.Background(), 11, `C:\Windows\Temp`, "lsass.dmp", 10*time.Second)
	if err != nil {
		t.Fatalf("StageFile: %v", err)
	}
	if !stage.Complete || stage.Percent != 100 || stage.SizeBytes != int64(len(payload)) {
		t.Fatalf("stage = %+v, want complete at 100%% with the listed size", stage)
	}
	if stage.Reused {
		t.Errorf("nothing was staged before, so this was not a reuse: %+v", stage)
	}

	out := filepath.Join(t.TempDir(), "lsass.dmp")
	n, err := c.FetchStaged(context.Background(), 11, "lsass.dmp", out)
	if err != nil {
		t.Fatalf("FetchStaged: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("bytes = %d, want %d", n, len(payload))
	}
	if got, _ := os.ReadFile(out); string(got) != payload {
		t.Errorf("content = %q", got)
	}
}

// The percentage is only meaningful when the server is given the real size; with
// size=0 it answers 100 for a half-written file, which is how a "successful"
// download used to end up truncated.
func TestStageFileNeverFetchesAPartialFile(t *testing.T) {
	srv, calls := stagingServer(t, "partial", 39541328, []int{56})
	c := NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})

	stage, err := c.StageFile(context.Background(), 11, `C:\Windows\Temp`, "lsass.dmp", 2*time.Second)
	if err != nil {
		t.Fatalf("StageFile: %v", err)
	}
	if stage.Complete {
		t.Fatalf("56%% of a 39 MB file is not complete: %+v", stage)
	}
	if !stage.TimedOut || stage.Percent != 56 {
		t.Errorf("stage = %+v", stage)
	}
	if n := calls("/api/file/downloadtobrowser"); n != 0 {
		t.Errorf("a partial staging must not be fetched (%d calls)", n)
	}

	// DownloadFile has nowhere to put a partial file either: it must fail loudly
	// and point at the cheap retry.
	out := filepath.Join(t.TempDir(), "lsass.dmp")
	if _, err := c.DownloadFile(context.Background(), 11, `C:\Windows\Temp`, "lsass.dmp", out, 2*time.Second); err == nil {
		t.Fatal("DownloadFile must not report success for an unfinished staging")
	} else {
		for _, want := range []string{"暂存未完成", "重试", "56%"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should contain %q: %v", want, err)
			}
		}
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Errorf("no local file should be created for an unfinished staging")
	}
}

// An already-complete staged copy is reused: no second transfer, and the fetch
// works — this is what makes the retry after a timeout cheap.
func TestStageFileReusesCompletedStaging(t *testing.T) {
	srv, calls := stagingServer(t, "already-there", 12, []int{100})
	c := NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})

	stage, err := c.StageFile(context.Background(), 11, `C:\Windows\Temp`, "lsass.dmp", 5*time.Second)
	if err != nil {
		t.Fatalf("StageFile: %v", err)
	}
	if !stage.Complete || !stage.Reused {
		t.Fatalf("stage = %+v, want a complete reuse", stage)
	}
	if n := calls("/api/file/downloadtoserver"); n != 0 {
		t.Errorf("an already-staged file must not be re-transferred (%d calls)", n)
	}
}

// An empty host file needs no transfer at all.
func TestStageFileEmptyHostFile(t *testing.T) {
	srv, calls := stagingServer(t, "", 0, []int{100})
	c := NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})

	stage, err := c.StageFile(context.Background(), 11, `C:\Windows\Temp`, "lsass.dmp", 5*time.Second)
	if err != nil {
		t.Fatalf("StageFile: %v", err)
	}
	if !stage.Complete || stage.SizeBytes != 0 {
		t.Errorf("stage = %+v", stage)
	}
	if n := calls("/api/file/downloadtoserver"); n != 0 {
		t.Errorf("an empty file needs no transfer (%d calls)", n)
	}
}

// A cancelled context (MCP client timed the tool call out) surfaces as an error
// instead of a silent success. The staging request is held open here, which is
// what a real transfer does.
func TestStageFileHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/file/ls"):
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"items":[{"name":"lsass.dmp","size":10}],"total":1},"type":"success"}`))
		case strings.HasSuffix(r.URL.Path, "/file/downloadtoserver"):
			<-release // hold the response open, like a long transfer
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":null}`))
		default:
			_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"pre":1},"type":"success"}`))
		}
	}))
	t.Cleanup(srv.Close)
	c := NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := c.StageFile(ctx, 11, `C:\Windows\Temp`, "lsass.dmp", 30*time.Second)
	if err == nil {
		t.Fatal("expected the cancelled context to be reported")
	}
	close(release) // let the detached staging request finish
}
