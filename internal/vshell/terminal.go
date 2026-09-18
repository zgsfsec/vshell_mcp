package vshell

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[>=]|\x1b[()][0-9A-Z]`)

// shellKind is the command-line dialect of a managed host's interactive shell.
type shellKind int

const (
	// shellPOSIX is sh/bash: `;` separates commands and `$?` holds the status.
	shellPOSIX shellKind = iota
	// shellCmd is Windows cmd.exe: `&` separates commands and `%errorlevel%`
	// holds the status.
	shellCmd
)

// ExecResult is the outcome of one command execution.
type ExecResult struct {
	// Output is everything the command wrote (stdout and stderr, which the
	// interactive shell merges), with escape sequences removed.
	Output string
	// ExitCode is the shell's exit status; -1 when the shell never reported one
	// (for example an echoed `%errorlevel%` that cmd expanded too early).
	ExitCode int
	// TimedOut reports that the end marker never arrived before the deadline:
	// the command did not finish, so Output is a partial capture.
	TimedOut bool
	// Interactive is set when the command stalled on an interactive prompt
	// (currently cmd's "-- More --" pager). The call is abandoned as soon as the
	// prompt is seen instead of waiting out the timeout, and Output holds the
	// page that was already printed.
	Interactive string
}

// Terminal executes commands on a managed host through v_shell's interactive
// WebSocket shell (/api/terminal/ws). Each Exec opens a fresh shell session,
// silences echo where the shell supports it, runs the command between unique
// begin/end markers, and returns only the command's output plus its exit code.
type Terminal struct {
	c  *Client
	ws *websocket.Conn
}

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// wsURL builds the terminal websocket URL, downgrading http/https to ws/wss.
func (c *Client) wsURL(hostID int, token string) string {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	scheme := "ws"
	if strings.HasPrefix(base, "https://") {
		scheme = "wss"
		base = strings.Replace(base, "https://", "", 1)
	} else {
		base = strings.Replace(base, "http://", "", 1)
	}
	prefix := strings.Trim(c.cfg.Prefix, "/")
	if prefix == "" {
		return fmt.Sprintf("%s://%s/terminal/ws?id=%d&token=%s", scheme, base, hostID, token)
	}
	return fmt.Sprintf("%s://%s/%s/terminal/ws?id=%d&token=%s", scheme, base, prefix, hostID, token)
}

// shellKind reports which dialect the host's interactive shell speaks. It comes
// from the host record (OsName, e.g. "windows_amd64") and is cached per host;
// an unknown OS falls back to POSIX and is not cached.
func (c *Client) shellKind(ctx context.Context, hostID int) shellKind {
	c.mu.Lock()
	kind, cached := c.shells[hostID]
	c.mu.Unlock()
	if cached {
		return kind
	}
	hosts, err := c.ListHosts(ctx, nil)
	if err != nil {
		return shellPOSIX
	}
	for _, h := range hosts {
		if h.Id != hostID {
			continue
		}
		kind = shellForOS(h.OsName)
		c.mu.Lock()
		if c.shells == nil {
			c.shells = map[int]shellKind{}
		}
		c.shells[hostID] = kind
		c.mu.Unlock()
		return kind
	}
	return shellPOSIX
}

// shellForOS maps a v_shell OsName ("windows_amd64", "linux_amd64", ...) to the
// dialect of the interactive shell that host serves.
func shellForOS(osName string) shellKind {
	if strings.Contains(strings.ToLower(osName), "windows") {
		return shellCmd
	}
	return shellPOSIX
}

// Exec runs command on the host and returns its output and exit code. If
// workdir is non-empty the command runs after a cd into that directory.
// timeout bounds the wait for the command to finish.
//
// A returned error means no command was handed to the shell (dial, prompt or
// write failure), so the call is safe to retry; Exec retries those up to three
// times. Once the command has been sent, failures are reported as a result with
// TimedOut set instead — retrying could run the command twice.
func (c *Client) Exec(ctx context.Context, hostID int, command, workdir string, timeout time.Duration) (ExecResult, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	tok, err := c.token(ctx)
	if err != nil {
		return ExecResult{}, err
	}
	url := c.wsURL(hostID, tok)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return ExecResult{}, err
		}
		dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
		ws, _, err := dialer.DialContext(ctx, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		t := &Terminal{c: c, ws: ws}
		res, sent, err := t.execOnce(ctx, hostID, command, workdir, timeout)
		ws.Close()
		if err == nil {
			return res, nil
		}
		if sent {
			return ExecResult{}, err
		}
		lastErr = err
	}
	return ExecResult{}, fmt.Errorf("terminal exec failed after 3 attempts: %v", lastErr)
}

// execOnce drives one shell session. The bool result reports whether the
// command was already handed to the shell: once it is, the caller must not
// retry, because the command may have run.
func (t *Terminal) execOnce(ctx context.Context, hostID int, command, workdir string, timeout time.Duration) (ExecResult, bool, error) {
	// 1. Wait for the initial shell prompt.
	if _, ok := t.readUntilPrompt(10 * time.Second); !ok {
		return ExecResult{}, false, fmt.Errorf("shell prompt not detected on connect")
	}
	kind := t.c.shellKind(ctx, hostID)

	// 2. Take over the prompt and silence the echo. The prompt is assembled from
	// a variable rather than written literally, so the line we type never
	// contains the rendered sentinel: waiting for "MCPP<hex>>" then cannot match
	// our own echo.
	//
	// Pinning the prompt is what lets this protocol know when the command has
	// finished, and it is what lets parseExecOutput cut the boundary
	// deterministically: the shell reprints a prompt after the command's output
	// and before it echoes our status line, so without a known prompt text the
	// host's own prompt ("C:\Windows\system32>") would leak into the output.
	suffix := randToken(4)
	rv, sv := "_r"+suffix, "_s"+suffix
	promptText := "MCPP" + suffix
	var promptLine string
	if kind == shellCmd {
		// `prompt` sets cmd's prompt; `$G` renders as '>'.
		promptLine = fmt.Sprintf("prompt %s$G", promptText)
		promptText += ">"
	} else {
		promptLine = fmt.Sprintf("stty -echo 2>/dev/null; _pp=MCPP%s; PS1=\"$_pp> \"", suffix)
		promptText += ">"
	}
	if err := t.ws.WriteMessage(websocket.TextMessage, []byte(promptLine+"\r")); err != nil {
		return ExecResult{}, false, fmt.Errorf("send prompt setup: %w", err)
	}

	begin := "MCPB_" + randToken(8)
	end := "MCPD_" + randToken(8)

	run := command
	if workdir != "" {
		if kind == shellCmd {
			run = fmt.Sprintf("cd /d %s & %s", workdir, command)
		} else {
			run = fmt.Sprintf("cd %s 2>/dev/null; %s", workdir, command)
		}
	}

	// Three more lines, and the shape matters:
	//
	//   1. setup  : assemble the end marker from shell variables, so the needle
	//               never appears verbatim in the lines we type (shells echo what
	//               they are given, and an echoed marker would end the read early)
	//   2. run    : begin marker + the user's command
	//   3. status : the exit code, on its own line
	//
	// The status must NOT be appended to the command line: cmd's `for ... do X`,
	// `( ... )` blocks and `|` pipelines all extend to the end of the line, so a
	// trailing `& echo %errorlevel%` gets swallowed into the loop body (printing a
	// marker on every iteration) or dropped entirely (the command succeeds while
	// we wait for a marker that never comes). A separate line cannot be absorbed,
	// and it also means `%errorlevel%` / `$?` expand *after* the command ran, so
	// no caret trick is needed.
	var setupLine, runLine, statusLine string
	switch kind {
	case shellCmd:
		setupLine = fmt.Sprintf("set %s=MCPD_& set %s=%s", rv, sv, end[len("MCPD_"):])
		runLine = fmt.Sprintf("echo %s & %s", begin, run)
		statusLine = fmt.Sprintf("echo %%%s%%%%%s%%%%errorlevel%%", rv, sv)
	default:
		setupLine = fmt.Sprintf("%s=MCPD_; %s=%s", rv, sv, end[len("MCPD_"):])
		runLine = fmt.Sprintf("echo %s; %s", begin, run)
		statusLine = fmt.Sprintf("echo $%s$%s$?", rv, sv)
	}

	markers := execMarkers{begin: begin, end: end, status: statusLine, prompt: promptText}

	if err := t.ws.WriteMessage(websocket.TextMessage, []byte(setupLine+"\r")); err != nil {
		return ExecResult{}, false, fmt.Errorf("send marker setup: %w", err)
	}
	if err := t.ws.WriteMessage(websocket.TextMessage, []byte(runLine+"\r")); err != nil {
		return ExecResult{}, true, fmt.Errorf("send command: %w", err)
	}

	// 3. Wait for the command to actually finish (sentinel prompt after the begin
	// marker) before typing anything else. Writing the status line while the
	// command is still streaming races the terminal's input buffer: the first
	// byte gets eaten ("echo ..." arrives as "cho ..."), the status line fails,
	// and a command that succeeded looks like a timeout. wmic triggers it
	// reliably; `systeminfo`, despite printing more, does not.
	buf, finished, pager := t.readCommandOutput(markers, timeout)
	if pager == "" && finished {
		// The command is done, so the status line can no longer race with it.
		// The leading \r is sacrificial: if the terminal still swallows a byte at
		// this boundary, it eats an empty line instead of the command name.
		if err := t.ws.WriteMessage(websocket.TextMessage, []byte("\r"+statusLine+"\r")); err != nil {
			return ExecResult{}, true, fmt.Errorf("send status line: %w", err)
		}
		statusWait := 10 * time.Second
		if timeout < statusWait {
			statusWait = timeout
		}
		extra, _ := t.readUntilText(end, statusWait)
		buf = append(buf, extra...)
	}

	res, complete := parseExecOutput(string(buf), markers)
	switch {
	case pager != "":
		// The command is sitting on an interactive prompt: report it right away
		// instead of burning the whole timeout.
		res.Interactive = pager
		res.ExitCode = -1
	case !complete:
		// No end marker: the command outlived the deadline (or the session
		// dropped). Report a partial capture instead of a bogus success.
		res.TimedOut = true
		res.ExitCode = -1
	}
	return res, true, nil
}

// morePagerMarker is the head of cmd's paging prompt. Live hosts print it as
// "-- More  --" (two spaces) as well as "-- More --", so only the stable prefix
// is matched.
const morePagerMarker = "-- More"

// readCommandOutput reads frames until the command has finished — the sentinel
// prompt showing up *after* the begin marker proves the shell is ready for the
// next line — or until an interactive pager shows up, or the wait elapses.
func (t *Terminal) readCommandOutput(m execMarkers, wait time.Duration) (buf []byte, finished bool, pager string) {
	t.ws.SetReadDeadline(time.Now().Add(wait))
	for {
		_, data, err := t.ws.ReadMessage()
		if err != nil {
			return buf, false, ""
		}
		buf = append(buf, data...)
		text := string(buf)
		bi := strings.LastIndex(text, m.begin)
		if bi < 0 {
			continue // nothing to judge yet: the command was not accepted
		}
		after := text[bi+len(m.begin):]
		if strings.Contains(after, morePagerMarker) {
			return buf, false, morePagerMarker
		}
		if strings.Contains(after, m.prompt) {
			return buf, true, ""
		}
	}
}

// execMarkers carries the boundary texts execOnce installed in the shell.
type execMarkers struct {
	begin  string // printed before the command's output
	end    string // printed by the status line, followed by the exit code
	status string // exact text of the status line submitted (echoed by the shell)
	prompt string // the sentinel prompt, e.g. "MCPP1a2b>"
}

// parseExecOutput turns one session's raw frame bytes into the command's output
// and exit code.
//
// Escape sequences are removed first, because v_shell renders the terminal with
// cursor-control trailing every frame (a cmd prompt arrives as
// "C:\Windows\system32>\x1b[0K\x1b[?25h"). The markers are then taken from
// their *last* occurrence: with echo on, the shell first echoes the command
// line we typed — which itself contains the begin marker — and only afterwards
// prints the markers as their own output lines.
//
// Inside that window sit two things that are not the command's output, in this
// order: the prompt the shell printed once the command finished, and the echoed
// status line. Both are cut away using texts we know exactly (the sentinel
// prompt and the status line we submitted).
func parseExecOutput(raw string, m execMarkers) (ExecResult, bool) {
	clean := ansiEscape.ReplaceAllString(raw, "")
	beginIdx := strings.LastIndex(clean, m.begin)
	endIdx := strings.LastIndex(clean, m.end)

	complete := true
	res := ExecResult{ExitCode: -1}
	switch {
	case beginIdx >= 0 && endIdx > beginIdx:
		res.Output = clean[beginIdx+len(m.begin):endIdx]
	case endIdx >= 0:
		res.Output = clean[:endIdx]
	case beginIdx >= 0:
		// The command started but never reported back: keep its partial output
		// and drop the echoed setup/command lines that precede the marker.
		res.Output = clean[beginIdx+len(m.begin):]
		complete = false
	default:
		res.Output = clean
		complete = false
	}
	if m.status != "" {
		if k := strings.LastIndex(res.Output, m.status); k >= 0 {
			res.Output = res.Output[:k]
		}
	}
	if m.prompt != "" {
		// The *first* prompt after the begin marker is the boundary: everything
		// from there on is the shell being ready again (the sacrificial empty
		// line prints another prompt, then the echoed status line, then the
		// marker). The sentinel is random, so command output cannot contain it.
		if k := strings.Index(res.Output, m.prompt); k >= 0 {
			res.Output = res.Output[:k]
		}
	}
	res.Output = normalizeOutput(res.Output)
	if code, ok := leadingInt(clean[endIdx+len(m.end):]); ok && complete {
		res.ExitCode = code
	}
	return res, complete
}

// leadingInt reads the integer a status line printed right after the end
// marker, e.g. "7\r\nC:\...>". It reports false when the shell did not expand
// its status variable.
func leadingInt(s string) (int, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}

// normalizeOutput trims the marker lines' padding, drops the NUL bytes v_shell
// uses to erase a line (they land in the middle of captured text, e.g. after
// "正在加载操作系统信息..." in systeminfo output), and normalizes line endings.
func normalizeOutput(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.Trim(s, " \t\r\n")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// readUntilPrompt reads from the socket until the buffer ends in a shell
// prompt character ('$', '#', '>'), or wait elapses. It returns the buffered
// bytes and whether a prompt was seen.
//
// A single absolute read deadline is set for the whole wait. Gorilla/websocket
// treats any read error (including a per-read deadline expiry) as permanent,
// so re-arming a short deadline inside the loop would poison the connection.
func (t *Terminal) readUntilPrompt(wait time.Duration) ([]byte, bool) {
	var buf []byte
	t.ws.SetReadDeadline(time.Now().Add(wait))
	for {
		_, data, err := t.ws.ReadMessage()
		if err != nil {
			return buf, hasPromptSuffix(buf)
		}
		buf = append(buf, data...)
		if hasPromptSuffix(buf) {
			return buf, true
		}
	}
}

// hasPromptSuffix reports whether the buffered frames end in a shell prompt.
// Escape sequences are stripped first: v_shell appends cursor control to every
// frame, so a Windows prompt arrives as "C:\Windows\system32>\x1b[0K\x1b[?25h"
// and a raw suffix test would never see the '>'.
func hasPromptSuffix(buf []byte) bool {
	s := strings.TrimRight(ansiEscape.ReplaceAllString(string(buf), ""), " \t\r\n")
	return strings.HasSuffix(s, "$") || strings.HasSuffix(s, "#") || strings.HasSuffix(s, ">")
}

// readUntilMarker reads until the needle bytes appear in the stream or wait
// elapses, returning everything read. Like readUntilPrompt it sets one absolute
// read deadline for the whole wait; gorilla/websocket connections are unusable
// after any read error, so a re-armed per-read deadline would break waiting.
func (t *Terminal) readUntilMarker(needle []byte, wait time.Duration) []byte {
	buf, _ := t.readUntilText(string(needle), wait)
	return buf
}

// readUntilText is readUntilMarker plus whether the needle was actually seen.
func (t *Terminal) readUntilText(needle string, wait time.Duration) ([]byte, bool) {
	var buf []byte
	t.ws.SetReadDeadline(time.Now().Add(wait))
	for {
		_, data, err := t.ws.ReadMessage()
		if err != nil {
			return buf, false
		}
		buf = append(buf, data...)
		if strings.Contains(string(buf), needle) {
			return buf, true
		}
	}
}
