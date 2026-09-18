package vshell

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --- fixtures taken from a live v_shell terminal session ---------------------
//
// Captured from a windows_amd64 host (cmd.exe). The escaping matters: v_shell
// renders the terminal with cursor control trailing nearly every frame, and cmd
// echoes the typed line before running it.
const (
	winBanner = "\x1b[0mMicrosoft Windows [版本 6.1.7601]\x1b[0K\x1b[?25l\r\n" +
		"版权所有 (c) 2009 Microsoft Corporation。保留所有权利。\x1b[0K\r\n" +
		"\x1b[0K\r\n" +
		"C:\\Windows\\system32>\x1b[0K\x1b[?25h"
	// ansiTail trails echoed input and prompt frames.
	ansiTail  = "\x1b[0K\x1b[?25l"
	winPrompt = "\x1b[0K\r\nC:\\Windows\\system32>\x1b[0K\x1b[?25h"
	posixPS1  = "\r\nroot@lab:~# "
)

var (
	// set _r<hex>=MCPD_& set _s<hex>=<hex>   |   _r<hex>=MCPD_; _s<hex>=<hex>
	setupEnd = regexp.MustCompile(`_s[0-9a-f]*=([0-9a-f]+)`)
	beginTag = regexp.MustCompile(`MCPB_[0-9a-f]+`)
	// prompt MCPP<hex>$G   |   stty -echo ...; _pp=MCPP<hex>; PS1="$_pp> "
	cmdPromptLine   = regexp.MustCompile(`prompt\s+(\S+?)\$G`)
	posixPromptLine = regexp.MustCompile(`_pp=(MCPP[0-9a-f]+)`)
)

// shellConfig configures one fakeShell (kept separate so the harness can hold
// atomics without being copied by value).
type shellConfig struct {
	osName     string // reported via /client/list, e.g. "windows_amd64"
	echo       bool   // echo submitted input (cmd) or not (posix with stty -echo)
	output     string // what the emulated command prints
	exitCode   string // what the status line reports (default "0")
	skipStatus bool   // never answer the status line
	skipMarker bool   // never print the begin marker
	pager      bool   // stop on an interactive pager instead of finishing
}

// fakeShell is an interactive-shell emulator behind the terminal WebSocket. It
// also answers /client/list, which is where the client learns the host's OS.
type fakeShell struct {
	shellConfig

	conns    atomic.Int32
	apiCalls atomic.Int32
	mu       sync.Mutex
	seen     []string
	begin    string // marker halves, learned from the setup line
	end      string
	prompt   string // sentinel prompt the client installed

	srv *httptest.Server
}

func newFakeShell(t *testing.T, cfg shellConfig) *fakeShell {
	t.Helper()
	if cfg.exitCode == "" {
		cfg.exitCode = "0"
	}
	shell := &fakeShell{shellConfig: cfg}
	win := strings.Contains(cfg.osName, "windows")
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/terminal/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		shell.conns.Add(1)
		if win {
			conn.WriteMessage(websocket.TextMessage, []byte(winBanner))
		} else {
			conn.WriteMessage(websocket.TextMessage, []byte("root@lab:~# "))
		}
		for {
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			line := strings.Trim(string(data), "\r\n")
			if line == "" {
				continue // the client's sacrificial empty line
			}
			shell.mu.Lock()
			shell.seen = append(shell.seen, line)
			shell.mu.Unlock()
			shell.respond(conn, line)
		}
	})
	mux.HandleFunc("/api/client/list", func(w http.ResponseWriter, r *http.Request) {
		shell.apiCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"items":[{"Id":2,"OsName":"` + cfg.osName + `"}]}}`))
	})
	shell.srv = httptest.NewServer(mux)
	t.Cleanup(shell.srv.Close)
	return shell
}

// promptNow renders the prompt the shell is currently showing. execOnce pins it
// to a sentinel right after connecting, so the mock follows that line.
func (f *fakeShell) promptNow() string {
	if f.prompt != "" {
		return f.prompt
	}
	if strings.Contains(f.osName, "windows") {
		return "\r\nC:\\Windows\\system32>"
	}
	return "root@lab:~# "
}

// respond emulates cmd/sh processing one submitted line. The markers are learned
// from the setup line, exactly as the real shells would assemble them.
func (f *fakeShell) respond(conn *websocket.Conn, line string) {
	win := strings.Contains(f.osName, "windows")
	frame := func(s string) { conn.WriteMessage(websocket.TextMessage, []byte(s)) }
	echoed := ""
	if f.echo {
		echoed = line + ansiTail + "\r\n"
	}

	switch {
	case cmdPromptLine.MatchString(line) || posixPromptLine.MatchString(line):
		// The client pinned the prompt: record what it renders from now on.
		if m := cmdPromptLine.FindStringSubmatch(line); m != nil {
			f.prompt = m[1] + ">"
		} else if m := posixPromptLine.FindStringSubmatch(line); m != nil {
			f.prompt = m[1] + "> "
		}
		frame(echoed)
		frame(f.promptNow())
	case setupEnd.MatchString(line):
		f.end = "MCPD_" + setupEnd.FindStringSubmatch(line)[1]
		frame(echoed) // the assignment prints nothing
		frame(f.promptNow())
	case strings.Contains(line, "stty"):
		frame(echoed)
		if !win {
			frame("sh: 1: stty: not found" + f.promptNow())
		}
	case beginTag.MatchString(line):
		// the run line: begin marker, the command's output, then either the shell
		// is ready again (prompt) or the command stalled on a pager
		f.begin = beginTag.FindString(line)
		frame(echoed)
		if f.skipMarker {
			f.begin = ""
		} else {
			frame(f.begin + ansiTail + "\r\n")
		}
		for _, ln := range strings.Split(f.output, "\n") {
			if ln != "" {
				frame(ln + ansiTail + "\r\n")
			}
		}
		if f.pager {
			frame("-- More  --" + ansiTail)
			return
		}
		frame(f.promptNow())
	case strings.HasPrefix(line, "echo "):
		// the status line, sent only after the command finished. Reality prints
		// one more prompt first: the client's sacrificial empty line.
		if f.skipStatus {
			return
		}
		frame(f.promptNow())
		frame(echoed)
		frame(f.end + f.exitCode + ansiTail + "\r\n")
		frame(f.promptNow())
	default:
		frame(echoed)
	}
}

// submitted returns the lines the client sent, in order.
func (f *fakeShell) submitted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

// markerLines returns only the command line (the one carrying the begin marker).
func (f *fakeShell) markerLines() []string {
	var out []string
	for _, ln := range f.submitted() {
		if beginTag.MatchString(ln) {
			out = append(out, ln)
		}
	}
	return out
}

func (f *fakeShell) client(t *testing.T) *Client {
	t.Helper()
	return NewClient(Config{BaseURL: f.srv.URL, Prefix: "/api", Token: "test-token", Timeout: 5 * time.Second})
}

// --- tests ------------------------------------------------------------------

// The live cmd prompt frame ends in cursor control, so its suffix is
// "\x1b[0K\x1b[?25h" rather than ">". This is the bug that made every Windows
// command fail with "shell prompt not detected on connect".
func TestHasPromptSuffixIgnoresEscapeSequences(t *testing.T) {
	if !hasPromptSuffix([]byte(winBanner)) {
		t.Errorf("real Windows banner frame not recognised as a prompt: %q", winBanner)
	}
	if !hasPromptSuffix([]byte("root@lab:~# \x1b[0m")) {
		t.Error("trailing reset after a '#' prompt not recognised")
	}
	if hasPromptSuffix([]byte("C:\\Windows\\system32> dir")) {
		t.Error("a line merely containing '>' must not count as a prompt")
	}
}

// Windows cmd: echo is on, so the typed line — which itself contains the begin
// marker — is replayed before the real output. The parse must skip it.
func TestExecWindowsCmdFrame(t *testing.T) {
	const whoami = "god\\administrator"
	shell := newFakeShell(t, shellConfig{osName: "windows_amd64", echo: true, output: whoami})

	res, err := shell.client(t).Exec(context.Background(), 2, "whoami", "", 10*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.TimedOut || res.Interactive != "" {
		t.Fatalf("unexpected timeout/pager; output=%q", res.Output)
	}
	if res.Output != whoami {
		t.Errorf("output = %q, want %q (echoed command line not skipped?)", res.Output, whoami)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
}

// The status line is submitted only after the shell reprinted its prompt:
// writing it while the command still streams races the terminal input buffer and
// eats the first byte ("echo" arrives as "cho"), which is what made `wmic` look
// like a timeout even though it had succeeded.
func TestExecWindowsCmdExitCodeAndSyntax(t *testing.T) {
	shell := newFakeShell(t, shellConfig{osName: "windows_amd64", echo: true, output: "Access is denied.", exitCode: "5"})

	res, err := shell.client(t).Exec(context.Background(), 2, `type C:\secret.txt`, "", 10*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 5 {
		t.Errorf("exit code = %d, want 5", res.ExitCode)
	}
	if res.Output != "Access is denied." {
		t.Errorf("output = %q", res.Output)
	}
	lines := shell.markerLines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 command line, got %d: %q", len(lines), lines)
	}
	sub := shell.submitted()
	if len(sub) != 4 {
		t.Fatalf("cmd session should be prompt+setup+run+status, got %q", sub)
	}
	if !strings.Contains(sub[0], "prompt MCPP") {
		t.Errorf("cmd session should pin the prompt first: %q", sub[0])
	}
	// The structural guarantee against `for`/`( )`/`|` swallowing the status:
	// the status marker text lives on its own line, never on the command line.
	if strings.Contains(sub[2], "MCPD_") || strings.Contains(sub[2], "errorlevel") {
		t.Errorf("the command line must not carry the status text (a cmd block would absorb it): %q", sub[2])
	}
	if !strings.Contains(sub[3], "echo %_r") || !strings.Contains(sub[3], "%errorlevel%") {
		t.Errorf("status line should read %%errorlevel%% on its own line: %q", sub[3])
	}
}

// Linux: echo is disabled by stty, so no echoed command line is present and the
// status comes from `$?` on its own line.
func TestExecPosixFrame(t *testing.T) {
	shell := newFakeShell(t, shellConfig{osName: "linux_amd64", output: "uid=0(root) gid=0(root)"})

	res, err := shell.client(t).Exec(context.Background(), 7, "id", "", 10*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.Output != "uid=0(root) gid=0(root)" || res.ExitCode != 0 {
		t.Errorf("got output=%q exit=%d", res.Output, res.ExitCode)
	}
	lines := shell.markerLines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 command line, got %d: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "; id") {
		t.Errorf("posix run line should chain with ';': %q", lines[0])
	}
	sub := shell.submitted()
	if len(sub) != 4 {
		t.Fatalf("posix session should be stty+setup+run+status, got %q", sub)
	}
	if !strings.Contains(sub[0], "stty -echo") {
		t.Errorf("posix session should silence echo first, got %q", sub[0])
	}
	if strings.Contains(sub[2], "MCPD_") || strings.Contains(sub[2], "$?") {
		t.Errorf("the command line must not carry the status text: %q", sub[2])
	}
	if !strings.Contains(sub[3], "echo $_r") || !strings.HasSuffix(sub[3], "$?") {
		t.Errorf("posix status line should read $? on its own line: %q", sub[3])
	}
}

// workdir is rendered per dialect.
func TestExecWorkdirSyntax(t *testing.T) {
	for _, tc := range []struct {
		osName, dir, want string
	}{
		{"windows_amd64", `C:\Temp`, `cd /d C:\Temp & `},
		{"linux_amd64", "/tmp", "cd /tmp 2>/dev/null; "},
	} {
		shell := newFakeShell(t, shellConfig{osName: tc.osName, echo: strings.Contains(tc.osName, "windows")})
		if _, err := shell.client(t).Exec(context.Background(), 2, "pwd", tc.dir, 10*time.Second); err != nil {
			t.Fatalf("%s: %v", tc.osName, err)
		}
		lines := shell.markerLines()
		if len(lines) == 0 || !strings.Contains(lines[0], tc.want) {
			t.Errorf("%s: run line %q does not contain %q", tc.osName, lines, tc.want)
		}
	}
}

// A command that stops on cmd's pager must be reported at once, not after the
// whole timeout — and the status line must never be typed into a waiting pager.
func TestExecPagerAbortsEarly(t *testing.T) {
	shell := newFakeShell(t, shellConfig{osName: "windows_amd64", echo: true, pager: true})

	start := time.Now()
	res, err := shell.client(t).Exec(context.Background(), 2, `type C:\big.bin | more`, "", 30*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.Interactive != morePagerMarker {
		t.Errorf("Interactive = %q, want %q", res.Interactive, morePagerMarker)
	}
	if res.TimedOut {
		t.Error("a pager stop must not be reported as a timeout")
	}
	if elapsed > 5*time.Second {
		t.Errorf("pager detected after %v; it should abort immediately", elapsed)
	}
	if sub := shell.submitted(); len(sub) != 3 {
		t.Errorf("the status line must not be sent into a waiting pager, got %q", sub)
	}
}

// A command that never finishes must be reported as timed out with a partial
// capture — and must NOT be retried, because it already ran on the host.
func TestExecTimeoutIsNotRetried(t *testing.T) {
	shell := newFakeShell(t, shellConfig{osName: "windows_amd64", echo: true, skipStatus: true})

	res, err := shell.client(t).Exec(context.Background(), 2, "ping -n 60 127.0.0.1", "", 2*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !res.TimedOut {
		t.Error("expected TimedOut for a command that never reported back")
	}
	if res.ExitCode != -1 {
		t.Errorf("exit code = %d, want -1 when the shell never reported one", res.ExitCode)
	}
	if got := shell.conns.Load(); got != 1 {
		t.Errorf("opened %d sessions; a sent command must not be retried", got)
	}
}

// A failure before the command is sent is still retried (three attempts).
func TestExecRetriesPreSendFailures(t *testing.T) {
	var conns atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conns.Add(1)
		conn.Close() // never emit a prompt
	}))
	t.Cleanup(srv.Close)

	c := NewClient(Config{BaseURL: srv.URL, Prefix: "/api", Token: "test-token", Timeout: 5 * time.Second})
	_, err := c.Exec(context.Background(), 1, "id", "", time.Second)
	if err == nil {
		t.Fatal("expected an error when the shell never presents a prompt")
	}
	if !strings.Contains(err.Error(), "after 3 attempts") {
		t.Errorf("error = %v, want the 3-attempt wrapper", err)
	}
	if got := conns.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

// shellForOS is the whole Windows/POSIX decision.
func TestShellForOS(t *testing.T) {
	for _, osName := range []string{"windows_amd64", "windows_i386", "Windows"} {
		if got := shellForOS(osName); got != shellCmd {
			t.Errorf("shellForOS(%q) = %v, want shellCmd", osName, got)
		}
	}
	for _, osName := range []string{"linux_amd64", "darwin_arm64", ""} {
		if got := shellForOS(osName); got != shellPOSIX {
			t.Errorf("shellForOS(%q) = %v, want shellPOSIX", osName, got)
		}
	}
}

// The host's dialect is looked up once and then cached.
func TestShellKindIsLookedUpOnce(t *testing.T) {
	shell := newFakeShell(t, shellConfig{osName: "windows_amd64", echo: true})
	c := shell.client(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Exec(ctx, 2, "whoami", "", 10*time.Second); err != nil {
			t.Fatalf("Exec: %v", err)
		}
	}
	if got := shell.apiCalls.Load(); got != 1 {
		t.Errorf("/client/list called %d times, want 1 (cached per host)", got)
	}
	if got := shell.conns.Load(); got != 3 {
		t.Errorf("sessions = %d, want 3 (one per Exec)", got)
	}
}

// parseExecOutput is exercised directly with the live frame shapes.
func TestParseExecOutput(t *testing.T) {
	begin, end := "MCPB_aaaa1111", "MCPD_bbbb2222"
	status, prompt := "echo %_r1a2b%%_s1a2b%%errorlevel%", "MCPP1a2b>"
	mk := execMarkers{begin: begin, end: end, status: status, prompt: prompt}

	// No end marker at all: not a parse, so the caller reports a timeout.
	if _, ok := parseExecOutput(winBanner+"echo "+begin+" & whoami"+winPrompt, mk); ok {
		t.Error("missing end marker should not parse")
	}

	// The real Windows shape: echoed command line, marker echo, output, the
	// prompt the shell reprinted, the extra prompt from the client's sacrificial
	// empty line, the echoed status line, then the marker with the exit code.
	// Only the command's output must survive — no prompt, no status text.
	raw := "echo " + begin + " & whoami" + ansiTail + "\r\n" +
		begin + ansiTail + "\r\n" +
		"god\\administrator" + ansiTail + "\r\n" +
		"\r\n" + prompt + "\r\n" + prompt + status + ansiTail + "\r\n" +
		end + "1" + ansiTail + "\r\n" + "\r\n" + prompt
	res, ok := parseExecOutput(raw, mk)
	if !ok {
		t.Fatal("expected a successful parse")
	}
	if res.Output != "god\\administrator" || res.ExitCode != 1 {
		t.Errorf("got output=%q exit=%d", res.Output, res.ExitCode)
	}

	// An unexpanded %errorlevel% leaves the status unknown rather than wrong.
	res, _ = parseExecOutput(begin+"\r\nout\r\n"+end+"%errorlevel%\r\n", mk)
	if res.ExitCode != -1 || res.Output != "out" {
		t.Errorf("got output=%q exit=%d, want \"out\"/-1", res.Output, res.ExitCode)
	}

	// Multi-line output keeps its line structure, normalized to \n.
	raw = begin + "\r\none" + ansiTail + "\r\ntwo" + ansiTail + "\r\n" + end + "0\r\n"
	res, _ = parseExecOutput(raw, mk)
	if res.Output != "one\ntwo" {
		t.Errorf("multi-line output = %q, want %q", res.Output, "one\ntwo")
	}

	// A command that prints without a trailing newline leaves the prompt (and the
	// status marker) on the same visual line as the output (`echo|set /p=...`).
	raw = begin + ansiTail + "\r\nno-newline" + prompt + status + ansiTail + "\r\n" + end + "1" + ansiTail + "\r\n"
	res, ok = parseExecOutput(raw, mk)
	if !ok {
		t.Fatal("marker mid-line should still parse")
	}
	if res.Output != "no-newline" || res.ExitCode != 1 {
		t.Errorf("got output=%q exit=%d, want \"no-newline\"/1", res.Output, res.ExitCode)
	}

	// v_shell pads cleared lines with NUL bytes; they must not survive into the
	// captured text (systeminfo output arrives with several of them).
	raw = begin + ansiTail + "\r\n正在加载操作系统信息...      \x00\n正在加载计算机信息...      \x00\n" + end + "0\r\n"
	res, _ = parseExecOutput(raw, mk)
	if strings.Contains(res.Output, "\x00") {
		t.Errorf("NUL bytes must be stripped, got %q", res.Output)
	}
	if !strings.Contains(res.Output, "正在加载操作系统信息...") || !strings.Contains(res.Output, "正在加载计算机信息...") {
		t.Errorf("stripping NULs must keep the text: %q", res.Output)
	}
}
