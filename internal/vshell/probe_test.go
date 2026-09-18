package vshell

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// socks5Script decides what the fake proxy does once a CONNECT arrives.
type socks5Script struct {
	rep      byte   // REP byte to answer with
	payload  []byte // bytes written back after a successful CONNECT
	holdOpen bool   // keep the connection open without sending anything
	authReq  bool   // require username/password authentication
	// awaitClients payload: read whatever the client sends, then close without
	// answering (what an open port does when the request is not its protocol).
	awaitClientPayload bool
}

// startFakeSocks5 serves a minimal SOCKS5 proxy with one script for every
// connection. It returns its address and an accessor for the targets that were
// asked for.
func startFakeSocks5(t *testing.T, script socks5Script) (string, func() []string) {
	return startFakeSocks5Seq(t, []socks5Script{script})
}

// startFakeSocks5Seq serves one script per connection (the last script repeats),
// which is what the payload probes need: they open a second connection.
func startFakeSocks5Seq(t *testing.T, scripts []socks5Script) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var (
		mu      sync.Mutex
		targets []string
		conns   int
	)
	nextScript := func() socks5Script {
		mu.Lock()
		defer mu.Unlock()
		i := conns
		conns++
		if i >= len(scripts) {
			i = len(scripts) - 1
		}
		return scripts[i]
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			script := nextScript()
			go func(c net.Conn, script socks5Script) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))

				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, int(head[1]))); err != nil {
					return
				}
				if script.authReq {
					if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
						return
					}
					if err := drainSocks5Auth(c); err != nil {
						return
					}
					if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
						return
					}
				} else if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}

				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				var host string
				switch req[3] {
				case 0x01:
					ip := make([]byte, 4)
					if _, err := io.ReadFull(c, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 0x03:
					l := make([]byte, 1)
					if _, err := io.ReadFull(c, l); err != nil {
						return
					}
					name := make([]byte, int(l[0]))
					if _, err := io.ReadFull(c, name); err != nil {
						return
					}
					host = string(name)
				case 0x04:
					if _, err := io.ReadFull(c, make([]byte, 16)); err != nil {
						return
					}
					host = "::"
				}
				portBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, portBuf); err != nil {
					return
				}
				target := fmt.Sprintf("%s:%d", host, binary.BigEndian.Uint16(portBuf))
				mu.Lock()
				targets = append(targets, target)
				mu.Unlock()

				if _, err := c.Write([]byte{0x05, script.rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				if script.rep != 0x00 {
					return
				}
				if script.awaitClientPayload {
					buf := make([]byte, 256)
					_, _ = c.Read(buf) // read the request, then close without answering
					return
				}
				if len(script.payload) > 0 {
					if _, err := c.Write(script.payload); err != nil {
						return
					}
					time.Sleep(300 * time.Millisecond)
					return
				}
				if script.holdOpen {
					_, _ = io.Copy(io.Discard, c) // stay silent until the deadline
				}
			}(conn, script)
		}
	}()

	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), targets...)
	}
}

// drainSocks5Auth consumes an RFC 1929 username/password message.
func drainSocks5Auth(c net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, make([]byte, int(head[1]))); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, int(plen[0])))
	return err
}

// The reply code is not trustworthy on v_shell (everything answers 0x00), so the
// verdict must come from the data plane.
func TestProbeSOCKS5Verdicts(t *testing.T) {
	cases := []struct {
		name        string
		script      socks5Script
		target      string
		wantVerdict string
		wantData    string
	}{
		{
			name:        "data means reachable",
			script:      socks5Script{rep: 0x00, payload: []byte("HTTP/1.0 220 hello\r\n")},
			target:      "10.0.0.9:80",
			wantVerdict: VerdictDataOpen,
			wantData:    dataPlaneData,
		},
		{
			name:        "success code but closed at once means refused",
			script:      socks5Script{rep: 0x00},
			target:      "10.0.0.9:12345",
			wantVerdict: VerdictRefused,
			wantData:    dataPlaneClosed,
		},
		{
			name:        "success code with silence is undecidable",
			script:      socks5Script{rep: 0x00, holdOpen: true},
			target:      "10.0.0.9:1433",
			wantVerdict: VerdictNoData,
			wantData:    dataPlaneSilent,
		},
		{
			name:        "explicit refused reply code",
			script:      socks5Script{rep: 0x05},
			target:      "10.0.0.9:9",
			wantVerdict: VerdictRefused,
			wantData:    dataPlaneNA,
		},
		{
			name:        "no route reply code",
			script:      socks5Script{rep: 0x03},
			target:      "10.9.9.9:9",
			wantVerdict: VerdictUnreachable,
			wantData:    dataPlaneNA,
		},
		{
			name:        "no target only checks the proxy",
			script:      socks5Script{rep: 0x00, holdOpen: true},
			target:      "",
			wantVerdict: VerdictProxyUp,
			wantData:    dataPlaneNA,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, targets := startFakeSocks5(t, tc.script)
			out := probeSOCKS5(addr, tc.target, "", "", nil, 500*time.Millisecond)
			if out.verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q (evidence: %v)", out.verdict, tc.wantVerdict, out.evidence)
			}
			if out.dataPlane != tc.wantData {
				t.Errorf("dataPlane = %q, want %q", out.dataPlane, tc.wantData)
			}
			if !out.dialOK {
				t.Errorf("dialOK = false for a reachable proxy")
			}
			if tc.target != "" {
				got := targets()
				if len(got) == 0 || got[len(got)-1] != tc.target {
					t.Errorf("proxy was asked for %v, want %q", got, tc.target)
				}
			}
			if tc.script.rep == 0x00 && tc.target != "" {
				// The 0x00 caveat must be spelled out in the evidence.
				joined := strings.Join(out.evidence, "\n")
				if !strings.Contains(joined, "0x00") {
					t.Errorf("evidence should warn that the reply code is optimistic: %v", out.evidence)
				}
			}
		})
	}
}

func TestProbeSOCKS5Authenticated(t *testing.T) {
	addr, _ := startFakeSocks5(t, socks5Script{rep: 0x00, payload: []byte("ok"), authReq: true})
	out := probeSOCKS5(addr, "10.0.0.9:80", "user", "pass", nil, 500*time.Millisecond)
	if out.verdict != VerdictDataOpen {
		t.Fatalf("verdict = %q, evidence: %v", out.verdict, out.evidence)
	}
}

func TestProbeSOCKS5ProxyDown(t *testing.T) {
	// A closed port: nothing listens there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	out := probeSOCKS5(addr, "10.0.0.9:80", "", "", nil, 500*time.Millisecond)
	if out.verdict != VerdictProxyDown {
		t.Errorf("verdict = %q, want %q", out.verdict, VerdictProxyDown)
	}
	if out.dialOK {
		t.Errorf("dialOK should be false")
	}
	if len(out.evidence) == 0 {
		t.Errorf("a failed dial should explain itself")
	}
}

// Sending our own request through the forward is what turns an ambiguous
// "no data" into a definite answer.
func TestProbeSOCKS5SendsPayload(t *testing.T) {
	// The fake proxy never answers, so the verdict stays no_data — but the
	// payload must have been written (the read deadline covers the reply).
	addr, _ := startFakeSocks5(t, socks5Script{rep: 0x00, holdOpen: true})
	out := probeSOCKS5(addr, "10.0.0.9:80", "", "", []byte("GET / HTTP/1.0\r\n\r\n"), 400*time.Millisecond)
	if out.verdict != VerdictNoData {
		t.Errorf("verdict = %q, want %q", out.verdict, VerdictNoData)
	}
	if out.dataPlane != dataPlaneNoReply {
		t.Errorf("dataPlane = %q, want %q (we sent a request and got nothing)", out.dataPlane, dataPlaneNoReply)
	}
	joined := strings.Join(out.evidence, "\n")
	if !strings.Contains(joined, "发出") {
		t.Errorf("evidence should mention the payload that was sent: %v", out.evidence)
	}
}

// An open port that closes the connection because our request is not its
// protocol must not be reported as a refused/closed port: the baseline probe
// (same target, no payload) stays open, which proves the port is listening.
func TestProbeSOCKS5DistinguishesRejectedRequestFromClosedPort(t *testing.T) {
	addr, _ := startFakeSocks5Seq(t, []socks5Script{
		{rep: 0x00, holdOpen: true},          // baseline: silent, port looks open
		{rep: 0x00, awaitClientPayload: true}, // with a payload: closes immediately
	})
	out := probeSOCKS5(addr, "10.0.0.9:1433", "", "", []byte("GET / HTTP/1.0\r\n\r\n"), 400*time.Millisecond)
	if out.verdict != VerdictOpenRejected {
		t.Fatalf("verdict = %q, want %q (evidence %v)", out.verdict, VerdictOpenRejected, out.evidence)
	}
	if !strings.Contains(strings.Join(out.evidence, "\n"), "端口是开的") {
		t.Errorf("evidence should explain the port is open: %v", out.evidence)
	}
}

// ...while a genuinely closed port closes the baseline too, and the payload is
// never sent because the baseline already settled the question.
func TestProbeSOCKS5ClosedPortWinsOverPayload(t *testing.T) {
	addr, targets := startFakeSocks5(t, socks5Script{rep: 0x00}) // closes right away
	out := probeSOCKS5(addr, "10.0.0.9:9", "", "", []byte("PING"), 400*time.Millisecond)
	if out.verdict != VerdictRefused {
		t.Fatalf("verdict = %q, want %q", out.verdict, VerdictRefused)
	}
	if got := targets(); len(got) != 1 {
		t.Errorf("the baseline should have been the only connection, got %v", got)
	}
	if strings.Contains(strings.Join(out.evidence, "\n"), "端口是开的") {
		t.Errorf("a closed port must not claim the port is open: %v", out.evidence)
	}
}

// A tcp tunnel dials its target as soon as the connection is accepted, so the
// data plane tells whether the target is alive.
func TestProbeTCPForward(t *testing.T) {
	for _, tc := range []struct {
		name        string
		onAccept    func(c net.Conn)
		wantVerdict string
	}{
		{"target speaks", func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-x\r\n")) }, VerdictDataOpen},
		{"target refuses", func(c net.Conn) {}, VerdictRefused},
		{"target silent", func(c net.Conn) { time.Sleep(2 * time.Second) }, VerdictNoData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				tc.onAccept(conn)
			}()

			out := probeTCPForward(ln.Addr().String(), nil, 400*time.Millisecond)
			if out.verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q (evidence %v)", out.verdict, tc.wantVerdict, out.evidence)
			}
		})
	}
}

// ProbeTunnel finds the tunnel, derives the endpoint from the connection URL and
// folds the mode-specific probe into one report.
func TestProbeTunnelReportsVerdictAndEndpoint(t *testing.T) {
	addr, _ := startFakeSocks5(t, socks5Script{rep: 0x00, payload: []byte("banner")})
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":0,"message":"ok","result":{"items":[{"Id":7,"ClientId":9,"Remark":"web1-socks5",`+
			`"Mode":"socks5","Port":%s,"Target":"","RunStatus":true,"IsConnect":true}],"total":1},"type":"success"}`, port)
	}))
	defer api.Close()

	c := NewClient(Config{BaseURL: api.URL, Prefix: "/api", Token: "t", Timeout: 5 * time.Second})
	p, err := c.ProbeTunnel(context.Background(), 7, "10.0.0.9:445", nil, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbeTunnel: %v", err)
	}
	if p.Verdict != VerdictDataOpen {
		t.Errorf("verdict = %q, evidence: %v", p.Verdict, p.Evidence)
	}
	if p.Endpoint != net.JoinHostPort("127.0.0.1", port) {
		t.Errorf("endpoint = %q, want 127.0.0.1:%s", p.Endpoint, port)
	}
	if p.Target != "10.0.0.9:445" || p.Mode != "socks5" || p.BytesRead == 0 {
		t.Errorf("probe = %+v", p)
	}
	if p.Elapsed == "" {
		t.Errorf("elapsed should be reported")
	}

	if _, err := c.ProbeTunnel(context.Background(), 999, "", nil, time.Second); err == nil ||
		!strings.Contains(err.Error(), "list_tunnels") {
		t.Errorf("unknown tunnel id should error and point at list_tunnels, got %v", err)
	}
}

// An offline client or a stopped tunnel is called out before the probe runs.
func TestProbeTunnelWarnsAboutOfflineClient(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"ok","result":{"items":[{"Id":3,"Mode":"udp","Port":53,` +
			`"RunStatus":false,"IsConnect":false}],"total":1},"type":"success"}`))
	}))
	defer api.Close()

	c := NewClient(Config{BaseURL: api.URL, Prefix: "/api", Token: "t"})
	p, err := c.ProbeTunnel(context.Background(), 3, "", nil, time.Second)
	if err != nil {
		t.Fatalf("ProbeTunnel: %v", err)
	}
	if p.Verdict != VerdictUnsupported {
		t.Errorf("udp should be reported as unsupported, got %q", p.Verdict)
	}
	joined := strings.Join(p.Evidence, "\n")
	for _, want := range []string{"停用", "不在线", "udp"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence should mention %q: %v", want, p.Evidence)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	if _, _, err := splitTarget("1.2.3.4"); err == nil {
		t.Errorf("missing port must fail")
	}
	if _, _, err := splitTarget("1.2.3.4:0"); err == nil {
		t.Errorf("port 0 must fail")
	}
	host, port, err := splitTarget("example.com:8443")
	if err != nil || host != "example.com" || port != 8443 {
		t.Errorf("splitTarget = %q,%d,%v", host, port, err)
	}
}
