package mcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chinaran404/vshell-mcp/internal/vshell"
)

// startFakeSocks5 answers the SOCKS5 handshake and the CONNECT request with
// success codes, then reads whatever the client sends and answers with reply
// (nil = stay silent). It records the payload it received.
func startFakeSocks5(t *testing.T, reply func(sent []byte) []byte) (string, func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var (
		mu  sync.Mutex
		got []byte
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				greet := make([]byte, 3)
				if _, err := io.ReadFull(c, greet); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				req := make([]byte, 10) // VER CMD RSV ATYP + IPv4 + port
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				buf := make([]byte, 256)
				n, _ := c.Read(buf)
				mu.Lock()
				got = append([]byte(nil), buf[:n]...)
				mu.Unlock()
				if reply != nil && n > 0 {
					if out := reply(buf[:n]); out != nil {
						_, _ = c.Write(out)
					}
				}
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), got...)
	}
}

// tunnelListServer serves one socks5 tunnel pointing at the given port.
func tunnelListServer(t *testing.T, port string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"code":0,"message":"ok","result":{"items":[{"Id":6,"ClientId":9,"Mode":"socks5",`+
			`"Port":%s,"Target":"","RunStatus":true,"IsConnect":true}],"total":1},"type":"success"}`, port)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func serverForURL(url string) *Server {
	return New(
		vshell.NewClient(vshell.Config{BaseURL: url, Prefix: "/api", Token: "t", Timeout: 5 * time.Second}),
		"http://vshell.test", "test")
}

// The tool wires the probe through: endpoint derived from the v_shell URL, and
// the verdict taken from the data plane rather than the proxy's status codes.
func TestProbeTunnelToolReportsDataPlaneVerdict(t *testing.T) {
	addr, _ := startFakeSocks5(t, nil)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	s := serverForURL(tunnelListServer(t, port).URL)

	res, err := s.handlerProbeTunnel(context.Background(), toolRequest("probe_tunnel", map[string]any{
		"id": float64(6), "target": "10.0.0.9:1433", "timeout_seconds": float64(1),
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", text)
	}
	for _, want := range []string{
		`"verdict": "no_data"`,
		`"socks_reply": "0x00 (succeeded)"`,
		`"data_plane": "silent"`,
		`"target": "10.0.0.9:1433"`,
		`"endpoint": "127.0.0.1:` + port + `"`,
		"0x00", // the caveat that the reply code is not a liveness signal
	} {
		if !strings.Contains(text, want) {
			t.Errorf("probe result should contain %q: %s", want, text)
		}
	}
}

// send/send_hex make the answer definite: the payload travels through the
// forward and a reply proves reachability.
func TestProbeTunnelToolSendsPayload(t *testing.T) {
	addr, sent := startFakeSocks5(t, func([]byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n")
	})
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	s := serverForURL(tunnelListServer(t, port).URL)

	res, err := s.handlerProbeTunnel(context.Background(), toolRequest("probe_tunnel", map[string]any{
		"id": float64(6), "target": "10.0.0.9:8444",
		"send":            "GET / HTTP/1.0\r\n\r\n",
		"timeout_seconds": float64(1),
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	text := resultText(t, res)
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", text)
	}
	if got := string(sent()); got != "GET / HTTP/1.0\r\n\r\n" {
		t.Errorf("proxy received %q, want the send payload", got)
	}
	for _, want := range []string{`"verdict": "data_open"`, `"data_plane": "data"`, `"sent_bytes": 18`, `first_bytes_hex`} {
		if !strings.Contains(text, want) {
			t.Errorf("probe result should contain %q: %s", want, text)
		}
	}

	// send_hex is the binary-protocol variant and takes precedence.
	res, err = s.handlerProbeTunnel(context.Background(), toolRequest("probe_tunnel", map[string]any{
		"id": float64(6), "target": "10.0.0.9:8444",
		"send_hex": "47 45 54 20 2f", "timeout_seconds": float64(1),
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if got := string(sent()); got != "GET /" {
		t.Errorf("proxy received %q, want the decoded hex payload", got)
	}

	// A malformed hex payload is rejected before anything is dialed.
	res, err = s.handlerProbeTunnel(context.Background(), toolRequest("probe_tunnel", map[string]any{
		"id": float64(6), "target": "10.0.0.9:8444", "send_hex": "zz",
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !res.IsError || !strings.Contains(resultText(t, res), "send_hex") {
		t.Errorf("bad hex should be a tool error: %s", resultText(t, res))
	}
}

func TestProbeTunnelToolRejectsUnknownID(t *testing.T) {
	s := serverForURL(tunnelListServer(t, "1").URL)

	res, err := s.handlerProbeTunnel(context.Background(), toolRequest("probe_tunnel", map[string]any{"id": float64(99)}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if text := resultText(t, res); !res.IsError || !strings.Contains(text, "list_tunnels") {
		t.Errorf("unknown tunnel id should be a tool error pointing at list_tunnels: %s", text)
	}
}

// probe_tunnel is part of the public surface and must be registered (see also
// TestToolInventory).
func TestProbeTunnelToolRegistered(t *testing.T) {
	s := serverForURL("http://vshell.test")
	tools := s.Handler().ListTools()
	tool, ok := tools["probe_tunnel"]
	if !ok {
		t.Fatalf("probe_tunnel is not registered")
	}
	if desc := tool.Tool.Description; !strings.Contains(desc, "0x00") {
		t.Errorf("the tool description must warn about the optimistic SOCKS reply code: %s", desc)
	}
}
