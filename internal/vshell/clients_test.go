package vshell

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// apiStub records one request and answers with the given envelope.
type apiStub struct {
	t        *testing.T
	path     string
	status   int
	envelope string
	gotPath  string
	gotBody  map[string]any
	srv      *httptest.Server
}

func newAPIStub(t *testing.T, path, envelope string) *apiStub {
	t.Helper()
	s := &apiStub{t: t, path: path, status: http.StatusOK, envelope: envelope}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &s.gotBody); err != nil {
				t.Errorf("request body is not a JSON object: %q", raw)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.envelope))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *apiStub) client() *Client {
	return NewClient(Config{BaseURL: s.srv.URL, Prefix: "/api", Token: "test-token", Timeout: 5 * time.Second})
}

// The request must land on /client/add with exactly the console's field names.
func TestAddClientRequestShape(t *testing.T) {
	stub := newAPIStub(t, "/api/client/add", `{"code":0,"message":"ok","result":null}`)
	err := stub.client().AddClient(context.Background(), ClientAddRequest{
		Tp:    "tcp",
		IP:    "192.168.111.20",
		Port:  49319,
		Vkey:  "vkey-abc",
		Salt:  "salt-def",
		Proxy: "socks5://127.0.0.1:1080",
	})
	if err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	if stub.gotPath != "/api/client/add" {
		t.Errorf("path = %q, want /api/client/add", stub.gotPath)
	}
	want := map[string]any{
		"ebpf":  false,
		"tp":    "tcp",
		"ip":    "192.168.111.20",
		"port":  float64(49319),
		"vkey":  "vkey-abc",
		"salt":  "salt-def",
		"proxy": "socks5://127.0.0.1:1080",
	}
	for k, v := range want {
		if got, ok := stub.gotBody[k]; !ok || got != v {
			t.Errorf("body[%q] = %v (present=%v), want %v", k, got, ok, v)
		}
	}
	if _, present := stub.gotBody["host"]; present {
		t.Errorf("host must be omitted for tp=tcp, got body %v", stub.gotBody)
	}
}

// ws mode sends host and omits ip/port, matching the console form's ifShow rules.
func TestAddClientWebSocketShape(t *testing.T) {
	stub := newAPIStub(t, "/api/client/add", `{"code":0,"message":"ok","result":null}`)
	err := stub.client().AddClient(context.Background(), ClientAddRequest{
		Tp:   "ws",
		Host: "ws://192.168.111.20:8080/ws",
		Vkey: "v",
		Salt: "s",
	})
	if err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	if stub.gotBody["host"] != "ws://192.168.111.20:8080/ws" || stub.gotBody["tp"] != "ws" {
		t.Errorf("body = %v", stub.gotBody)
	}
	for _, k := range []string{"ip", "port"} {
		if _, present := stub.gotBody[k]; present {
			t.Errorf("%s must be omitted for tp=ws, got body %v", k, stub.gotBody)
		}
	}
}

// An empty tp means tcp, like the console's default.
func TestAddClientDefaultsTpToTCP(t *testing.T) {
	stub := newAPIStub(t, "/api/client/add", `{"code":0,"message":"ok","result":null}`)
	if err := stub.client().AddClient(context.Background(), ClientAddRequest{IP: "10.0.0.5", Port: 4444, Vkey: "v", Salt: "s"}); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	if stub.gotBody["tp"] != "tcp" {
		t.Errorf("tp = %v, want tcp", stub.gotBody["tp"])
	}
}

// Mode-specific requirements are checked locally, before any HTTP call.
func TestAddClientValidation(t *testing.T) {
	cases := []struct {
		name string
		req  ClientAddRequest
		want string
	}{
		{"missing vkey", ClientAddRequest{Tp: "tcp", IP: "1.2.3.4", Port: 1, Salt: "s"}, "vkey"},
		{"missing salt", ClientAddRequest{Tp: "tcp", IP: "1.2.3.4", Port: 1, Vkey: "v"}, "salt"},
		{"unknown tp", ClientAddRequest{Tp: "udp", IP: "1.2.3.4", Port: 1, Vkey: "v", Salt: "s"}, "tcp / kcp / ws"},
		{"tcp without ip", ClientAddRequest{Tp: "tcp", Port: 1, Vkey: "v", Salt: "s"}, "需要 ip"},
		{"tcp without port", ClientAddRequest{Tp: "tcp", IP: "1.2.3.4", Vkey: "v", Salt: "s"}, "port"},
		{"port out of range", ClientAddRequest{Tp: "tcp", IP: "1.2.3.4", Port: 70000, Vkey: "v", Salt: "s"}, "1-65535"},
		{"ws without host", ClientAddRequest{Tp: "ws", Vkey: "v", Salt: "s"}, "需要 host"},
		{"ws with http url", ClientAddRequest{Tp: "ws", Host: "http://1.2.3.4/ws", Vkey: "v", Salt: "s"}, "ws:// 或 wss://"},
		{"ebpf over kcp", ClientAddRequest{Tp: "kcp", Ebpf: true, IP: "1.2.3.4", Port: 1, Vkey: "v", Salt: "s"}, "只支持 tp=tcp 或 tp=ws"},
	}
	for _, tc := range cases {
		stub := newAPIStub(t, "/api/client/add", `{"code":0,"message":"ok","result":null}`)
		err := stub.client().AddClient(context.Background(), tc.req)
		if err == nil {
			t.Errorf("%s: expected a validation error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %q, want it to mention %q", tc.name, err, tc.want)
		}
		if stub.gotPath != "" {
			t.Errorf("%s: validation must not reach the API (path=%q)", tc.name, stub.gotPath)
		}
	}
}

// A rejected registration (v_shell answering code != 0) surfaces its message.
func TestAddClientPropagatesAPIError(t *testing.T) {
	stub := newAPIStub(t, "/api/client/add", `{"code":-1,"message":"连接失败","result":null,"type":"error"}`)
	err := stub.client().AddClient(context.Background(), ClientAddRequest{Tp: "tcp", IP: "127.0.0.1", Port: 9, Vkey: "v", Salt: "s"})
	if err == nil {
		t.Fatal("expected an error for code=-1")
	}
	if !strings.Contains(err.Error(), "连接失败") {
		t.Errorf("error = %v, want the server message", err)
	}
}
