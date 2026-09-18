package vshell

import (
	"context"
	"fmt"
	"strings"
)

// ClientAddRequest registers a forward ("正向"/bind) client with the v_shell
// server: the target already runs a bind payload that listens on a port, and
// this call makes the server dial it so the host comes online. The field names
// mirror the web console's 新增正向客户端 form (and the bind payload's own
// connection settings), so tp/ip/port (or host), vkey and salt must match what
// generate_client(kind=listen) was given.
type ClientAddRequest struct {
	Ebpf  bool   `json:"ebpf"`
	Tp    string `json:"tp"`             // tcp | kcp | ws
	IP    string `json:"ip,omitempty"`   // tp=tcp/kcp
	Port  int    `json:"port,omitempty"` // tp=tcp/kcp
	Host  string `json:"host,omitempty"` // tp=ws, e.g. "ws://192.168.1.1:8080/ws"
	Vkey  string `json:"vkey"`
	Salt  string `json:"salt"`
	Proxy string `json:"proxy,omitempty"` // optional egress proxy for the server side
}

// Validate enforces the console's mode-specific requirements locally, so a
// malformed call fails with a readable error instead of an opaque API reply.
func (r *ClientAddRequest) Validate() error {
	if r.Tp == "" {
		r.Tp = "tcp"
	}
	switch r.Tp {
	case "tcp", "kcp", "ws":
	default:
		return fmt.Errorf("tp 必须是 tcp / kcp / ws(收到 %q)", r.Tp)
	}
	if r.Ebpf && r.Tp == "kcp" {
		return fmt.Errorf("ebpf 客户端只支持 tp=tcp 或 tp=ws")
	}
	if r.Vkey == "" {
		return fmt.Errorf("缺少 vkey(必须与生成 bind payload 时一致)")
	}
	if r.Salt == "" {
		return fmt.Errorf("缺少 salt(必须与生成 bind payload 时一致)")
	}
	switch r.Tp {
	case "tcp", "kcp":
		if r.IP == "" {
			return fmt.Errorf("tp=%s 需要 ip(目标 IP 或域名)", r.Tp)
		}
		if r.Port <= 0 || r.Port > 65535 {
			return fmt.Errorf("tp=%s 需要 1-65535 之间的 port(收到 %d)", r.Tp, r.Port)
		}
	case "ws":
		if r.Host == "" {
			return fmt.Errorf("tp=ws 需要 host,如 ws://192.168.1.1:8080/ws")
		}
		if !strings.HasPrefix(r.Host, "ws://") && !strings.HasPrefix(r.Host, "wss://") {
			return fmt.Errorf("host 必须以 ws:// 或 wss:// 开头(收到 %q)", r.Host)
		}
	}
	return nil
}

// AddClient registers the forward client described by req (POST /client/add).
// The server connects out to the bind payload; a target that is unreachable
// from the v_shell server makes this fail.
func (c *Client) AddClient(ctx context.Context, req ClientAddRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	_, err := c.Call(ctx, "/client/add", req)
	return err
}
