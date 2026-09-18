package vshell

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Tunnel probe verdicts. They describe what the *data plane* showed, because
// v_shell's SOCKS5 proxy answers every CONNECT with a success code (0x00) even
// when the target does not exist — see socksReplyNote.
const (
	// VerdictProxyDown: the tunnel's own listening port could not be reached,
	// or the proxy refused to speak SOCKS5/HTTP with us.
	VerdictProxyDown = "proxy_down"
	// VerdictProxyUp: the proxy is up and accepted us, but no target was given
	// to probe end-to-end.
	VerdictProxyUp = "proxy_up"
	// VerdictDataOpen: data came back through the tunnel — the target is
	// definitely reachable and speaking.
	VerdictDataOpen = "data_open"
	// VerdictRefused: the far end actively refused (SOCKS 0x05, or the proxy
	// accepted the CONNECT but the connection was closed immediately).
	VerdictRefused = "refused"
	// VerdictUnreachable: no route to the target (SOCKS 0x03/0x04, dial timeout).
	VerdictUnreachable = "unreachable"
	// VerdictNoData: the forward was accepted and the connection was not closed,
	// but nothing came back within the window. Not proof of life: a service that
	// waits for the client to speak looks exactly like a host that does not exist
	// and whose TCP connect is still timing out.
	VerdictNoData = "no_data"
	// VerdictOpenRejected: the connection stayed open when nothing was sent, but
	// closed once our payload went through. The port is open; the request itself
	// was refused (wrong protocol/format) — not the same as a closed port.
	VerdictOpenRejected = "open_request_rejected"
	// VerdictUnsupported: this tunnel mode cannot be probed this way (udp).
	VerdictUnsupported = "unsupported"
)

// Data-plane observations.
const (
	dataPlaneData    = "data"     // bytes came back
	dataPlaneClosed  = "closed"   // the far end closed immediately
	dataPlaneSilent  = "silent"   // still open, nothing sent within the window
	dataPlaneNoReply = "no_reply" // our own payload got no answer
	dataPlaneNA      = "n/a"      // not attempted
)

// socksReplyNote is attached to every SOCKS5 verdict that hinged on the reply
// code, so a reader is never left believing a 0x00 means "target is up".
const socksReplyNote = "v_shell 的 socks5 代理对任何 CONNECT 都回成功码 0x00(不存在的主机、无路由、关闭的端口同样如此)," +
	"因此本工具的结论取自数据面:能收到数据=确定通;连接被立刻关闭=拒/不可达;连接不关但无数据=无法判定(见 hint)。"

// noDataHint explains the residual ambiguity of a silent forward and how to
// resolve it.
const noDataHint = "连接没有被关闭,但窗口内没有数据。两种可能无法从这一步区分:" +
	"(1) 目标服务存活,只是不主动发数据(MSSQL、HTTP 等要客户端先说话);" +
	"(2) 目标主机不存在或不可路由,转发还卡在 TCP 连接超时上。要拿确定结论:用 send_hex 发一个该协议的请求" +
	"(如 HTTP 的 GET / HTTP/1.0)、把 timeout_seconds 调大(不可路由最终会转成连接被关闭),或在目标侧用 execute_command 查端口。"

// rejectedRequestHint explains a connection that closed only after our payload
// went through: the payload-carrying probes tell it apart from a closed port by
// probing the same target once more without a payload.
const rejectedRequestHint = "端口是开的:同一条隧道在不带请求时连接保持打开,是这段请求被对端关闭了(协议/内容不匹配," +
	"例如把 HTTP 请求发给了 MSSQL 的 1433)。端口存活这一点可以确定;要看到响应就换成该协议真正的握手报文" +
	"(MSSQL 用 TDS prelogin、TLS 用 ClientHello),或改用 execute_command 在目标侧确认服务。"

// TunnelProbe is the result of one reachability probe through a tunnel/proxy.
type TunnelProbe struct {
	TunnelId int    `json:"tunnel_id"`
	Mode     string `json:"mode"`
	Remark   string `json:"remark,omitempty"`
	// Endpoint is the tunnel's listening address, which lives on the v_shell
	// server host (not on the managed host) — the probe dials it from here.
	Endpoint string `json:"endpoint"`
	// Target is what the probe asked the tunnel to reach ("" = only checked the
	// proxy itself).
	Target string `json:"target,omitempty"`
	// SentBytes is how many bytes of our own payload were written through the
	// forward before reading the reply.
	SentBytes int    `json:"sent_bytes,omitempty"`
	Verdict   string `json:"verdict"`
	DialOK    bool   `json:"dial_ok"`
	// SocksReply is the SOCKS5 REP byte as "0xNN (name)"; empty for other modes.
	SocksReply string `json:"socks_reply,omitempty"`
	DataPlane  string `json:"data_plane"`
	BytesRead  int    `json:"bytes_read"`
	FirstBytes string `json:"first_bytes_hex,omitempty"`
	// ClientOnline / RunStatus mirror list_tunnels: an offline client or a
	// stopped tunnel makes every probe fail regardless of the target.
	ClientOnline bool     `json:"client_online"`
	RunStatus    bool     `json:"run_status"`
	Elapsed      string   `json:"elapsed"`
	Evidence     []string `json:"evidence,omitempty"`
	Hint         string   `json:"hint,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// ProbeTunnel checks whether traffic actually flows through a tunnel: it dials
// the tunnel's listening port on the v_shell server host and, when a target is
// given (or the tunnel has one), asks the proxy to forward to it. payload, when
// non-empty, is written through the forward before reading, which turns an
// otherwise ambiguous "no data" answer into a protocol-level test.
//
// The verdict comes from the data plane, not from the proxy's status codes:
// v_shell's SOCKS5 always replies 0x00 (see socksReplyNote).
func (c *Client) ProbeTunnel(ctx context.Context, id int, target string, payload []byte, timeout time.Duration) (*TunnelProbe, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tunnels, err := c.ListTunnels(ctx)
	if err != nil {
		return nil, err
	}
	var t *Tunnel
	for i := range tunnels {
		if tunnels[i].Id == id {
			t = &tunnels[i]
			break
		}
	}
	if t == nil {
		return nil, fmt.Errorf("隧道 Id %d 不存在(用 list_tunnels 查看)", id)
	}

	start := time.Now()
	p := &TunnelProbe{
		TunnelId:     t.Id,
		Mode:         strings.ToLower(t.Mode),
		Remark:       t.Remark,
		Endpoint:     c.tunnelEndpoint(*t),
		ClientOnline: t.IsConnect,
		RunStatus:    t.RunStatus,
		SentBytes:    len(payload),
	}
	defer func() { p.Elapsed = time.Since(start).Round(time.Millisecond).String() }()

	if !t.RunStatus {
		p.Evidence = append(p.Evidence, "隧道处于停用状态(RunStatus=false),端到端必定不通;先执行 start_tunnel")
	}
	if !t.IsConnect {
		p.Evidence = append(p.Evidence, "绑定客户端不在线(IsConnect=false),端口能连上也不会转发到目标;先确认该主机 IsConnect=true")
	}

	switch {
	case p.Mode == "" || p.Mode == "socks5":
		p.Mode = "socks5"
		if target == "" {
			target = t.Target
		}
		p.Target = target
		probeSOCKS5(p.Endpoint, target, t.Username, t.Password, payload, timeout).apply(p)
	case p.Mode == "http":
		if target == "" {
			target = t.Target
		}
		p.Target = target
		probeHTTPConnect(p.Endpoint, target, payload, timeout).apply(p)
	case p.Mode == "tcp":
		if target == "" {
			target = t.Target
		}
		p.Target = target
		probeTCPForward(p.Endpoint, payload, timeout).apply(p)
	case p.Mode == "udp":
		p.Verdict = VerdictUnsupported
		p.DataPlane = dataPlaneNA
		p.Evidence = append(p.Evidence,
			"udp 隧道无法用 TCP 探测判断连通性;请直接在目标协议上跑一次探测(如 DNS 查询)")
	default:
		p.Verdict = VerdictUnsupported
		p.DataPlane = dataPlaneNA
		p.Evidence = append(p.Evidence, fmt.Sprintf("未知隧道模式 %q,无法探测", t.Mode))
	}

	switch p.Verdict {
	case VerdictProxyUp:
		p.Hint = "代理本身可用;想测「服务端→客户端→目标」这一段,请带上 target(如 192.168.1.10:445)"
	case VerdictNoData:
		p.Hint = noDataHint
		if len(payload) > 0 {
			p.Hint = "已通过隧道发出 " + strconv.Itoa(len(payload)) + " 字节,但没有收到任何回应:" +
				"目标可能不是该协议/服务不响应这段请求,也可能不可路由。可换一个该协议的典型请求重试," +
				"或调大 timeout_seconds 看连接是否最终被关闭,或在目标侧用 execute_command 核对端口。"
		}
	case VerdictRefused:
		p.Hint = "数据面判定目标拒连:端口未开、被防火墙 reject,或目标主机已给出 RST——" +
			"注意这不是 SOCKS 应答码给出的结论(它也回 0x00)"
	case VerdictOpenRejected:
		p.Hint = rejectedRequestHint
	}
	return p, nil
}

// tunnelEndpoint returns the tunnel's listening address as reachable from this
// process: the v_shell server's host plus the tunnel's port. Tunnels bind on the
// server (see add_listener/add_tunnel semantics), never on the managed host.
func (c *Client) tunnelEndpoint(t Tunnel) string {
	host := "127.0.0.1"
	if u, err := url.Parse(c.cfg.BaseURL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	return net.JoinHostPort(host, strconv.Itoa(t.Port))
}

// probeOutcome is what the mode-specific probes report before it is folded into
// a TunnelProbe.
type probeOutcome struct {
	dialOK      bool
	established bool
	verdict     string
	socksReply  string
	dataPlane   string
	bytesRead   int
	firstBytes  string
	evidence    []string
	errText     string
}

func (o probeOutcome) apply(p *TunnelProbe) {
	p.DialOK = o.dialOK
	p.SocksReply = o.socksReply
	p.DataPlane = o.dataPlane
	p.BytesRead = o.bytesRead
	p.FirstBytes = o.firstBytes
	p.Error = o.errText
	p.Evidence = append(p.Evidence, o.evidence...)
	if o.verdict != "" {
		p.Verdict = o.verdict
	}
}

// dialEndpoint opens the TCP session to the tunnel's listening port.
func dialEndpoint(endpoint string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", endpoint, timeout)
}

// inspectDataPlane sends payload (when non-empty) and classifies what the far
// end did: sent data, closed at once, or stayed silent.
func inspectDataPlane(conn net.Conn, payload []byte, wait time.Duration) (state string, n int, firstHex string, errText string) {
	if wait <= 0 {
		wait = 2 * time.Second
	}
	if len(payload) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(wait))
		if _, err := conn.Write(payload); err != nil {
			return dataPlaneClosed, 0, "", "发送载荷失败: " + err.Error()
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	replyState := dataPlaneSilent
	if len(payload) > 0 {
		replyState = dataPlaneNoReply
	}
	switch {
	case n > 0:
		return dataPlaneData, n, hexPreview(buf[:n]), ""
	case err == nil:
		return dataPlaneClosed, 0, "", ""
	case isTimeout(err):
		return replyState, 0, "", ""
	default:
		// EOF, RST, or any other read error: the far end is not there.
		return dataPlaneClosed, 0, "", err.Error()
	}
}

// verdictForDataPlane maps a data-plane observation to a verdict.
func verdictForDataPlane(state string) string {
	switch state {
	case dataPlaneData:
		return VerdictDataOpen
	case dataPlaneClosed:
		return VerdictRefused
	default:
		return VerdictNoData
	}
}

// probeTCPForward probes a tcp-mode tunnel: the server dials the configured
// target as soon as our connection is accepted, so the data plane directly
// reveals whether the target is alive. Like the socks5 probe, a payload is
// preceded by a payload-free baseline.
func probeTCPForward(endpoint string, payload []byte, timeout time.Duration) probeOutcome {
	if len(payload) == 0 {
		return tcpForwardOnce(endpoint, nil, timeout)
	}
	baseline := tcpForwardOnce(endpoint, nil, baselineWindow(timeout))
	if baseline.verdict != VerdictNoData {
		baseline.evidence = append(baseline.evidence,
			"(本次未发出请求:先做了不带请求的基准探测,该结果已足以定论)")
		return baseline
	}
	out := tcpForwardOnce(endpoint, payload, timeout)
	if out.dataPlane == dataPlaneClosed {
		out.verdict = VerdictOpenRejected
		out.evidence = append(out.evidence, rejectedRequestHint)
	}
	return out
}

// tcpForwardOnce is one dial-and-classify pass over a tcp tunnel.
func tcpForwardOnce(endpoint string, payload []byte, timeout time.Duration) probeOutcome {
	out := probeOutcome{dataPlane: dataPlaneNA}
	conn, err := dialEndpoint(endpoint, timeout)
	if err != nil {
		out.verdict = VerdictProxyDown
		out.errText = err.Error()
		out.evidence = append(out.evidence, "无法连接隧道监听端口 "+endpoint+"(隧道未启用 / 端口被防火墙拦 / 服务端不可达)")
		return out
	}
	defer conn.Close()
	out.dialOK = true
	out.established = true
	state, n, firstHex, errText := inspectDataPlane(conn, payload, timeout)
	out.dataPlane, out.bytesRead, out.firstBytes, out.errText = state, n, firstHex, errText
	out.verdict = verdictForDataPlane(state)
	out.evidence = append(out.evidence, tcpPlaneEvidence(state, n)+"(tcp 隧道在连接建立时即由服务端去连目标)")
	return out
}

func tcpPlaneEvidence(state string, n int) string {
	switch state {
	case dataPlaneData:
		return fmt.Sprintf("目标发来 %d 字节:链路与目标都可用的强证据。", n)
	case dataPlaneClosed:
		return "连接被立即关闭:目标端口拒连或链路不通。"
	default:
		return "连接没有被关闭,但目标没有发数据。"
	}
}

// baselineWindow bounds the payload-free reference probe: it only needs to learn
// whether the far end closes at once or stays open, both of which happen fast
// except for the "stays open" case, which is exactly the case we are willing to
// wait for.
func baselineWindow(timeout time.Duration) time.Duration {
	w := timeout / 2
	if w < 500*time.Millisecond {
		w = 500 * time.Millisecond
	}
	if w > 3*time.Second {
		w = 3 * time.Second
	}
	return w
}

// probeSOCKS5 probes a socks5 tunnel. When a payload is supplied, the target is
// first probed *without* it: a closed port closes the connection either way, and
// only the baseline tells that apart from an open port rejecting our request.
func probeSOCKS5(endpoint, target, username, password string, payload []byte, timeout time.Duration) probeOutcome {
	if len(payload) == 0 {
		return socks5Once(endpoint, target, username, password, nil, timeout)
	}
	baseline := socks5Once(endpoint, target, username, password, nil, baselineWindow(timeout))
	if baseline.verdict != VerdictNoData {
		baseline.evidence = append(baseline.evidence,
			"(本次未发出请求:先做了不带请求的基准探测,该结果已足以定论)")
		return baseline
	}
	out := socks5Once(endpoint, target, username, password, payload, timeout)
	if out.dataPlane == dataPlaneClosed {
		out.verdict = VerdictOpenRejected
		out.evidence = append(out.evidence, rejectedRequestHint)
	}
	return out
}

// socks5Once performs a SOCKS5 handshake and (when target is non-empty) a
// CONNECT, then classifies the data plane.
func socks5Once(endpoint, target, username, password string, payload []byte, timeout time.Duration) probeOutcome {
	out := probeOutcome{dataPlane: dataPlaneNA}
	conn, err := dialEndpoint(endpoint, timeout)
	if err != nil {
		out.verdict = VerdictProxyDown
		out.errText = err.Error()
		out.evidence = append(out.evidence, "无法连接 socks5 端口 "+endpoint+"(隧道未启用 / 端口被防火墙拦 / 服务端不可达)")
		return out
	}
	defer conn.Close()
	out.dialOK = true

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		out.verdict = VerdictProxyDown
		out.errText = err.Error()
		return out
	}

	// 1. Greeting: offer no-auth, and user/pass when the tunnel carries one.
	methods := []byte{0x00}
	if username != "" || password != "" {
		methods = append(methods, 0x02)
	}
	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greet); err != nil {
		out.verdict = VerdictProxyDown
		out.errText = err.Error()
		return out
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		out.verdict = VerdictProxyDown
		out.errText = "读取握手应答失败: " + err.Error()
		out.evidence = append(out.evidence, endpoint+" 不是 SOCKS5 代理(握手无应答)")
		return out
	}
	if reply[0] != 0x05 {
		out.verdict = VerdictProxyDown
		out.errText = fmt.Sprintf("SOCKS 版本号 %d(期望 5)", reply[0])
		out.evidence = append(out.evidence, endpoint+" 不是 SOCKS5 代理")
		return out
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if username == "" && password == "" {
			out.verdict = VerdictProxyDown
			out.errText = "代理要求用户名/密码认证,但隧道未配置认证信息"
			return out
		}
		if err := socks5Auth(conn, username, password); err != nil {
			out.verdict = VerdictProxyDown
			out.errText = err.Error()
			out.evidence = append(out.evidence, "SOCKS5 用户名/密码认证失败(与隧道配置的账号不一致?)")
			return out
		}
	case 0xFF:
		out.verdict = VerdictProxyDown
		out.errText = "代理拒绝了所有认证方式"
		return out
	default:
		out.verdict = VerdictProxyDown
		out.errText = fmt.Sprintf("代理要求不支持的认证方式 0x%02X", reply[1])
		return out
	}

	if target == "" {
		out.verdict = VerdictProxyUp
		out.evidence = append(out.evidence,
			"socks5 握手成功("+endpoint+"),未提供 target,只验证了代理本身")
		return out
	}

	// 2. CONNECT target.
	host, port, err := splitTarget(target)
	if err != nil {
		out.verdict = VerdictUnsupported
		out.errText = err.Error()
		return out
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	} else {
		if len(host) > 255 {
			out.verdict = VerdictUnsupported
			out.errText = "目标域名过长"
			return out
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		out.verdict = VerdictProxyDown
		out.errText = err.Error()
		return out
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		out.verdict = VerdictProxyDown
		out.errText = "读取 CONNECT 应答失败: " + err.Error()
		return out
	}
	// Drain the bound address so the stream is positioned on payload.
	switch head[3] {
	case 0x01:
		_, _ = io.ReadFull(conn, make([]byte, 4+2))
	case 0x04:
		_, _ = io.ReadFull(conn, make([]byte, 16+2))
	case 0x03:
		alen := make([]byte, 1)
		if _, err := io.ReadFull(conn, alen); err == nil {
			_, _ = io.ReadFull(conn, make([]byte, int(alen[0])+2))
		}
	}
	out.socksReply = fmt.Sprintf("0x%02X (%s)", head[1], socksReplyName(head[1]))
	out.evidence = append(out.evidence, socksReplyNote)

	if head[1] != 0x00 {
		out.verdict = verdictForSocksReply(head[1])
		out.evidence = append(out.evidence,
			"CONNECT "+target+" 被代理拒绝:"+out.socksReply)
		out.dataPlane = dataPlaneNA
		return out
	}
	out.established = true

	// 3. The reply code is untrustworthy here: judge by the data plane.
	state, n, firstHex, errText := inspectDataPlane(conn, payload, timeout)
	out.dataPlane, out.bytesRead, out.firstBytes, out.errText = state, n, firstHex, errText
	out.verdict = verdictForDataPlane(state)
	switch state {
	case dataPlaneData:
		out.evidence = append(out.evidence, fmt.Sprintf("CONNECT 后收到 %d 字节数据:目标确实可达", n))
	case dataPlaneClosed:
		out.evidence = append(out.evidence, "CONNECT 回了成功码,但连接被立即关闭:目标端口/主机实际不可达(这正是 SOCKS 回码不可信的场景)")
	case dataPlaneNoReply:
		out.evidence = append(out.evidence, fmt.Sprintf("CONNECT 回成功码,发出 %d 字节后仍未收到任何数据,连接也没被关闭", len(payload)))
	default:
		out.evidence = append(out.evidence, "CONNECT 回了成功码且连接保持打开,但窗口内无数据")
	}
	return out
}

// socks5Auth performs RFC 1929 username/password authentication.
func socks5Auth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("socks5 账号或密码超过 255 字节")
	}
	buf := []byte{0x01, byte(len(username))}
	buf = append(buf, username...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, password...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("读取认证应答失败: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("认证失败(状态 0x%02X)", resp[1])
	}
	return nil
}

// probeHTTPConnect probes an http-mode proxy with a CONNECT request.
func probeHTTPConnect(endpoint, target string, payload []byte, timeout time.Duration) probeOutcome {
	out := probeOutcome{dataPlane: dataPlaneNA}
	conn, err := dialEndpoint(endpoint, timeout)
	if err != nil {
		out.verdict = VerdictProxyDown
		out.errText = err.Error()
		out.evidence = append(out.evidence, "无法连接 http 代理端口 "+endpoint+"(隧道未启用 / 端口被防火墙拦 / 服务端不可达)")
		return out
	}
	defer conn.Close()
	out.dialOK = true
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if target == "" {
		out.verdict = VerdictProxyUp
		out.evidence = append(out.evidence, "http 代理端口可连接,未提供 target,只验证了端口本身")
		return out
	}
	if _, _, err := splitTarget(target); err != nil {
		out.verdict = VerdictUnsupported
		out.errText = err.Error()
		return out
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		out.verdict = VerdictProxyDown
		out.errText = err.Error()
		return out
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		out.verdict = VerdictProxyDown
		out.errText = "读取 CONNECT 应答失败: " + err.Error()
		return out
	}
	line = strings.TrimSpace(line)
	code := httpStatusCode(line)
	switch {
	case code >= 200 && code < 300:
		out.established = true
		state, n, firstHex, errText := inspectDataPlane(conn, payload, timeout)
		out.dataPlane, out.bytesRead, out.firstBytes, out.errText = state, n, firstHex, errText
		out.verdict = verdictForDataPlane(state)
		out.evidence = append(out.evidence, "CONNECT "+target+" 返回 "+line)
	default:
		out.dataPlane = dataPlaneNA
		out.verdict = VerdictRefused
		out.errText = line
		out.evidence = append(out.evidence, "CONNECT "+target+" 被代理拒绝: "+line)
	}
	return out
}

// httpStatusCode picks the numeric status out of a status line like
// "HTTP/1.1 200 Connection established".
func httpStatusCode(line string) int {
	fields := strings.Fields(line)
	for _, f := range fields[1:] {
		if n, err := strconv.Atoi(f); err == nil {
			return n
		}
	}
	return 0
}

// socksReplyName maps the RFC 1928 REP byte to its name.
func socksReplyName(rep byte) string {
	switch rep {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown"
	}
}

func verdictForSocksReply(rep byte) string {
	switch rep {
	case 0x03, 0x04, 0x06:
		return VerdictUnreachable
	case 0x00:
		return ""
	default:
		return VerdictRefused
	}
}

// splitTarget splits "host:port" and validates the port.
func splitTarget(target string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return "", 0, fmt.Errorf("target 必须是 host:port 格式(收到 %q): %w", target, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("target 缺少主机部分(收到 %q)", target)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("target 端口必须是 1-65535(收到 %q)", portStr)
	}
	return host, port, nil
}

// hexPreview renders up to 16 bytes as hex, so a protocol banner can be
// recognized without dumping a payload into the transcript.
func hexPreview(b []byte) string {
	if len(b) > 16 {
		b = b[:16]
	}
	parts := make([]string, 0, len(b))
	for _, x := range b {
		parts = append(parts, fmt.Sprintf("%02x", x))
	}
	return strings.Join(parts, " ")
}

// isTimeout reports whether err is a deadline expiry (as opposed to the far end
// closing the connection).
func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
