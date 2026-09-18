// vshell-mcp exposes the v_shell management platform — command control,
// file management, tunnel/listener management and client generation on
// managed hosts — as a Model Context Protocol server.
//
// Command-line configuration (no environment variables needed):
//
//	-h <url>    v_shell web console base URL (required), e.g. http://host:8082
//	-u <user>   login username (default: admin)
//	-p <pass>   login password (required unless -token is given)
//	-token      optional pre-supplied JWT; skips username/password login
//	-transport  stdio | sse | streamable | both (default: both)
//	-listen     HTTP listen address (default: 127.0.0.1, loopback only)
//	-port       MCP HTTP server listen port (default: 19080)
//	-mcpurl     optional externally-reachable MCP base URL (behind a proxy)
//	-prefix     v_shell API path prefix (default: /api)
//	-timeout    per-request timeout in seconds (default: 60)
//	-mcptoken   bearer token MCP clients must present; randomly generated when
//	            empty (the generated value is printed once at startup)
//	-noauth     disable the MCP bearer token check (loopback / SSH tunnel only)
//
// Example (Streamable HTTP, the transport modern clients speak):
//
//	./vshell-mcp -h http://your-vshell-server:8082 -u admin -p 'secret' \
//	  -transport streamable -mcptoken 'long-random-string'
//
// Clients configure it as an HTTP MCP server at http://127.0.0.1:19080/mcp
// (the legacy SSE endpoints /sse + /message stay available by default too).
// Every HTTP request must carry the header `Authorization: Bearer <mcptoken>`;
// the port is reachable by anyone who can route to it, so never leave it
// unauthenticated on an untrusted network.
//
// With -transport stdio the process speaks JSON-RPC over stdin/stdout and is
// started by the MCP client itself: no listener, no bearer token, and every
// diagnostic goes to stderr so stdout stays a clean protocol channel.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/chinaran404/vshell-mcp/internal/mcp"
	"github.com/chinaran404/vshell-mcp/internal/vshell"
)

// version is injected at build time via
// `go build -ldflags "-X main.version=<tag>"`. Defaults to "dev".
var version = "dev"

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `vshell-mcp — v_shell 管理平台 MCP 服务

把 v_shell 的命令控制、文件管理、隧道/监听管理、客户端生成、服务器信息等能力开放给 AI。

用法:
  vshell-mcp -h <v_shell地址> -u <账号> -p <密码> [选项]

必填:
  -h <url>   v_shell Web 控制台地址,如 http://your-vshell-server:8082
  -u <user>  登录账号(默认 admin)
  -p <pass>  登录密码(设了 -token 则无需)

选项:
  -token     预置 JWT,跳过账号密码登录
  -transport 传输方式(默认 both):
               stdio       由 MCP 客户端启动本进程,stdin/stdout 走 JSON-RPC
                            (不监听端口、不需要 -mcptoken,日志全部走 stderr)
               sse         传统 HTTP+SSE:GET /sse + POST /message
               streamable  Streamable HTTP:POST /mcp
               both        (默认)同一端口同时提供 /mcp 与 /sse
  -listen    HTTP 监听地址(默认 127.0.0.1,仅本机;对外暴露用 0.0.0.0)
  -port      HTTP 服务监听端口(默认 19080)
  -mcpurl    MCP 服务器对外可达地址(置于反向代理后时设置)
  -prefix    v_shell API 路径前缀(默认 /api)
  -timeout   单次请求超时秒数(默认 60)
  -mcptoken  MCP 接入鉴权 Token(Bearer);留空则启动时随机生成并打印一行
  -noauth    关闭 MCP 接入鉴权(危险:仅限回环/SSH 隧道场景)
  -version   显示版本号并退出
  -help      显示本帮助

接入(Streamable HTTP,推荐):
  服务 URL:  http://127.0.0.1:19080/mcp
  认证:      Bearer Token = <mcptoken>(即请求头 Authorization: Bearer <mcptoken>)

接入(传统 SSE):
  claude mcp add vshell --transport sse http://127.0.0.1:19080/sse \
    --header "Authorization: Bearer <mcptoken>"

接入(stdio,客户端代管进程):
  命令: vshell-mcp
  参数: -h http://your-vshell-server:8082 -u admin -p <密码> -transport stdio

注:-h 已绑定为 v_shell 地址参数(而非帮助);查看帮助请用 -help。
`)
	}
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(1)
	}

	vs := vshell.NewClient(cfg.vshell)
	// Fail fast if credentials are wrong.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	if _, err := vs.ListHosts(ctx, nil); err != nil {
		cancel()
		log.Fatalf("无法连接 v_shell(检查 -h 地址与 -u/-p 账号密码): %v", err)
	}
	cancel()

	addr := net.JoinHostPort(cfg.listen, strconv.Itoa(cfg.port))
	srv := mcp.New(vs, cfg.vshell.BaseURL, version)

	// stdio carries the protocol on stdout: every diagnostic must go to stderr.
	out := io.Writer(os.Stdout)
	if cfg.transport == mcp.TransportStdio {
		out = os.Stderr
	}

	switch {
	case cfg.noAuth:
		fmt.Fprintln(out, "MCP 鉴权: 已关闭(-noauth)——任何能访问该端口的人都能控制 v_shell,"+
			"请确认端口只对本机/隧道可达")
	case cfg.mcpTokenGenerated:
		fmt.Fprintf(out, "MCP 鉴权: Authorization: Bearer %s\n", cfg.mcpToken)
		fmt.Fprintln(out, "          (未指定 -mcptoken,本次启动随机生成;重启会变,建议用 -mcptoken 固定)")
	case cfg.transport != mcp.TransportStdio && !cfg.tokenIgnored:
		fmt.Fprintln(out, "MCP 鉴权: Authorization: Bearer <由 -mcptoken 指定>(不回显)")
	}
	if cfg.mcpTokenWeak {
		fmt.Fprintln(os.Stderr, "警告: -mcptoken 长度小于 16,建议改用 ≥32 位随机串")
	}

	if cfg.transport == mcp.TransportStdio {
		fmt.Fprintln(out, "vshell-mcp: transport=stdio(由客户端启动,stdin/stdout 走 JSON-RPC)")
	} else {
		display := cfg.listen
		switch display {
		case "", "0.0.0.0", "::", "[::]":
			display = "127.0.0.1"
		}
		fmt.Fprintf(out, "v_shell MCP server listening on %s\n", addr)
		switch cfg.transport {
		case mcp.TransportStreamable:
			fmt.Fprintf(out, "  Streamable HTTP: http://%s%s\n", net.JoinHostPort(display, strconv.Itoa(cfg.port)), mcp.StreamablePath)
		case mcp.TransportBoth:
			fmt.Fprintf(out, "  Streamable HTTP: http://%s%s\n", net.JoinHostPort(display, strconv.Itoa(cfg.port)), mcp.StreamablePath)
			fmt.Fprintf(out, "  SSE endpoint:    http://%s/sse\n", net.JoinHostPort(display, strconv.Itoa(cfg.port)))
		default:
			fmt.Fprintf(out, "  SSE endpoint:    http://%s/sse\n", net.JoinHostPort(display, strconv.Itoa(cfg.port)))
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		os.Exit(0)
	}()

	if cfg.transport == mcp.TransportStdio {
		if err := srv.ServeStdio(); err != nil {
			log.Fatalf("stdio transport failed: %v", err)
		}
		return
	}
	if err := srv.Serve(addr, cfg.mcpURL, cfg.authToken(), cfg.transport); err != nil {
		log.Fatalf("MCP server failed: %v", err)
	}
}

type config struct {
	vshell vshell.Config
	port   int
	listen string
	mcpURL string

	transport mcp.Transport

	mcpToken          string // bearer token MCP clients must present
	noAuth            bool   // explicitly disable bearer auth
	mcpTokenGenerated bool   // token was generated because none was supplied
	mcpTokenWeak      bool   // supplied token is shorter than minTokenLen
	tokenIgnored      bool   // -mcptoken was supplied but stdio ignores it
}

// minTokenLen is the advisory lower bound for a supplied -mcptoken.
const minTokenLen = 16

// authToken returns the token the HTTP transports must enforce; empty means the
// endpoint is served without authentication (only when -noauth was given, or in
// stdio mode where the client owns the pipe).
func (c *config) authToken() string {
	if c.noAuth || c.transport == mcp.TransportStdio {
		return ""
	}
	return c.mcpToken
}

// randomToken returns n random bytes as hex, for the auto-generated token.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// parseFlags parses command-line flags. Note: -h is intentionally bound to
// the v_shell URL (not help); use -help to print usage.
func parseFlags() (*config, error) {
	var (
		baseURL   = flag.String("h", "", "v_shell Web 控制台地址,如 http://your-vshell-server:8082(必填)")
		user      = flag.String("u", "admin", "登录账号")
		pass      = flag.String("p", "", "登录密码(必填,除非提供了 -token)")
		token     = flag.String("token", "", "预置 JWT,设置后跳过账号密码登录")
		transport = flag.String("transport", string(mcp.DefaultTransport), "传输方式:stdio | sse | streamable | both")
		listen    = flag.String("listen", "127.0.0.1", "HTTP 监听地址(默认仅本机;对外暴露用 0.0.0.0)")
		port      = flag.Int("port", 19080, "MCP HTTP 服务监听端口")
		mcpURL    = flag.String("mcpurl", "", "MCP 服务器对外可达地址(置于反向代理后时设置)")
		prefix    = flag.String("prefix", "/api", "v_shell API 路径前缀")
		timeout   = flag.Int("timeout", 60, "单次 HTTP 请求超时(秒)")
		mcpTok    = flag.String("mcptoken", "", "MCP 接入鉴权 Token(Bearer),留空则启动时随机生成")
		noAuth    = flag.Bool("noauth", false, "关闭 MCP 接入鉴权(危险:仅限回环/SSH 隧道场景)")
		showVer   = flag.Bool("version", false, "显示版本号并退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("vshell-mcp %s\n", version)
		os.Exit(0)
	}

	if *baseURL == "" {
		return nil, fmt.Errorf("缺少必填参数 -h(v_shell 地址)")
	}
	if *token == "" && *pass == "" {
		return nil, fmt.Errorf("缺少登录凭据:请提供 -p 密码(或 -token)")
	}
	if *timeout <= 0 {
		*timeout = 60
	}
	if *port <= 0 || *port > 65535 {
		return nil, fmt.Errorf("-port 必须是 1-65535 之间的端口")
	}
	mode, err := mcp.ParseTransport(*transport)
	if err != nil {
		return nil, err
	}
	if *noAuth && *mcpTok != "" {
		return nil, fmt.Errorf("-noauth 与 -mcptoken 不能同时使用(二者语义冲突)")
	}
	if mode == mcp.TransportStdio && *noAuth {
		return nil, fmt.Errorf("-noauth 只对 HTTP 传输有意义,stdio 传输请去掉该参数")
	}

	cfg := &config{
		vshell: vshell.Config{
			BaseURL:  *baseURL,
			Prefix:   *prefix,
			Username: *user,
			Password: *pass,
			Token:    *token,
			Timeout:  time.Duration(*timeout) * time.Second,
		},
		transport: mode,
		listen:    *listen,
		port:      *port,
		mcpURL:    *mcpURL,
		noAuth:    *noAuth,
		mcpToken:  *mcpTok,
	}
	if mode == mcp.TransportStdio {
		// The parent process owns the pipes: a bearer token would guard nothing,
		// and the port/URL flags would start no listener.
		cfg.tokenIgnored = *mcpTok != ""
		if cfg.tokenIgnored {
			fmt.Fprintln(os.Stderr, "提示: stdio 传输由客户端独占进程,-mcptoken 不生效(已忽略)")
		}
		if *port != 19080 || *mcpURL != "" || *listen != "127.0.0.1" {
			fmt.Fprintln(os.Stderr, "提示: stdio 传输不监听端口,-port/-listen/-mcpurl 不生效(已忽略)")
		}
		return cfg, nil
	}
	if !cfg.noAuth {
		if cfg.mcpToken == "" {
			gen, err := randomToken(32)
			if err != nil {
				return nil, fmt.Errorf("生成 MCP 鉴权 Token 失败: %w", err)
			}
			cfg.mcpToken = gen
			cfg.mcpTokenGenerated = true
		} else if len(cfg.mcpToken) < minTokenLen {
			cfg.mcpTokenWeak = true
		}
	}
	return cfg, nil
}
