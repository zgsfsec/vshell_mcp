# vshell-mcp

把 **v_shell 管理平台** 的命令控制、文件管理、隧道代理、监听管理、客户端生成等能力封装为 **MCP Server**,支持 **stdio / SSE / Streamable HTTP** 三种传输,让 AI 可以直接操作平台上的任意受管主机。

## ✨ 功能特性

- **服务器信息**:查看当前连接配置(URL / 账号)、登录用户、服务端版本与授权
- **仪表盘指标**:客户端/监听/代理数量、在线数、CPU/内存/磁盘/负载、带宽、TCP/UDP 连接数
- **主机管理**:列出所有受管主机(在线/离线、系统、IP、用户、归属地)
- **命令控制**:在任意主机上执行 shell 命令(支持管道/重定向/workdir/超时)
- **文件管理**:列目录、读写文件、新建/删除/重命名、上传/下载、URL 下载(wget)
- **隧道代理**:隧道/代理的增删改查、启用/停用、改备注、**连通性自检**(`probe_tunnel`)
- **监听管理**:查看、新增、编辑、启停、改备注(按需求**不提供删除**)
- **客户端生成**:生成并下载客户端(stage 反向 / listen 正向 / stageless / shellcode / dll / ebpf 等)

**共 33 个工具**;`register_client` 与监听器管理工具(edit/start/stop/remark)等由 mock 单测覆盖,其余均通过官方 MCP SDK 与真实 v_shell 实例端到端验证。

## 工作原理

```
AI 客户端(Claude Code / XiangSec 等)
   │  MCP:stdio(客户端代管进程)、Streamable HTTP( POST http://127.0.0.1:19080/mcp )
   │       或传统 SSE( type: sse, url: http://<MCP服务器>:19080/sse )
   ▼
vshell-mcp  (本仓库,Go 编写)
   │  HTTP API: /api/login、/api/client/list、/api/file/*、/api/tunnel/*(POST JSON)
   │  WebSocket: /api/terminal/ws(交互式终端,用于命令控制)
   ▼
v_shell 平台  (http://<v_shell地址>:8082)
```

- **命令控制**:复用 v_shell 管理台的终端 WebSocket(`/api/terminal/ws`)。每条命令开启一次交互式 shell,
  按主机 `OsName` 选用 cmd 或 sh 语法(Linux 先 `stty -echo` 关回显,Windows 不做无用尝试),
  再让 shell 自己拼出 `MCPB_*` / `MCPD_*` 唯一标记夹住命令 —— 标记不以明文出现在输入行里,
  因此不会被终端回显误判;解析前先剥离 ANSI 转义序列与 NUL 填充字节,结束后回传真实退出码。
  取退出码的状态行**等命令真正结束(哨兵提示符再现)后才发**,前面还垫一个"牺牲空行":
  否则状态行会和仍在输出的命令抢终端输入缓冲,首个字符被吞(`echo` 变成 `cho`),
  已成功的命令会被误判成超时(`wmic` 是稳定复现的例子)。命令停在交互式提示(如 `-- More --` 分页)
  时立即中止并说明原因,不再空等到超时。
- **文件/隧道**:直接调用 v_shell 的 `/api/file/*`、`/api/tunnel/*` HTTP 接口。
  批量传输(上传、`/file/downloadtoserver` 暂存)走独立的 24h 超时 client ——
  交互用的 60s 预算对"服务端把几 MB 文件拉到暂存区"这一步太短。
- **输出编码护栏**:命令输出如果不是合法 UTF-8(部分 Windows agent 会原样转发 GBK/CP936 字节),
  Go 的 JSON 编码器本会把每个坏字节替换成 U+FFFD、把乱码当成"成功"。现在会先尝试按 GBK 解码为 UTF-8
  并把结果标成 `output_encoding: "gbk"`,同时附上未经改动的 `output_base64`;实在解不了就整段走 base64
  (`output_is_base64: true`),保证字节可还原。当前 v_shell 4.9.3 的终端已把输出转成 UTF-8(实测),
  这层是防线:换 agent/换版本时不会静默丢字。
- **认证**:启动时用账号密码登录换取 JWT(`Token: <JWT>` 请求头),过期自动重新登录。

## 环境要求

- Go 1.24+(仅构建时需要;运行只需要编译好的二进制)
- 运行机器能访问 v_shell 平台的 Web 地址(HTTP / HTTPS 均可)

## 构建

```bash
go build -o vshell-mcp .
# 或
./run.sh          # 未编译时脚本会自动编译
```

## 配置与启动

全部通过**命令行参数**配置,无需任何环境变量:

```bash
./vshell-mcp -h http://your-vshell-server:8082 -u admin -p 'your_password'
```

| 参数 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `-h <url>` | ✅ | - | v_shell Web 控制台地址,如 `http://your-vshell-server:8082` |
| `-u <user>` | ⭕* | `admin` | 登录账号 |
| `-p <pass>` | ⭕* | - | 登录密码 |
| `-token` | ⭕ | - | 预置 JWT,设置后跳过账号密码登录 |
| `-transport` | ⭕ | `both` | 传输方式:`stdio` / `sse` / `streamable` / `both` |
| `-listen` | ⭕ | `127.0.0.1` | HTTP 监听地址(**默认仅本机**;对外暴露用 `0.0.0.0`) |
| `-port` | ⭕ | `19080` | MCP HTTP 服务监听端口 |
| `-mcpurl` | ⭕ | 空 | MCP 服务器对外可达地址(置于反向代理后时设置) |
| `-prefix` | ⭕ | `/api` | v_shell API 路径前缀 |
| `-timeout` | ⭕ | `60` | 单次请求超时(秒) |
| `-mcptoken` | ⭕ | 随机生成 | MCP 接入鉴权 Token(Bearer);留空时启动随机生成并打印一次 |
| `-noauth` | ⭕ | 关 | 关闭 MCP 接入鉴权(**危险**,仅限回环 / SSH 隧道场景) |
| `-help` | - | - | 显示帮助 |

**传输方式怎么选**

| `-transport` | 端点 | 适用客户端 |
|---|---|---|
| `both`(默认) | `/mcp` 与 `/sse` 同一端口 | 不折腾:新旧客户端都能接,不带参数即此模式 |
| `streamable` | `POST /mcp`(单端点) | 现代客户端:XiangSec、Claude Code(`--transport http`)等 |
| `sse` | `GET /sse` + `POST /message` | 只认传统 HTTP+SSE 的客户端(如 MCP Python SDK 的 `sse_client`) |
| `stdio` | 无监听(由客户端启动本进程) | 客户端自己拉起子进程:XiangSec stdio、Claude Desktop 等 |

> `stdio` 模式下进程独占 stdin/stdout(JSON-RPC 通道),因此**不监听端口**、`-mcptoken` / `-noauth` / `-listen` / `-mcpurl` 均不生效(会打印一行 stderr 提示),所有日志走 stderr,stdout 保持干净。

> `*`:设置了 `-token` 则账号密码可省;否则 `-p` 必填(`-u` 默认 `admin`)。
> ⚠️ `-h` 已绑定为 v_shell **地址**参数(非 help);查看帮助请用 `-help`。
> ⚠️ **HTTP 传输默认带 Bearer 鉴权,且不允许与 `-noauth` 同时使用 `-mcptoken`;**`-noauth` 与 `stdio` 也不能同时使用。

启动时先做一次登录/连通性校验,凭据错误会直接报错退出。正常启动(默认 `both`):

```
v_shell MCP server listening on 127.0.0.1:19080
  Streamable HTTP: http://127.0.0.1:19080/mcp
  SSE endpoint:    http://127.0.0.1:19080/sse
MCP 鉴权: Authorization: Bearer 791b4b2c...(随机生成,或用 -mcptoken 固定)
```

`-transport streamable` 只打印 `/mcp` 一行,`-transport sse` 只打印 `/sse` 一行。

## 接入 AI 客户端

先启动服务(HTTP 传输默认已是 `both`,`-mcptoken` 请用 ≥32 位随机串):

```bash
./vshell-mcp -h http://your-vshell-server:8082 -u admin -p 'your_password' \
  -mcptoken '<32位随机串>'
```

### Streamable HTTP(XiangSec 等)

「新增 MCP 服务」表单里按下面填(点「提交预览」可先核对写进 `config.toml` 的条目):

| 字段 | 值 |
|---|---|
| 服务标识 | `vshell`(只允许字母/数字/下划线/连字符,工具会以 `mcp__vshell__<工具名>` 暴露) |
| 显示名称 | `v_shell`(随意) |
| 传输方式 | `streamable_http(远程端点)`——**不要选 stdio**,也不支持 sse |
| 服务 URL | `http://127.0.0.1:19080/mcp`(注意是 `/mcp`,不是 `/sse`) |
| 认证方式 | `Bearer Token` |
| Bearer Token | 与 `-mcptoken` 完全一致的值 |

等价于给 `/mcp` 的每个请求带 `Authorization: Bearer <mcptoken>`:缺失或错误一律 `401`
(initialize 就要带,客户端会在首次连接时报"鉴权失败")。

### Claude Code

```bash
claude mcp add vshell --transport sse http://<MCP服务器>:19080/sse \
  --header "Authorization: Bearer <mcptoken>"
```

或写入项目 `.mcp.json` / `~/.claude.json`:

```json
{
  "mcpServers": {
    "vshell": {
      "type": "sse",
      "url": "http://<MCP服务器>:19080/sse",
      "headers": { "Authorization": "Bearer <mcptoken>" }
    }
  }
}
```

> **每个请求都必须带这个 header**(SSE 流与 `/message` 投递端点都要求);缺失或错误一律 `401`。
> 若服务端用了 `-noauth`(仅建议在回环 / SSH 隧道下),则可省略 header。

> MCP 服务运行在其它机器时,`url` 填该机器的地址与端口;若开了 `-mcpurl`,填它生成的地址。

### 其它支持 SSE MCP 的客户端

通用配置:`type: sse`,`url: http://<mcp服务器>:19080/sse`。

### 由客户端启动(stdio,不占端口)

客户端自己拉起子进程时用 `-transport stdio`,无需 `-mcptoken`、也不监听端口:

| 字段 | 值 |
|---|---|
| 传输方式 | `stdio(本地进程)` |
| 启动命令 | `D:\path\to\vshell-mcp-windows-amd64.exe` |
| 命令参数 | 每行一个:`-h` / `http://your-vshell-server:8082` / `-u` / `admin` / `-p` / `<密码>` / `-transport` / `stdio` |
| 工作目录 | 留空或二进制所在目录 |

> 该模式下 stdout 是 JSON-RPC 通道,任何日志都走 stderr;若客户端能看到子进程 stderr,
> 启动时会看到 `vshell-mcp: transport=stdio(...)` 一行。

## 工具清单(32 个)

> 通用说明:`host_id` 为「客户端管理」里的主机 Id(见 `list_hosts`);`local_path` 等本地路径均指 **MCP 服务器所在机器** 的路径。

### 服务器信息(2)

| 工具 | 参数 | 说明 |
|---|---|---|
| `get_server_info` | `reveal_password`? | 当前连接配置(URL/账号/API 前缀)、登录用户、服务端版本/端口/授权;**密码默认打码**为 `******`,传 `reveal_password=true` 才返回明文 |
| `get_dashboard` | - | 服务器仪表盘指标(客户端/监听/代理数量、在线数、CPU/内存/磁盘/负载、带宽、TCP/UDP 连接、版本/授权到期) |

### 主机与命令控制(2)

| 工具 | 参数 | 说明 |
|---|---|---|
| `list_hosts` | `host_id`? `online_only`? | 列出所有主机;`host_id` 查单台,`online_only=true` 只查在线 |
| `execute_command` | `host_id`* `command`* `workdir`? `timeout_seconds`? | 在主机上执行 shell 命令,返回 `output`(stdout+stderr 合并)、`exit_code` 与 `ok`;默认超时 60s。**按主机系统自动选用语法**:Windows 走 cmd(`&` 串联、`%VAR%` 变量),Linux/macOS 走 sh(`;` 串联、`$VAR`)。命令在超时内未结束则返回错误并附上已捕获的部分输出 |

### 文件管理(12)

| 工具 | 参数 | 说明 |
|---|---|---|
| `list_directory` | `host_id`* `path`? | 列出主机目录(默认 `/`) |
| `get_disks` | `host_id`* | 主机磁盘/挂载信息 |
| `read_file` | `host_id`* `path`* `filename`* | 读取文件;二进制自动 base64(`base64_encoded`)。**服务端按 UTF-8 解码**,GBK/ANSI 等本地编码会被替换成 U+FFFD 且原字节不可恢复——此时返回 `bytes_replaced` + `encoding_warning`,要原始内容请用 `download_file` |
| `write_file` | `host_id`* `path`* `filename`* `content`* | 写入/覆盖文件 |
| `create_directory` | `host_id`* `path`* `dirname`* | 新建目录 |
| `create_file` | `host_id`* `path`* `filename`* | 新建空文件 |
| `delete_file` | `host_id`* `path`* `filename`* | 删除单个文件/目录 |
| `delete_files` | `host_id`* `path`* `names`* | 批量删除 |
| `rename_file` | `host_id`* `path`* `target`* `new_name`* | 重命名/移动(可带路径) |
| `upload_file` | `host_id`* `path`* `local_path`* `remote_name`? | 上传本地文件到主机;默认以本地 basename 命名 |
| `download_file` | `host_id`* `path`* `filename`* `local_path`? `stage_wait_seconds`? | 下载主机文件到本地(**两跳**:服务端先从目标拉到自己暂存目录,再发给 MCP)。暂存没完成时返回 `staged=false` + `staging_percent` + 重试指引(**不会**给出半个文件);`stage_wait_seconds` 默认 120 |
| `wget_file` | `host_id`* `path`* `url`* | 让主机通过 URL 下载文件 |

### 隧道 / 代理(9,对应 `/tunnel/list`)

| 工具 | 参数 | 说明 |
|---|---|---|
| `list_tunnels` | - | 列出所有隧道:Id、绑定客户端、模式、端口、目标、账号、启用/停用、客户端在线状态 |
| `add_tunnel` | `client_id`* `port`* `mode`? `target`? `username`? `password`? `remark`? | 新建隧道;`mode` 为 `socks5`/`http`/`tcp`/`udp`(默认 socks5),`tcp`/`udp` 必须带 `target`(格式 `10.1.1.99:80`) |
| `edit_tunnel` | `id`* + 上述字段 | 编辑隧道配置 |
| `set_tunnel_remark` | `id`* `remark`* | 修改隧道备注 |
| `start_tunnel` | `id`* | 启用隧道;**幂等**(已运行返回 `status=already_running`) |
| `stop_tunnel` | `id`* | 停用隧道;**幂等**(已停止返回 `status=already_stopped`) |
| `delete_tunnel` | `id`* | 删除单条隧道 |
| `delete_tunnels` | `ids`* | 批量删除隧道(Id 数组) |
| `probe_tunnel` | `id`* `target`? `send`? `send_hex`? `timeout_seconds`? | **连通性自检**:在隧道端口上跑一次真实转发,以**数据面**判定通不通(见下方「隧道判活」);`send`/`send_hex` 可发一个该协议的请求,把"无法判定"变成"确定通" |

> **隧道判活(v_shell 的 SOCKS 回码不可信)**:v_shell 的 socks5 代理对**任何** CONNECT 都回成功码
> `0x00`(不存在的主机、无路由、关闭的端口同样回 `0x00`)。所以**不要**用 SOCKS 应答码判断端口/主机存活,
> 直接用 `probe_tunnel`,它的结论来自数据面:
> `data_open`=收到数据(确定通)、`refused`=连接被立即关闭(拒连/不可达)、
> `no_data`=连接没被关闭但窗口内没有数据(**无法判定**:可能是服务存活但不先发言,也可能是主机不可路由、
> 转发还卡在 TCP 超时上)、`open_request_rejected`=不带请求时连接保持、带上 `send` 才被关闭
> (**端口是开的**,只是这段请求被对端拒了,例如把 HTTP 请求发给了 MSSQL)、`unreachable`=代理明确回报无路由、
> `proxy_down`=隧道端口都连不上(未启用/服务端不可达)、`unsupported`=udp 隧道无法这样测。
>
> 想避开 `no_data` 的歧义就给 `send`(如 `GET / HTTP/1.0\r\n\r\n`)或 `send_hex`(二进制协议):
> 工具会先做一次**不带请求的基准探测**,因此"端口关闭"与"端口开着但拒绝这段请求"能被区分开;
> 有数据回来才是 100% 确定,`first_bytes_hex` 可以用来识别协议 banner(MSSQL/SSH/TLS 等)。

### 监听器(6,对应 `/listener/list`)

> 按需求:**不提供删除监听器**(未暴露 `/listener/del`、`/listener/dellist`),但启停/编辑/改备注齐全。

| 工具 | 参数 | 说明 |
|---|---|---|
| `list_listeners` | `status`? `mode`? | 查看所有监听器:Id、模式、监听地址、外网连接地址、心跳间隔、超时心跳次数、Vkey、加密盐、备注、运行状态 |
| `add_listener` | `listen_addr`* `mode`? `vkey`* `encrypt_salt`* `client_id`? `connect_addr`? `ws_connect_addr`? `dns_domain`? `public_dns`? `oss_url`? `disconnect_timeout`? `ping_interval`? `remark`? | 新建监听器;`mode` 为 `tcp`/`kcp`/`ws`/`dns`/`doh`/`dot`/`oss`(默认 tcp),各模式地址要求见工具描述 |
| `edit_listener` | `id`* `listen_addr`* `vkey`* `encrypt_salt`* + 与 `add_listener` 相同字段 | 修改监听器配置;**先 `list_listeners` 读出当前值整体回传**,漏传的字段会落回默认值(tcp / 30 / 10) |
| `start_listener` | `id`* | 启用(启动)监听器;**幂等**(已运行返回 `status=already_running`) |
| `stop_listener` | `id`* | 停用监听器;**幂等**(已停止返回 `status=already_stopped`) |
| `set_listener_remark` | `id`* `remark`* | 只改备注,不动其他配置 |

> ⚠️ **`listen_addr` 永远绑定在 v_shell 服务端主机上**:`client_id` 只是记录绑定关系,
> **不会**让监听端口开在被绑定的目标主机上(目标机 `netstat` 查不到该端口,别据此以为"监听到了内网")。
> 要在内网主机上开监听端口,用 `generate_client(kind=listen)` 的 bind 载荷 + `register_client` 把该主机纳入控制台。
> `open failed` 基本都是服务端侧原因:端口被占用、无权限绑定、地址不属于服务端本机。
>
> ⚠️ `list_listeners` 的 `status`/`mode` 过滤**由 MCP 本地完成**(v_shell 的 `/listener/list` 并不按 `status` 过滤),
> 并返回 `total`(过滤后)、`total_unfiltered`(全部)、`filtered_out`(被过滤掉的条数),用于区分"没有监听器"和"全被过滤掉"。

### 客户端生成与正向注册(2)

| 工具 | 参数 | 说明 |
|---|---|---|
| `generate_client` | `kind`* `save_path`* `arch`? `listener_id`? `tp`? `host`? `port`? `vkey`? `salt`? `upx`? `proxy`? `format`? | 生成并下载客户端到 `save_path`。`kind`:`stage`(需 `listener_id`+`arch`)/ `listen`(需 `arch`+`tp`+`host`+`port`+`vkey`+`salt`)/ `listendll`(同 listen,arch 为 .dll)/ `stageless`(需 `listener_id`+`arch`)/ `shellcode`(需 `listener_id`+`arch`+`format`)/ `dll`(需 `listener_id`+`arch`)/ `ebpf`(需 `arch`+`tp`+`vkey`+`salt`) |
| `register_client` | `vkey`* `salt`* `tp`? `ip`? `port`? `host`? `ebpf`? `proxy`? | **正向(bind)客户端注册**:让服务端主动去连目标上已在监听的 bind payload,使其上线(对应控制台「新增正向客户端」)。参数必须与生成 payload 时一致;`tp=tcp/kcp` 给 `ip`+`port`,`tp=ws` 给 `host`(如 `ws://1.2.3.1:8080/ws`)。成功后用 `list_hosts` 确认 `IsConnect=true` |

> **正向上线流程**:`generate_client(kind=listen)` 生成 bind payload → 投递并在目标上运行(它会监听端口)→
> `register_client`(`tp`/`ip`/`port`/`vkey`/`salt` 与生成时一致)→ `list_hosts` 里出现该主机。
> 前提是 v_shell 服务端网络能直达该监听地址,否则注册会失败。
> 反向(stage/stageless 等)则不需要这一步——payload 自己回连,主机自动上线。
>
> ⚠️ **首次投递是带外环节**:生成物落在 **MCP 服务器本地**,而 `upload_file` 要求目标主机**已经在线**,
> 二者互锁。首台主机必须用带外通道投递(HTTP 下载、共享目录、已有 shell 等);上线之后才能用 `upload_file`
> 铺开到后续目标。
>
> ⚠️ `register_client` 是**新增**语义:同一目标重复注册会累积多条记录(旧的停在离线状态),需在控制台清理。
> 返回里会给出 `records_matching_target` / `records_matching_target_offline`(按 `Addr`/`LocalIP` 尽力匹配),
> 便于发现重复记录。
>
> ⚠️ 「服务端能不能连到目标」没有独立的预探测接口——`register_client` **本身就是探测**:调用成功且
> `list_hosts` 里出现该主机(`IsConnect=true`)才算真的通。失败通常意味着目标 payload 没在监听,
> 或服务端到该地址路由不通;反方向的「服务端经隧道 → 目标」可以用 `probe_tunnel` 先验证。

(* = 必填;? = 可选)

## 测试

```bash
# 单元测试(传输选择、/mcp 与 /sse 的 Bearer 鉴权、路由、终端分帧解析)
go test ./...

# 终端解析回归:用真实抓取的 Windows cmd / Linux sh 帧驱动,覆盖回显、ANSI 尾巴、
# 退出码与超时分支(见 internal/vshell/terminal_frames_test.go)
go test ./internal/vshell -run 'TestExec|TestParseExec|TestHasPrompt' -v

# register_client 与监听器管理(edit/start/stop/remark)的请求体/校验/错误传播
# (mock HTTP,不碰真实 v_shell)
go test ./internal/vshell -run 'TestAddClient|TestListener|TestEditListener' -v
go test ./internal/mcp -run 'TestRegisterClient|TestListener' -v

# 隧道连通性探测(内置假 socks5/目标服务,验证数据面判定与回码陷阱)
go test ./internal/vshell -run 'TestProbe|TestSplitTarget' -v

# 输出编码护栏(GBK 解码、base64 兜底、JSON 不产生 U+FFFD)
go test ./internal/mcp -run 'TestDecodeCommandOutput' -v

# 对真实 v_shell 实例跑完整冒烟(需配好 -h -u -p)
VSHELL_URL=http://your-vshell-server:8082 VSHELL_USERNAME=admin VSHELL_PASSWORD=xxx \
  go run ./cmd/smoke

# 用官方 MCP Python SDK 连接运行中的 MCP 服务并调用工具(传统 SSE)
python3 tests/client_smoke.py
```

### 真机验证探针(可选)

`tests/live_verify_probe.go.txt` 是针对真实靶机的一次性验收脚本,覆盖:
命令输出无标记泄漏/无 NUL、`for`/`if`/无换行输出等形态、`-- More --` 分页快速失败、
以及 >3MB 文件下载(用 `ntoskrnl.exe` 做只读样本,不写靶机)。用法:

```bash
cp tests/live_verify_probe.go.txt internal/vshell/zz_verify_probe_test.go
VSHELL_PROBE=1 VSHELL_PASSWORD=xxx go test ./internal/vshell -run TestZZVerify -v
rm internal/vshell/zz_verify_probe_test.go      # 用完即删
```

> 该探针会编译出一个连接 C2 的临时测试二进制。**若装了杀软请先把项目目录、`%LOCALAPPDATA%\go-build`
> 与 `%LOCALAPPDATA%\Temp\go-build*` 加入信任区**,否则 `vshell.test.exe` 会被以
> `HEUR:Backdoor/*` 隔离(go test 表现为 `exit status 0xffffffff`)。
> 也可以 `go test -c -o build/local-verify.exe ./internal/vshell` 后直接运行该 exe 绕开临时目录。

## 项目结构

```
.
├── main.go                 入口:命令行参数解析、登录校验、按 -transport 启动 stdio / HTTP 服务
├── internal/
│   ├── vshell/             v_shell 客户端
│   │   ├── client.go       HTTP 封装(登录、Token 刷新、统一响应解析)
│   │   ├── terminal.go     终端 WebSocket 命令执行
│   │   ├── files.go        文件管理操作
│   │   ├── tunnel.go       隧道/代理管理操作
│   │   ├── probe.go        隧道连通性探测(socks5/http/tcp,以数据面判定)
│   │   ├── listener.go     监听器管理操作(仅查看/新增,无删除)
│   │   ├── client_gen.go   客户端生成/下载
│   │   ├── clients.go      正向(bind)客户端注册(POST /client/add)
│   │   ├── dashboard.go    服务器信息与仪表盘
│   │   └── types.go        数据结构
│   └── mcp/
│       ├── server.go       MCP 工具定义与处理器 + 传输层(stdio / SSE / Streamable HTTP + Bearer 鉴权)
│       └── output_encoding.go 命令输出编码护栏(UTF-8 校验 / GBK 解码 / base64 兜底)
├── cmd/smoke/main.go       冒烟测试程序
├── tests/client_smoke.py   官方 MCP SDK 验证脚本
├── docs/API_NOTES.md       v_shell Web API 逆向笔记
└── run.sh                  启动脚本(自动编译 + 参数透传)
```

## 安全说明

- **本工具能执行任意命令、增删文件与隧道**,属于强能力工具,请只对你自己拥有管理权限的 v_shell 平台使用。
- **MCP 端口必须带鉴权**:HTTP 传输默认只监听 `127.0.0.1:19080`(仅本机);一旦用 `-listen 0.0.0.0`
  对外暴露,任何能路由到该端口的人都能控制整个 v_shell。默认已强制
  `Authorization: Bearer <mcptoken>`(`/mcp`、`/sse`、`/message` 全部覆盖;未指定则启动随机生成),
  比对为常数时间且大小写不敏感的 scheme 匹配;`-noauth` 仅供回环 / SSH 隧道场景使用。
  **对外暴露时强烈建议**用防火墙限制来源 IP,例如
  `ufw allow from <你的出口IP> to any port 19080`,或干脆保持回环监听 + `ssh -N -L 19080:127.0.0.1:19080 user@server`。
- **不要只靠 CORS/DNS-rebinding 防护**:上游 SSE 传输默认给 `/sse` 回 `Access-Control-Allow-Origin: *`,
  Bearer 头能挡住浏览器发起的跨域请求(EventSource 无法自定义 header),但它不替代鉴权与防火墙。
  Streamable HTTP 传输自带 DNS-rebinding 防护:回环连接若带非回环 `Host` 头会回 `403`。
- `get_server_info` 默认把登录密码打码成 `******` 并返回 `password_masked: true`(避免凭据进入对话记录/日志);
  确需明文时显式传 `reveal_password: true`。
- 命令控制走的是目标主机的真实 shell,交互式程序(`vim`、`passwd`、`top` 等)会卡住,请用非交互命令。
- `execute_command` 会在会话里临时改写目标 shell 的提示符为哨兵串(`MCPP<随机>)`,并把 `_r<随机>`/`_s<随机>`
  两个变量留在该会话环境里;每次执行都开新会话,退出即消失,不影响主机上的其他配置。
  发送状态行前还会先敲一个空行(牺牲行),用来吸收终端可能吞掉的第一个字节。
- 启动参数中的密码会出现在进程命令行(`ps` 可见),生产环境建议结合密钥管理或 `-token` 使用。

## 常见问题

- **启动报"无法连接 v_shell"** — 检查 `-h` 地址是否可达、`-u`/`-p` 是否正确、账号是否有权。
- **`execute_command` 返回空 / 超时** — 目标主机可能离线(`IsConnect=false`),或命令是交互式程序。
  耗时命令在调用时调大 `timeout_seconds` 参数(如 `timeout_seconds=300`)。超时会返回**错误**(不是空结果),
  并附带已捕获的部分输出,表示命令可能仍在主机上运行。
- **报"停在交互式提示 `-- More` 上"** — 命令打开了分页器(典型是 `... | more`)。已在检测到时立即中止,
  不会空等到超时;请去掉 `| more`、或改成重定向到文件后 `read_file`、或用 `findstr` 过滤。
- **`echo|set /p=x` 的 `exit_code` 是 1** — 这是 cmd 的真实语义(`set /p` 从管道读到 EOF 返回 1),不是解析错误。
- **大文件下载"卡很久"或拿到的文件只有一部分** — 两个原因都已修:
  1. `download_file` 是**两跳**:①服务端把文件从**目标主机**拉到自己的暂存目录 `download/<客户端Id>/`(慢的一跳),
  ②MCP 再从服务端取回本地(通常很快)。第 ① 跳由服务端**后台继续**,和本次工具调用是否超时无关 —— 所以
  `stage_wait_seconds`(默认 120)到点后工具返回 `staged=false` + `staging_percent` + `size_bytes`,**不返回半个文件**;
  **直接重试**即可,暂存完成时通常秒回(实测 39 MB dump:全新暂存 60 秒 → 重试取回 **0.6 秒**,报 `staged_reused: true`)。
  2. **`/file/getdownloadper` 的百分比是按请求里的 `size` 算的**:旧实现传 `size:0`,服务端就**恒回 `pre:100`**,
  文件还在写就被当成"暂存完成"拉下来 → 截断的文件 + 报成功(实测:暂存 3 MB / 7.4 MB 时,`size=0` 回 100、带真实 size 回 42)。
  现在先查目标文件真实大小再轮询,只有 staged 字节数 = 目标大小才取回。
- **大文件要更快?别只用 vshell 文件通道** — 实战经验(39 MB 的 lsass 全内存 dump):第 ① 跳要过 C2 通道,而
  「目标侧 SMB 拷到 web1 的可下载目录 → 直接 HTTP 拉」走的是同网段直连,秒下。可复用的做法:
  `execute_command` 里 `copy` 到一台有 HTTP 服务的机器(如 web1 的站点目录),再用 `wget_file` 或 MCP 外的 HTTP 拉取;
  小文件继续用 `download_file` 即可。
- **`execute_command` 的 `exit_code` 非 0** — 命令本身失败(`ok=false`),`output` 里通常有 shell 的报错;
  `exit_code=-1` 表示 shell 没能回报状态(例如命令还没跑完就被超时打断)。
- **Windows 主机上的命令写法** — 走的是 cmd:`dir`、`type C:\path\file.txt`、`tasklist | findstr x`,
  变量用 `%TEMP%`,串联用 `&&`/`&`;**不要**用 `$VAR`、单引号或 `ls`(那是 sh 语法)。
  Linux/macOS 主机则相反。
- **Windows 主机命令以前必失败(已修复)** — `shell prompt not detected on connect` 是旧版本对
  cmd 提示符里的 ANSI 转义序列判断错误所致,现按主机 `OsName` 选择 cmd/sh 语法并剥离转义序列后再解析。
- **`download_file` 失败** — 文件在主机侧须存在且当前用户可读;下载是异步任务,大文件需等待轮询完成。
- **`add_tunnel` 报参数错误** — 检查:`mode=tcp/udp` 必须给 `target`;`port` 不能与已有隧道/服务端口冲突。
- **SOCKS5 代理回了成功但连不上/`proxychains`、nmap 满屏假阳性** — v_shell 的 socks5 **对任何 CONNECT 都回
  `0x00`**(实测:不存在的主机、无路由、关闭的端口一律 `0x00`),这是**服务端行为**,不要用 SOCKS 应答码判活。
  判活请用 `probe_tunnel`:它看数据面 —— 连接被立即关闭=`refused`(确定不在)、收到数据=`data_open`(确定在)、
  连接不关也没数据=`no_data`(**无法判定**:服务不先发言 与 主机不可路由 在这一步无法区分)。
  要确定结论就用 `send`/`send_hex` 发一个该协议的请求(如 `GET / HTTP/1.0\r\n\r\n`),有回应即确定可达;
  或用 `first_bytes_hex` 识别协议 banner。同理,用第三方工具走这个 socks5 端口时要靠数据面/超时判断。
- **`add_listener` 在目标机上看不到端口** — `listen_addr` **永远绑定在 v_shell 服务端主机上**(服务端进程
  `netstat` 可见,目标机看不到)。`client_id` 不会改变这一点。要在内网主机上开端口,用
  `generate_client(kind=listen)` 的 bind 载荷 + `register_client`。`open failed` 的常见原因是端口占用/无权限/
  地址不属于服务端本机(错误信息里现在会带上地址与模式)。
- **`get_dashboard` 的 `hostCount` 是 0,但明明有主机在线** — v_shell 4.9.3 的 `hostCount` 实测就是 0
  (`clientCount`/`clientOnlineCount` 才是对的)。工具会额外给出 `hosts_total` / `hosts_online`(取自
  `clientCount`/`clientOnlineCount`)并在不一致时给出 `hostCount_warning`;判断"有没有主机在线"用这两个字段
  或 `list_hosts(online_only=true)`。
- **`list_listeners` 加了过滤却看到别的状态的监听器 / 结果为 0** — v_shell 的 `/listener/list` 不按 `status`
  过滤,过滤现在由 MCP 本地完成,并给出 `total_unfiltered` 与 `filtered_out`;`total=0` 时看 `note` 区分
  "没有监听器"还是"全被过滤掉"。
- **重复调用 `start_tunnel` / `start_listener` 报错** — 现在幂等:本来就处于目标状态时直接返回
  `status=already_running` / `already_stopped`(不调用服务端、不算失败);真正失败时错误里带 `Id`、当前
  `RunStatus`/`Status`、端口与客户端在线状态。
- **`execute_command` 的中文输出变成乱码** — 现在有编码护栏:非法 UTF-8 会先按 GBK 解码并标注
  `output_encoding: "gbk"`(同时给 `output_base64` 原始字节);解不了则 `output_is_base64: true`。
  若仍看到 U+FFFD,说明上游(目标 agent/服务端)已经做过一次有损解码,原始字节不可恢复——让目标改用 UTF-8 输出
  (Windows 上先 `chcp 65001`),或对文件走 `read_file`/`download_file`。
- **MCP 客户端连接不上** — 确认 MCP 服务器已启动且端口可访问;检查防火墙;用了 `-mcpurl` 时确认对外地址可达。
  若客户端只支持 `streamable_http`(如 XiangSec)或只认传统 SSE,默认的 `both` 已同时提供 `/mcp` 与 `/sse`,
  确认 URL 写的是 `/mcp` 还是 `/sse` 即可;漏带 `Authorization: Bearer <mcptoken>` 会在 initialize 阶段就 401。
