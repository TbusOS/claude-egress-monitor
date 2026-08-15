# Claude 会连哪些域名，以及怎么自己查出来

这份文档回答两个问题：**Claude 的三个入口各自会向外连哪些主机**，
以及**你怎么不信我、自己把这张表重新做一遍**。

第二个问题比第一个重要。网上那种"Claude 域名白名单"列表最大的毛病是
没人知道哪一条已经过期了 —— 版本一升，域名可能就换了。所以这里每一条都
写清取证方式，命令可以直接跑。

---

## 一、取证方法（先讲怎么查）

### 1. Claude Code（CLI）

Claude Code 发行为**单文件可执行**，安装在：

```
~/.local/share/claude/versions/<版本号>
```

它不是压缩包，字符串直接可读：

```bash
BIN=~/.local/share/claude/versions/$(ls -t ~/.local/share/claude/versions | head -1)

# 所有出现过的 https 主机名，按出现次数排序
strings -a "$BIN" \
  | grep -oE 'https://[a-z0-9.-]+\.[a-z]{2,}' \
  | sed 's|https://||' | sort | uniq -c | sort -rn | head -40

# 只看 Anthropic / Claude 自己的域名
strings -a "$BIN" | grep -oE '[a-z0-9-]+\.(anthropic\.com|claude\.ai|claude\.com)' \
  | sort | uniq -c | sort -rn

# 只看遥测相关
strings -a "$BIN" | grep -oiE '[a-z0-9._-]*(datadoghq|sentry\.io|statsig)[a-z0-9._-]*' \
  | sort | uniq -c | sort -rn
```

**读这个结果要小心两件事**，我们自己就踩过：

- **出现次数高 ≠ 运行时会连。** `github.com` 出现近千次，但绝大多数在
  文档字符串、错误提示和示例里。
- **字符串里有某个词 ≠ 存在那个域名。** 二进制里能搜到 `statsig`，
  于是很容易顺手写下一条 `statsig.anthropic.com` —— 而这个主机名**并不存在**，
  实测不解析。真正的第一方开关入口叫 `a-api.anthropic.com`。
  凡是从字符串猜出来的域名，必须再解析一次确认。

### 2. Claude 桌面端

桌面端是 Electron 应用，代码打包在 asar 里，字符串同样可读：

```bash
D=/Applications/Claude.app/Contents/Resources/app.asar

strings -a "$D" | grep -oE '[a-z0-9-]+\.(anthropic\.com|claude\.ai|claude\.com)' \
  | sort | uniq -c | sort -rn

strings -a "$D" | grep -oiE '[a-z0-9._-]*(datadoghq|sentry\.io)[a-z0-9._-]*' \
  | sort | uniq -c | sort -rn
```

### 3. 网页端

浏览器开发者工具的 Network 面板按域名分组即可，不需要工具。
注意网页端的第三方域名会随着页面功能变化，比 CLI 更不稳定。

### 4. 运行时对账（最有说服力的一条）

上面三种都是静态的 —— 它们说明"代码里写了这个域名"，不说明"它真的连了"。
真实连接要看进程的 socket：

```bash
# Claude Code 的进程名是版本号，不是 "claude"，用路径匹配
PIDS=$(ps -Ao pid=,args= | grep '/\.local/share/claude/versions/' \
        | grep -v grep | awk '{print $1}' | paste -sd, -)

lsof -nP -iTCP -sTCP:ESTABLISHED -a -p "$PIDS"
```

本仓的 `cem probe` 做的就是这件事，外加把地址翻译成域名和归属。

---

## 二、清单

清单的权威版本在代码里：[`cem/endpoints.py`](../cem/endpoints.py)。
那里每一条都带 `evidence` 字段，取值含义：

| 证据 | 意思 |
|---|---|
| `cli-strings` | 从 Claude Code 单文件可执行里抽到 |
| `desktop-asar` | 从桌面端 `app.asar` 里抽到 |
| `observed` | 在本机 `lsof` 里真实抓到过这条连接 |
| `docs` | Anthropic 公开文档写明 |

命令行随时打印：

```bash
python3 -m cem endpoints          # 人读
python3 -m cem endpoints --json   # 机读
```

### 分类

**模型 API / 会话（业务主干）**

| 域名 | 说明 |
|---|---|
| `api.anthropic.com` | 模型推理。Claude Code 的绝大部分流量在这里 —— 对话内容、工具调用、文件片段都从这条链路出去。挂在 Anthropic 自有 AS399358 上，anycast |
| `claude.ai` | 网页端主站与会话接口；CLI 走 OAuth 登录时也打这里 |
| `code.claude.com` | Claude Code 侧的后端服务（云端会话、artifact 发布、远程触发）。在 CLI 里出现频次仅次于 api.anthropic.com |
| `platform.claude.com` | 平台 / 控制台接口（组织、用量、密钥管理） |

**特性开关 / 配置**

| 域名 | 说明 |
|---|---|
| `a-api.anthropic.com` | 第一方分析 / 特性开关接口。挂在 Cloudflare 上 |
| `a-cdn.anthropic.com` | 上面那组的静态配置下发端。实测解析到 Google Cloud 的负载均衡地址 |

**遥测**（详见 [02-telemetry.md](02-telemetry.md)）

| 域名 | 说明 |
|---|---|
| `http-intake.logs.us5.datadoghq.com` | Claude Code 的日志遥测出口，整条 URL 在 CLI 里硬编码 |
| `browser-intake-us5-datadoghq.com` | Datadog 浏览器端 SDK 的 intake，桌面端与网页端的前端遥测 |
| `o1158394.ingest.us.sentry.io` | Sentry 崩溃 / 异常上报，US 区 |

**版本更新**

| 域名 | 说明 |
|---|---|
| `releases.claude.com` | 版本元数据，自动更新检查读它 |
| `downloads.claude.ai` | 安装包下载。实测走 Google Cloud，不是 Cloudflare |

**MCP（装了远程 MCP 才有流量）**

| 域名 | 说明 |
|---|---|
| `mcp-proxy.anthropic.com` | 托管 MCP 服务器的代理入口 |
| `mcp.claude.com` | Claude 侧 MCP 目录 / 连接器 |

**其他**：`www.anthropic.com` 被 CLI 用作可用性 / 延迟基准探测。

---

## 三、哪些域名能问出"出口 IP"，哪些不能

这是本仓一个关键的技术分界。

**挂在 Cloudflare 上的域名**都提供一个标准端点：

```bash
curl -s https://claude.ai/cdn-cgi/trace
```

返回纯文本 `key=value`，其中：

| 字段 | 含义 |
|---|---|
| `ip` | **Cloudflare 那一侧看到的你的源地址** —— 这就是"出口 IP" |
| `loc` | 该地址的国家码 |
| `colo` | 接待这次请求的 Cloudflare 边缘机房三字码（`SIN` 新加坡、`NRT` 东京、`SJC` 圣何塞…） |
| `warp` / `gateway` | 是否经过 Cloudflare 自己的隧道产品 |
| `http` / `tls` | 协议与 TLS 版本 |

`cdn-cgi/trace` 在**每个**挂在 Cloudflare 上的站点下都存在，
所以可以拿它做跨站点对照：如果 `claude.ai` 和 `1.1.1.1` 问出来的
`ip=` 不一样，差异只可能来自你本地的分流规则 —— 两边都是 Cloudflare，
对面的实现是同一套。

**不在 Cloudflare 上的域名**（遥测 intake、`downloads.claude.ai`、
`a-cdn.anthropic.com`）没有这个端点，因此**问不出出口 IP**，
只能量可达性和延迟。这类域名在清单里标 `probe="tcp"`，
界面上打「只能量延迟」标签。

本仓对这类域名**只做 TLS 握手，不发任何 HTTP 请求**。往别人的遥测 intake
写数据是污染它的数据，也会让一个监控工具自己变成上报源。

---

## 四、这张表会过期

Claude Code 的发版节奏很快。表里的版本号写在 `cem/endpoints.py`
的 `CLI_VERSION_SAMPLED`，界面右上角也显示。

升级之后重新对账，只要跑第一节那三条 `strings` 命令，
和 `python3 -m cem endpoints` 的输出比一遍即可。有出入就改 `endpoints.py`
—— 改的时候记得**先解析一次确认域名真实存在**。

---

[← 回到目录](index.html) · [遥测 →](02-telemetry.md)
