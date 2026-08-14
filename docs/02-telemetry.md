# 遥测：那个 Datadog 是哪儿的，怎么关

## 零、Datadog 是什么

**一家做监控 / 可观测性的美国 SaaS 公司**（纽交所 DDOG）。它卖的东西很简单：
你的软件把自己的运行日志、性能指标、报错发到 Datadog 的服务器，
你的团队在 Datadog 的网页控制台里看图表、查报错、设告警。
同类产品还有 New Relic、Grafana Cloud、Splunk。

所以看到 Claude Code 连 `datadoghq.com` 时，正确的理解是：
**Claude Code 把自己的客户端运行日志发给了 Anthropic 的监控服务商**，
Anthropic 用它看"客户端有没有崩、慢在哪、哪个功能报错多"。
这不是一个可疑的第三方，而是这类软件的标准做法。

真正要问清的只有三件事，这份文档就答这三件：

1. **发到哪个地区** —— Datadog 分成好几个互不相通的站点，
   Claude Code 用的是落在**美国 Google Cloud** 上的那个（US5）。
2. **多久发一次、发多少** —— 默认 15 秒一批，一批最多 100 条。
3. **能不能关** —— 能，有环境变量；桌面端和网页端只能在网络层拦。

至于**包里具体写了什么内容**，静态分析答不了，这个工具也不去解密 TLS
偷看。它只回答"流量去了哪、走了哪条路、多久一次"。

## 一、结论

Claude Code 的遥测有三条独立的链路，落在三家不同的服务上：

| 链路 | 目的地 | 区域 | 谁在用 |
|---|---|---|---|
| 日志 | `http-intake.logs.us5.datadoghq.com` | Datadog **US5** 站点，落地美国 | Claude Code（CLI） |
| 前端日志 / RUM | `browser-intake-us5-datadoghq.com` | 同上 | 桌面端、网页端 |
| 崩溃 / 异常 | `o1158394.ingest.us.sentry.io` | Sentry **US** 区 | CLI、桌面端 |

再加一条**不是遥测但常被算进来**的：`a-api.anthropic.com` /
`a-cdn.anthropic.com` 是第一方的特性开关与配置下发，
关掉它会影响功能开关下发，和"上报"不是一回事。

---

## 二、Datadog US5 到底是哪里

`us5` 不是"美国第五个机房"这种意思，它是 Datadog 的**站点代号**。
Datadog 把 SaaS 分成若干独立站点，各自有独立的数据存储和访问域名：

| 站点 | 域名后缀 | 底层云 |
|---|---|---|
| US1 | `datadoghq.com` | AWS |
| US3 | `us3.datadoghq.com` | Azure |
| **US5** | **`us5.datadoghq.com`** | **Google Cloud** |
| EU1 | `datadoghq.eu` | AWS，欧洲 |
| AP1 | `ap1.datadoghq.com` | AWS，日本 |
| AP2 | `ap2.datadoghq.com` | AWS，澳洲 |

Claude Code 里**六个站点的域名都在**（浏览器 SDK 会把整张站点表打进包里），
但**实际使用的是 US5** —— 因为硬编码的那条完整 URL 指向它。

可以自己确认落地位置：

```bash
# 真实解析（绕过本机可能存在的 fake-ip 改写）
curl -s -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=http-intake.logs.us5.datadoghq.com&type=A'

# 查这个地址属于谁（Team Cymru 的 DNS 接口，读 BGP 全表，不要 key）
# 把 a.b.c.d 反过来拼在 origin.asn.cymru.com 前面
dig +short TXT <d>.<c>.<b>.<a>.origin.asn.cymru.com
```

实测解析结果落在 Google Cloud 的地址段里，与"US5 跑在 GCP 上"一致。

本仓的 `cem probe` 会自动做这两步，输出在「解析对账」和「实时连接」里。

---

## 二点五、一条命令看全部字段

```bash
python3 -m cem telemetry              # 人读
python3 -m cem telemetry --all-events # 连 182 个事件名一起列
python3 -m cem telemetry --json       # 机读
```

它从**你本机安装的那个版本**里现读，不是一份写死的清单 ——
写死的清单过两个版本就是错的，而且没人知道它错了。

几个直接读得出来的结论：

- `hostname` 是硬编码的字符串 `"claude-code"`，**不会上报你的真实主机名**
- `head_sha` 会上报当前 git HEAD 的 commit sha
- 有个函数叫 `stripPiiFieldsForDatadog` —— 上报前会主动剥离 PII 字段
- 事件名有白名单，不在名单里的事件发不出去

边界见 [06-toolbox.md](06-toolbox.md)：静态提取只能知道「会发哪些字段」，
不知道「某一次具体发了什么值」。

## 三、CLI 里的硬编码证据

```bash
BIN=~/.local/share/claude/versions/$(ls -t ~/.local/share/claude/versions | head -1)
strings -a "$BIN" | grep -oE '.{120}us5\.datadoghq\.com.{120}'
```

会看到类似这样一段（片段，字段名可能随版本变化）：

```
… jed="https://http-intake.logs.us5.datadoghq.com/api/v2/logs",
   oNo="pubea…5bc",   ← Datadog 的公开 client token
   bI_=15000,         ← 攒批间隔，毫秒
   SI_=100,           ← 一批最多多少条
   … CLAUDE_CODE_DATADOG_FLUSH_INTERVAL_MS …
```

三个可以直接读出来的事实：

1. 走的是 Datadog 的 **v2 日志接入接口**，不是 metrics、不是 trace。
2. 默认**每 15 秒攒一批发一次**，一批上限 100 条。
   环境变量 `CLAUDE_CODE_DATADOG_FLUSH_INTERVAL_MS` 可以改这个间隔。
3. 那个 `pub…` 是 Datadog 的 **client token**（前缀就是 `pub`），
   设计上就是要放进客户端的公开凭据，只能写入、不能读别人的数据。
   这里故意只写前后几位 —— 想看完整值自己跑上面那条命令，
   把别人的凭据抄进文档没有意义。

**它上报什么内容？** 这一点静态字符串答不了，本仓也不去解密 TLS 去看。
Anthropic 的隐私文档是唯一权威说明。这个工具只回答**流量去了哪个地区、
走了哪条路、多久一次**，不声称知道包里写了什么 —— 这条边界要画清楚。

---

## 四、怎么关

### Claude Code

相关环境变量（都是从 CLI 二进制里抽出来的，可自行 `strings` 确认）：

```bash
# 关掉非必要出网。范围最大的一个开关。
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# 单独关错误上报（Sentry）
export DISABLE_ERROR_REPORTING=1

# 单独关遥测
export DISABLE_TELEMETRY=1

# 关自动更新检查（会打 releases.claude.com）
export DISABLE_AUTOUPDATER=1

# 改 Datadog 攒批间隔（不是关，是放缓）
export CLAUDE_CODE_DATADOG_FLUSH_INTERVAL_MS=60000
```

想确认到底关掉没有，**别只看环境变量，看连接**：

```bash
python3 -m cem probe            # 「此刻的连接」那一节
```

如果关了之后 `lsof` 里再也不出现指向 Datadog / Sentry 的连接，
那就是真的关了。这比读文档可靠。

另外，CLI 也支持把遥测导到**你自己的** OpenTelemetry 收集器 —— 二进制里
有整套 `OTEL_EXPORTER_OTLP_*` 变量和 `CLAUDE_CODE_ENABLE_TELEMETRY`。
企业环境里这通常比"全关掉"更实用：数据留在自己的收集器里。

### 桌面端 / 网页端

桌面端和网页端的遥测由应用内部控制，没有环境变量入口。
能做的是在网络层拦：

- 在分流器（Clash / Surge / sing-box）里给
  `*-intake-*.datadoghq.com`、`*.ingest.us.sentry.io` 配 `REJECT`；
- 或者在 DNS 层拦这两组域名。

拦掉之后本仓的探测会把它们显示成"不可达"，正好可以用来验证规则生效了。

**别拦 `api.anthropic.com` 那一组** —— 那是业务主干，拦掉就没法用了。

---

## 五、为什么这件事值得关心

三个具体理由，不是"隐私"两个字：

1. **遥测和业务流量可能走不同的出口。** 业务流量走你精心挑的节点，
   遥测顺着默认规则从另一个地区出去，这在分流配置里非常常见 ——
   而这两条链路都带着能关联到你的信息。
2. **遥测落地区域是合规问题。** 数据发到美国的 Datadog，
   在某些组织的规定里需要显式说明。含糊过去不行，
   所以要有一张写得出站点代号的表。
3. **拦错了会静默降级。** 一刀切拦 `*.anthropic.com` 会连特性开关一起
   拦掉，表现是"某些功能莫名其妙没有了"，很难查。
   所以要分清哪条是遥测、哪条是控制面、哪条是业务。
