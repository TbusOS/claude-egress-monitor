"""Claude 三端的出网域名清单。

**这张表不是猜的**，每一行都有取证来源，见 `evidence` 字段：

- `cli-strings`   —— 从 Claude Code 单文件可执行里 `strings` 抽出（版本见 CLI_VERSION）
- `desktop-asar`  —— 从 `/Applications/Claude.app/Contents/Resources/app.asar` 抽出
- `observed`      —— 在本机 `lsof` 里真实抓到过的连接
- `docs`          —— Anthropic 公开文档写明的

新增一行之前先拿到证据，否则这张表会退化成"网上抄来的域名列表"，
而这类列表最大的问题是没人知道哪一条已经过期了。

复现命令写在 docs/01-endpoints.md，任何人可以自己跑一遍对账。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

CLI_VERSION_SAMPLED = "2.1.x"
DESKTOP_SAMPLED = "/Applications/Claude.app (2026-08-14)"

# 类别。UI 上按这个上色分组，docs 里按这个分节。
CAT_API = "api"              # 模型推理 / 会话，业务主干
CAT_AUTH = "auth"            # 登录、令牌
CAT_CONTROL = "control"      # 特性开关、配置下发
CAT_TELEMETRY = "telemetry"  # 遥测：日志、错误、指标
CAT_UPDATE = "update"        # 版本检查与下载
CAT_CONTENT = "content"      # 文档、静态资源
CAT_MCP = "mcp"              # MCP 代理


@dataclass(frozen=True)
class Endpoint:
    host: str
    category: str
    surfaces: tuple[str, ...]     # cli / desktop / web
    purpose: str                  # 中文一句话说清它干什么
    evidence: tuple[str, ...]
    # 探测方式：cf-trace 表示这个域名挂在 Cloudflare 上、有 /cdn-cgi/trace
    # 可以直接问出"它眼里的你"；tcp 表示只能量延迟不能问出口 IP。
    probe: str = "tcp"
    optional: bool = False        # 只在特定配置下才会出现
    note: Optional[str] = None
    # 对照组：**不属于 Claude**，只用来做出口/延迟的参照。
    # 所有"结论"类计算都必须把它排除掉 —— 否则对照组走默认路由这件
    # 完全正常的事，会被算成"你的 Claude 域名分流有问题"，
    # 而读者会照着这条假警报去改一份本来没问题的规则。
    baseline: bool = False


# ---------------------------------------------------------------- 主干

ENDPOINTS: tuple[Endpoint, ...] = (
    Endpoint(
        host="api.anthropic.com",
        category=CAT_API,
        surfaces=("cli", "desktop"),
        purpose="模型推理 API。Claude Code 的绝大部分流量在这里，"
                "对话内容、工具调用、文件片段都从这条链路出去。",
        evidence=("cli-strings", "desktop-asar", "observed", "docs"),
        probe="cf-trace",
        note="Anthropic 自有 AS399358，走 anycast。可用 ANTHROPIC_BASE_URL 改写。",
    ),
    Endpoint(
        host="claude.ai",
        category=CAT_API,
        surfaces=("cli", "desktop", "web"),
        purpose="网页端主站与会话接口；CLI 走 OAuth 登录时也打这里。",
        evidence=("cli-strings", "desktop-asar", "docs"),
        probe="cf-trace",
    ),
    Endpoint(
        host="code.claude.com",
        category=CAT_API,
        surfaces=("cli", "desktop"),
        purpose="Claude Code 侧的后端服务（云端会话、artifact 发布、"
                "远程触发等）。CLI 里出现频次仅次于 api.anthropic.com。",
        evidence=("cli-strings", "desktop-asar"),
        probe="cf-trace",
    ),
    Endpoint(
        host="platform.claude.com",
        category=CAT_API,
        surfaces=("cli", "desktop", "web"),
        purpose="平台/控制台接口（组织、用量、密钥管理）。",
        evidence=("cli-strings", "desktop-asar"),
        probe="cf-trace",
    ),
    Endpoint(
        host="www.anthropic.com",
        category=CAT_CONTENT,
        surfaces=("cli", "desktop", "web"),
        purpose="官网。CLI 拿它做可用性/延迟基准探测。",
        evidence=("cli-strings", "desktop-asar"),
        probe="cf-trace",
    ),

    # ---------------------------------------------------------- 控制面
    #
    # 注意：CLI 里能搜到 "statsig" 这个词（特性开关 SDK 的名字），
    # 但**搜不到 statsig.anthropic.com 这个主机名**，实测该域名也不解析。
    # 第一方的开关/分析入口是下面这组 a- 前缀域名。
    # 这条更正来自实测 —— 只按字符串猜域名就会写出一个不存在的条目。
    Endpoint(
        host="a-api.anthropic.com",
        category=CAT_CONTROL,
        surfaces=("cli", "desktop"),
        purpose="第一方分析 / 特性开关接口。挂在 Cloudflare 上，"
                "可以问出出口 IP。",
        evidence=("cli-strings", "desktop-asar"),
        probe="cf-trace",
    ),
    Endpoint(
        host="a-cdn.anthropic.com",
        category=CAT_CONTROL,
        surfaces=("cli", "desktop"),
        purpose="上面那组的静态配置下发端。",
        evidence=("cli-strings", "desktop-asar"),
        probe="tcp",
        note="实测解析到 Google Cloud 的负载均衡地址，没有 cdn-cgi/trace，"
             "所以这个域名只能量延迟，问不出出口 IP。",
    ),

    # ---------------------------------------------------------- 遥测
    Endpoint(
        host="http-intake.logs.us5.datadoghq.com",
        category=CAT_TELEMETRY,
        surfaces=("cli",),
        purpose="Claude Code 的日志遥测出口。CLI 里硬编码整条 URL"
                "（/api/v2/logs）与一个公开 client token，默认 15 秒攒一批发一次。",
        evidence=("cli-strings", "observed"),
        probe="tcp",
        note="Datadog US5 站点。关掉的办法见 docs/02-telemetry.md。",
    ),
    Endpoint(
        host="browser-intake-us5-datadoghq.com",
        category=CAT_TELEMETRY,
        surfaces=("desktop", "web"),
        purpose="Datadog 浏览器端 SDK（RUM / browser-logs）的 intake，"
                "网页端与桌面端的前端遥测走这里。",
        evidence=("cli-strings", "desktop-asar"),
        probe="tcp",
    ),
    Endpoint(
        host="o1158394.ingest.us.sentry.io",
        category=CAT_TELEMETRY,
        surfaces=("cli", "desktop"),
        purpose="Sentry 崩溃/异常上报，组织 id 1158394，US 区。",
        evidence=("cli-strings", "desktop-asar"),
        probe="tcp",
    ),

    # ---------------------------------------------------------- 更新
    Endpoint(
        host="downloads.claude.ai",
        category=CAT_UPDATE,
        surfaces=("cli", "desktop"),
        purpose="安装包 / 版本下载。",
        evidence=("cli-strings", "desktop-asar"),
        probe="tcp",
        note="实测走 Google Cloud，不是 Cloudflare，没有 trace 端点。",
    ),
    Endpoint(
        host="releases.claude.com",
        category=CAT_UPDATE,
        surfaces=("cli", "desktop"),
        purpose="版本元数据（自动更新检查读它）。",
        evidence=("cli-strings", "desktop-asar"),
        probe="cf-trace",
    ),

    # ---------------------------------------------------------- MCP
    Endpoint(
        host="mcp-proxy.anthropic.com",
        category=CAT_MCP,
        surfaces=("cli", "desktop"),
        purpose="托管 MCP 服务器的代理入口。装了远程 MCP 才有流量。",
        evidence=("cli-strings", "desktop-asar"),
        probe="cf-trace",
        optional=True,
    ),
    Endpoint(
        host="mcp.claude.com",
        category=CAT_MCP,
        surfaces=("cli", "desktop", "web"),
        purpose="Claude 侧 MCP 目录 / 连接器。",
        evidence=("cli-strings", "desktop-asar"),
        probe="cf-trace",
        optional=True,
    ),
)

# 只做延迟/出口基准，不属于 Claude —— 拿它当对照组：
# 如果 claude.ai 慢而这个不慢，问题在 Claude 那条链路而不是你的网络。
BASELINES: tuple[Endpoint, ...] = (
    Endpoint(
        host="1.1.1.1",
        category=CAT_CONTENT,
        surfaces=(),
        purpose="Cloudflare 公共 DNS 的 trace 端点，用作出口/延迟对照组。"
                "它和 claude.ai 都在 Cloudflare 上，所以两者出口不同"
                "只可能是你本地的分流规则造成的。",
        evidence=("docs",),
        probe="cf-trace",
        baseline=True,
    ),
)

ALL: tuple[Endpoint, ...] = ENDPOINTS + BASELINES

BY_HOST = {e.host: e for e in ALL}


def for_surface(surface: str) -> tuple[Endpoint, ...]:
    return tuple(e for e in ENDPOINTS if surface in e.surfaces)


def trace_capable(include_optional: bool = False) -> tuple[Endpoint, ...]:
    """能问出"目的地眼里的你"的那些域名。"""
    return tuple(
        e for e in ALL
        if e.probe == "cf-trace" and (include_optional or not e.optional)
    )


def classify_host(host: str) -> Optional[Endpoint]:
    """把观测到的域名归到清单里。未知域名返回 None，不猜。"""
    return BY_HOST.get(host)


def is_baseline(host: str) -> bool:
    e = BY_HOST.get(host)
    return bool(e and e.baseline)


# 「Claude 的业务出口」到底看哪些域名：主干 + 登录 + 官网，排除对照组、
# 排除遥测（遥测走哪儿是另一个问题，不该混进业务出口的结论里）。
CLAUDE_EGRESS_CATEGORIES = (CAT_API, CAT_AUTH, CAT_CONTENT, CAT_CONTROL)


def claude_egress_hosts(include_optional: bool = False) -> tuple[str, ...]:
    return tuple(
        e.host for e in ENDPOINTS
        if not e.baseline
        and e.probe == "cf-trace"
        and e.category in CLAUDE_EGRESS_CATEGORIES
        and (include_optional or not e.optional)
    )


__all__ = [
    "ALL",
    "BASELINES",
    "BY_HOST",
    "CAT_API",
    "CAT_AUTH",
    "CAT_CONTENT",
    "CAT_CONTROL",
    "CAT_MCP",
    "CAT_TELEMETRY",
    "CAT_UPDATE",
    "CLI_VERSION_SAMPLED",
    "DESKTOP_SAMPLED",
    "ENDPOINTS",
    "Endpoint",
    "classify_host",
    "for_surface",
    "trace_capable",
]
