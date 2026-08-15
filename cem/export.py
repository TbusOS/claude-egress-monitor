"""导出「Claude 会访问哪些域名」的**全集** —— 一份可以直接发给别人的清单。

## 全集 = 三个来源的并集，去重

| 来源 | 拿到什么 | 时效 |
|---|---|---|
| **内置清单** `endpoints.py` | 人工整理过、每条都写了用途 | 人手维护，会过期 |
| **扫本机安装** `discover.scan_installed()` | 二进制里写死的域名 | 装上新版本当场就能发现 |
| **实时观测** lsof / 分流器 | 真的连过的域名 | 连过才有 |

三者去重后合成一张表。**同一个域名只出现一次**，把它的全部证据并在一行上。

## 每一行都带证据等级，不能一律说成"Claude 会访问"

这是这个模块最要紧的一条。扫出来的东西里混着三种完全不同的情况：

- `preview.claude.ai` —— 大概率是真的会连
- `docs.anthropic.com` —— 多半只是界面里的一个链接，你点了才会打开
- `gcal.mcp.claude.com` —— 只有开了那个连接器才用得上
- `api-staging.anthropic.com` —— 内部环境，正常用户可能永远不会连

**这三种从二进制里是分不出来的。** 所以这里不猜：把证据摊开写清楚，
让读者自己判断，并在文件里明说"出现在二进制里不等于每次都会连"。

分两档：

- **确证** —— 本机真的抓到过连接（`observed`）
- **代码里写着** —— 只在二进制/清单里出现过，会在某个场景用到

## 白名单，不是黑名单

这份文件的用途就是给别人看，所以**逐个列出允许出现的字段**，其余一律不进。

允许：域名、类别、用途、入口、证据、是否观测到、首次/最近见到的日期。

不允许（写在这儿是为了以后有人想加时先看到）：出口 IP、代理端口、
本机地址、进程 PID / 进程名、ASN / 归属 / 城市、延迟数字（p50 能反推
你的大致位置和链路质量，是弱指纹）。

父域不认识的域名（可能是你自己的私有 MCP 服务器）**默认不进导出**，
只报个数 —— 见 `discover.py` 的三档说明。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from . import discover
from . import endpoints as ep

REPO_URL = "https://github.com/TbusOS/claude-egress-monitor"

# 证据标签 → 人话。顺序就是可信度从高到低。
EVIDENCE_LABELS = {
    "observed": "本机真的抓到过连接",
    "router": "分流器记录到真实连接",
    "docs": "官方文档写了",
    "cli-strings": "Claude Code 二进制里出现",
    "desktop-asar": "桌面端 app.asar 里出现",
    "scan-cli": "本机扫描：CLI 二进制里出现",
    "scan-desktop": "本机扫描：桌面端里出现",
}
STRONG_EVIDENCE = ("observed", "router")

SURFACE_LABELS = {"cli": "Claude Code", "desktop": "桌面端", "web": "浏览器"}

CATEGORY_LABELS = {
    ep.CAT_API: "模型 API / 会话",
    ep.CAT_AUTH: "登录鉴权",
    ep.CAT_CONTROL: "特性开关 / 配置",
    ep.CAT_TELEMETRY: "遥测上报",
    ep.CAT_UPDATE: "版本更新",
    ep.CAT_CONTENT: "文档 / 静态资源",
    ep.CAT_MCP: "MCP 代理",
}
CAT_DISCOVERED = "discovered"
CATEGORY_LABELS[CAT_DISCOVERED] = "本机发现（不在内置清单里）"

CATEGORY_ORDER = (ep.CAT_API, ep.CAT_AUTH, ep.CAT_CONTROL, ep.CAT_CONTENT,
                  ep.CAT_UPDATE, ep.CAT_TELEMETRY, ep.CAT_MCP, CAT_DISCOVERED)

PRIVACY_NOTE = (
    "这份清单只有域名和它们的用途。不含任何本机信息：没有出口 IP、"
    "没有代理端口、没有进程 PID、没有 ASN / 归属 / 城市、也没有延迟数字。"
    "可以直接发给别人。"
)

READING_NOTE = (
    "**「代码里写着」不等于「每次都会连」。** 从二进制里抽出来的域名里混着三种"
    "情况：真正的运行时目标、界面上的链接（点了才打开）、以及只在特定功能开启后"
    "才用到的（MCP 连接器、内部环境）。这三种从二进制里分不出来，所以这里不猜 ——"
    "证据摊开写，你自己判断。只有标了「确证」的才是本机真的抓到过连接。"
)


@dataclass(frozen=True)
class DomainRow:
    host: str
    category: str
    purpose: Optional[str]
    surfaces: tuple[str, ...]
    evidence: tuple[str, ...]
    optional: bool
    note: Optional[str]
    in_inventory: bool
    observed_rounds: int
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    @property
    def observed(self) -> bool:
        return self.observed_rounds > 0 or any(
            e in self.evidence for e in STRONG_EVIDENCE)

    @property
    def confidence(self) -> str:
        return "确证" if self.observed else "代码里写着"

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)

    @property
    def surface_label(self) -> str:
        if not self.surfaces:
            return "—"
        return " / ".join(SURFACE_LABELS.get(s, s) for s in self.surfaces)


@dataclass(frozen=True)
class ExportDoc:
    rows: tuple[DomainRow, ...]
    generated_at: float
    cli_version: str
    desktop_sampled: str
    rounds: int
    window_hours: Optional[float]
    unattributed: int
    withheld: tuple[str, ...] = field(default=())   # 父域不认识、默认不导出的

    @property
    def observed_count(self) -> int:
        return sum(1 for r in self.rows if r.observed)

    @property
    def discovered_count(self) -> int:
        return sum(1 for r in self.rows if not r.in_inventory)


# ─────────────────────────────────────────────────────── 汇总

def observed_hosts(samples: Iterable) -> tuple[dict[str, int], int]:
    """数每个域名在多少轮里被观测到。纯函数。

    返回 `({域名: 轮数}, 归不到任何域名的连接数)`。
    """
    counts: dict[str, int] = {}
    unattributed = 0
    for sample in samples:
        seen: set[str] = set()
        for conn in getattr(sample, "connections", ()) or ():
            raw = getattr(conn, "host", None)
            if not raw:
                # 走本机代理的连接看不到目的地。那是已知的观测盲区，
                # 不是"归不到" —— 界面上单独讲过这一条。
                if getattr(conn, "kind", None) != "local-proxy":
                    unattributed += 1
                continue
            for part in str(raw).split("、"):
                host = discover.normalise(part)
                if host:
                    seen.add(host)
        for host in seen:
            counts[host] = counts.get(host, 0) + 1
    return counts, unattributed


def build(samples: Iterable = (), *, discovered: Optional[dict] = None,
          include_optional: bool = True, include_unknown: bool = False,
          now: Optional[float] = None) -> ExportDoc:
    """把三个来源合成一张去重的表。

    `discovered` 是 `DiscoveryStore.all()` 的形状：`{域名: {first,last,hits,sources,kind}}`。

    对照组（`baseline`）不进导出 —— 这份文件的标题是"Claude 会访问哪些域名"，
    把 1.1.1.1 写进去是错的。
    """
    samples = tuple(samples)
    counts, unattributed = observed_hosts(samples)
    discovered = discovered or {}

    rows: dict[str, DomainRow] = {}

    # ① 内置清单
    for e in ep.ENDPOINTS:
        if e.baseline:
            continue
        if e.optional and not include_optional:
            continue
        rows[e.host] = DomainRow(
            host=e.host, category=e.category, purpose=e.purpose,
            surfaces=tuple(e.surfaces), evidence=tuple(e.evidence),
            optional=e.optional, note=e.note, in_inventory=True,
            observed_rounds=counts.get(e.host, 0),
        )

    # ② 本机发现的（扫描 + 分流器）。清单里已有的把证据并上去，没有的新起一行。
    withheld: list[str] = []
    for host, meta in sorted(discovered.items()):
        kind = meta.get("kind") or discover.classify(host)
        if kind == discover.KIND_UNKNOWN and not include_unknown:
            withheld.append(host)
            continue
        sources = tuple(meta.get("sources") or ())
        exist = rows.get(host)
        if exist is not None:
            merged = tuple(dict.fromkeys(exist.evidence + sources))
            rows[host] = DomainRow(
                host=exist.host, category=exist.category, purpose=exist.purpose,
                surfaces=exist.surfaces, evidence=merged, optional=exist.optional,
                note=exist.note, in_inventory=True,
                observed_rounds=exist.observed_rounds,
                first_seen=meta.get("first"), last_seen=meta.get("last"),
            )
            continue
        rows[host] = DomainRow(
            host=host, category=CAT_DISCOVERED, purpose=None, surfaces=(),
            evidence=sources, optional=False, note=None, in_inventory=False,
            observed_rounds=counts.get(host, 0),
            first_seen=meta.get("first"), last_seen=meta.get("last"),
        )

    # ③ 观测到但既不在清单也不在发现库里的（理论上不该有，兜底）
    for host, n in counts.items():
        if host in rows:
            continue
        if discover.classify(host) == discover.KIND_UNKNOWN and not include_unknown:
            withheld.append(host)
            continue
        rows[host] = DomainRow(
            host=host, category=CAT_DISCOVERED, purpose=None, surfaces=(),
            evidence=("observed",), optional=False, note=None,
            in_inventory=False, observed_rounds=n,
        )

    order = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    ordered = sorted(rows.values(),
                     key=lambda r: (order.get(r.category, 99), r.host))

    window: Optional[float] = None
    stamps = [s.ts for s in samples if getattr(s, "ts", None) is not None]
    if len(stamps) >= 2:
        window = round((max(stamps) - min(stamps)) / 3600.0, 2)

    return ExportDoc(
        rows=tuple(ordered),
        generated_at=now if now is not None else time.time(),
        cli_version=ep.CLI_VERSION_SAMPLED,
        desktop_sampled=ep.DESKTOP_SAMPLED,
        rounds=len(samples), window_hours=window,
        unattributed=unattributed,
        withheld=tuple(sorted(set(withheld))),
    )


# ─────────────────────────────────────────────────────── 三种格式

def _stamp(ts: Optional[float], fmt: str = "%Y-%m-%d %H:%M") -> str:
    if not ts:
        return "—"
    return time.strftime(fmt, time.localtime(ts))


def _coverage(doc: ExportDoc) -> list[str]:
    out = []
    if doc.rounds:
        win = f"，跨度约 {doc.window_hours} 小时" if doc.window_hours else ""
        out.append(f"**本机观测**：{doc.rounds} 轮采样{win}，"
                   f"{doc.observed_count} 个域名被真的抓到过连接。")
    else:
        out.append("**本机观测**：这一份没有观测数据 —— "
                   "起界面开着监控一段时间再导，「确证」那一列才会有内容。")
    if doc.discovered_count:
        out.append(f"**本机发现**：{doc.discovered_count} 个域名不在内置清单里，"
                   f"是从这台机器上装的 Claude 里扫出来的 —— "
                   f"清单是人手维护的，Claude 一更新就会漏，所以每次导出都重新扫一遍。")
    if doc.unattributed:
        out.append(f"另有 {doc.unattributed} 条连接归不到任何域名"
                   f"（走本机代理时目的地不可见）。")
    if doc.withheld:
        out.append(f"**有 {len(doc.withheld)} 个域名被扣下没有导出**："
                   f"它们的父域不在已知的 Claude 相关域里，可能是你自己配的 "
                   f"MCP 服务器之类。要带上请加 `--include-unknown`，"
                   f"**加之前先自己看一眼那是什么**。")
    return out


def to_markdown(doc: ExportDoc) -> str:
    out: list[str] = ["# Claude 会访问哪些域名", ""]
    out.append(f"由 [claude-egress-monitor]({REPO_URL}) 于 "
               f"{_stamp(doc.generated_at)} 导出，共 {len(doc.rows)} 个域名。")
    out += ["", f"> {PRIVACY_NOTE}", ""]
    out.append(f"**清单基线**：Claude Code {doc.cli_version} · "
               f"桌面端 {doc.desktop_sampled}")
    out.append("")
    out += _coverage(doc)
    out += ["", READING_NOTE, ""]

    for cat in CATEGORY_ORDER:
        group = [r for r in doc.rows if r.category == cat]
        if not group:
            continue
        out.append(f"## {CATEGORY_LABELS.get(cat, cat)}")
        out.append("")
        if cat == CAT_DISCOVERED:
            out.append("这些不在内置清单里，所以没有人工写的用途说明 —— "
                       "它们是从本机装的 Claude 里扫出来的。")
            out.append("")
            out.append("| 域名 | 把握 | 证据 | 首次见到 |")
            out.append("|---|---|---|---|")
            for r in group:
                ev = "、".join(EVIDENCE_LABELS.get(e, e) for e in r.evidence) or "—"
                out.append(f"| `{r.host}` | {r.confidence} | {ev} | "
                           f"{_stamp(r.first_seen, '%Y-%m-%d')} |")
        else:
            out.append("| 域名 | 用途 | 入口 | 把握 |")
            out.append("|---|---|---|---|")
            for r in group:
                purpose = (r.purpose or "—").replace("|", "\\|")
                if r.optional:
                    purpose += "（可选，特定配置下才出现）"
                mark = (f"确证（{r.observed_rounds} 轮）"
                        if r.observed_rounds else r.confidence)
                out.append(f"| `{r.host}` | {purpose} | {r.surface_label} | {mark} |")
        out.append("")

    out += ["## 证据是什么意思", ""]
    for key, label in EVIDENCE_LABELS.items():
        hosts = [r.host for r in doc.rows if key in r.evidence]
        if hosts:
            out.append(f"- **{key}** —— {label}（{len(hosts)} 个域名）")
    out += ["", "复现方法写在仓库的 `docs/01-endpoints.md`，可以自己跑一遍对账。", ""]

    out += ["## 怎么用这份清单", "",
            "- **写分流规则**：用 `--format text` 导出纯域名列表，"
            "直接喂给 Clash / sing-box 的 rule-provider",
            "- **查自己的机器**：`python3 -m cem probe` 会对这些域名逐个探测，"
            "告诉你每个从哪个 IP、哪个地区出去",
            "- **关掉遥测**：遥测那一类是发往第三方（Datadog / Sentry）的，"
            "办法见仓库的 `docs/02-telemetry.md`",
            "- **自己重新导一份**：`python3 -m cem export --format md -o 域名清单.md`",
            ""]
    return "\n".join(out)


def to_text(doc: ExportDoc) -> str:
    """一行一个域名，`#` 开头是注释。直接能喂给分流规则。"""
    out = ["# Claude 会访问的域名清单（全集，已去重）",
           f"# 由 claude-egress-monitor 于 {_stamp(doc.generated_at)} 导出，"
           f"共 {len(doc.rows)} 个",
           f"# {REPO_URL}",
           "# 只含域名，不含任何本机信息。",
           "# 注意：出现在这里不等于每次都会连 —— 部分域名只在特定功能开启后才用到。",
           ""]
    for cat in CATEGORY_ORDER:
        group = [r for r in doc.rows if r.category == cat]
        if not group:
            continue
        out.append(f"# ── {CATEGORY_LABELS.get(cat, cat)}")
        for r in group:
            tags = []
            if r.optional:
                tags.append("可选")
            if r.observed:
                tags.append("已观测")
            suffix = ("    # " + "、".join(tags)) if tags else ""
            out.append(f"{r.host}{suffix}")
        out.append("")
    return "\n".join(out)


def to_json(doc: ExportDoc) -> str:
    payload = {
        "schema": "claude-egress-monitor/domains@2",
        "generated_at": round(doc.generated_at, 3),
        "baseline": {"cli": doc.cli_version, "desktop": doc.desktop_sampled},
        "counts": {
            "total": len(doc.rows),
            "observed": doc.observed_count,
            "discovered_beyond_inventory": doc.discovered_count,
            "withheld_unknown_parent": len(doc.withheld),
        },
        "observation": {
            "rounds": doc.rounds,
            "window_hours": doc.window_hours,
            "unattributed_connections": doc.unattributed,
        },
        "privacy": PRIVACY_NOTE,
        "reading": ("出现在二进制里不等于每次都会连；只有 observed=true "
                    "才是本机真的抓到过连接。"),
        "domains": [
            {
                "host": r.host,
                "category": r.category,
                "category_label": r.category_label,
                "purpose": r.purpose,
                "surfaces": list(r.surfaces),
                "evidence": list(r.evidence),
                "optional": r.optional,
                "note": r.note,
                "in_inventory": r.in_inventory,
                "observed": r.observed,
                "observed_rounds": r.observed_rounds,
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
            }
            for r in doc.rows
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


FORMATS = {"markdown": to_markdown, "text": to_text, "json": to_json}
EXTENSIONS = {"markdown": ".md", "text": ".txt", "json": ".json"}
MEDIA_TYPES = {
    "markdown": "text/markdown; charset=utf-8",
    "text": "text/plain; charset=utf-8",
    "json": "application/json; charset=utf-8",
}


def render(doc: ExportDoc, fmt: str = "markdown") -> str:
    if fmt not in FORMATS:
        raise ValueError(f"不认识的格式：{fmt}（可选 {', '.join(sorted(FORMATS))}）")
    return FORMATS[fmt](doc)


__all__ = [
    "CATEGORY_LABELS",
    "CAT_DISCOVERED",
    "DomainRow",
    "EVIDENCE_LABELS",
    "EXTENSIONS",
    "ExportDoc",
    "FORMATS",
    "MEDIA_TYPES",
    "PRIVACY_NOTE",
    "READING_NOTE",
    "build",
    "observed_hosts",
    "render",
    "to_json",
    "to_markdown",
    "to_text",
]
