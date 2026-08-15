"""发现**内置清单里没有的**域名。

## 为什么必须有这一层

内置清单（`endpoints.py`）是人手维护的，而 Claude 每次版本更新都可能加新域名。
只靠清单，这个工具会随着时间越来越不准 —— 而且不准的方式最坏：
**它会安静地漏掉新域名**，看起来一切正常。

所以要有一条能自己发现新域名的路。

## 三条发现渠道，强弱不同

| 渠道 | 拿到什么 | 需要什么 | 时效 |
|---|---|---|---|
| **A. 扫本机装的 Claude Code / 桌面端** | 二进制里写死的域名 | 什么都不用 | 装上新版本**当场**就能发现 |
| **B. 分流器控制接口** | 真实连过的域名（`metadata.host`） | 用户开 external-controller | 连过才有 |
| **C. lsof + 已知反查表** | 只能确认已知域名"确实连过" | 什么都不用 | **发现不了新域名** |

A 是主力：它不需要连过、不需要任何配置，而且正好对上"跟着版本变"这件事。
C 单独用不够（反查表是拿已知清单建的，新域名进不来），但它能给出"哪些是
真的在用的"。

## 发现之后怎么处理：三档

不是所有扫出来的域名都能往外发 —— 用户可能配了私有 MCP 服务器，
那个主机名进了导出文件就是泄漏。所以按**父域**分三档：

- `known`   —— 已经在内置清单里
- `related` —— 不在清单里，但挂在已知的 Claude 相关父域下
                （`anthropic.com` / `claude.ai` / `claude.com` / 遥测那几家）
                **这就是要抓的新域名**，默认进导出
- `unknown` —— 父域也不认识。可能是新的、也可能是你自己的 MCP 服务器。
                **默认不进导出**，只报个数；要带上得显式加 `--include-unknown`

这一档划分是刻意保守的：漏掉一个新域名只是清单旧了，
而把用户的私有主机名写进一份准备外发的文件是不可逆的。
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Iterable, Optional

from . import endpoints as ep

# 已知属于 Claude 生态的父域。挂在这些下面的新域名默认可以外发。
#
# 遥测那三家（Datadog / Sentry）也在里面：它们不是 Anthropic 的，但
# "Claude 把数据发去哪"正是这份清单最该说清楚的事之一。
CLAUDE_PARENTS = (
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "datadoghq.com",
    "datadoghq.eu",
    "sentry.io",
    "ingest.sentry.io",
    "statsig.com",
)

KIND_KNOWN = "known"
KIND_RELATED = "related"
KIND_UNKNOWN = "unknown"

# 从二进制里抓域名。要求至少两段、TLD 至少两个字母。
# 刻意**不**接受纯数字结尾（那多半是版本号被误认成域名）。
DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}[a-z]{2,24})\b",
    re.I)

# 明显不是出网目标的：本机、示例、文档保留、包名。
NOISE_SUFFIXES = (".local", ".localhost", ".example", ".test", ".invalid",
                  ".internal", ".arpa", ".json", ".js", ".ts", ".md",
                  ".png", ".svg", ".css", ".map", ".node", ".wasm", ".py")
NOISE_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0"})


def normalise(host: str) -> Optional[str]:
    """规整一个候选域名；不像域名就返回 None。"""
    if not host:
        return None
    host = host.strip().strip(".").lower()
    if not host or " " in host or host in NOISE_HOSTS:
        return None
    if host.endswith(NOISE_SUFFIXES):
        return None
    if len(host) > 253 or "." not in host:
        return None
    # 全是数字的段（IP 或版本号）不算域名
    if all(part.isdigit() for part in host.split(".")):
        return None
    return host


def parent_of(host: str) -> Optional[str]:
    """这个域名挂在哪个已知的 Claude 父域下。"""
    for parent in CLAUDE_PARENTS:
        if host == parent or host.endswith("." + parent):
            return parent
    return None


def classify(host: str) -> str:
    """三档分类。见模块开头的说明。纯函数。"""
    if ep.classify_host(host) is not None:
        return KIND_KNOWN
    return KIND_RELATED if parent_of(host) else KIND_UNKNOWN


def extract_domains(blob: str) -> tuple[str, ...]:
    """从一段文本（二进制里的明文字符串）里抽域名。纯函数。

    只保留挂在已知 Claude 父域下的 —— 一个几百 MB 的 JS bundle 里有几千个
    域名（依赖包的主页、许可证链接、示例），全抓出来只会得到噪声。
    """
    found: dict[str, None] = {}
    for m in DOMAIN_RE.finditer(blob):
        host = normalise(m.group(1))
        if host and parent_of(host):
            found[host] = None
    return tuple(sorted(found))


def from_connections(conns: Iterable) -> tuple[str, ...]:
    """从实时连接里取域名。纯函数。

    `Connection.host` 可能是「a、b」这种多域名形式（anycast 地址反查）。
    """
    found: dict[str, None] = {}
    for c in conns or ():
        raw = getattr(c, "host", None)
        if not raw:
            continue
        for part in str(raw).split("、"):
            host = normalise(part)
            if host:
                found[host] = None
    return tuple(sorted(found))


# ─────────────────────────────────────────────────────── 落盘

RECORD_VERSION = 1


class DiscoveryStore:
    """发现到的域名。一个 JSON 文件，线程安全。

    为什么要落盘：用户说"监控了一段时间，发现访问了这些域名" ——
    那就必须跨重启累积，只放内存里等于每次重启从头再来。

    文件在 `data/` 下，已经在 .gitignore 里。里面**只有域名和时间戳**，
    没有 IP、没有端口 —— 万一有人手滑提交了，损失也是有限的。
    """

    def __init__(self, path: Optional[Path]):
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        self._loaded = False

    @property
    def enabled(self) -> bool:
        return self._path is not None

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path or not self._path.is_file():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        hosts = raw.get("hosts") if isinstance(raw, dict) else None
        if isinstance(hosts, dict):
            self._data = {k: v for k, v in hosts.items()
                          if isinstance(v, dict) and normalise(k)}

    def _flush(self) -> None:
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"v": RECORD_VERSION, "hosts": self._data}
            self._path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=1),
                encoding="utf-8")
        except OSError:
            pass          # 记不下来不该让采样失败

    def record(self, hosts: Iterable[str], *, source: str,
               now: Optional[float] = None) -> int:
        """记一批域名，返回其中**第一次见到**的个数。"""
        ts = now if now is not None else time.time()
        fresh = 0
        with self._lock:
            self._load()
            for raw in hosts:
                host = normalise(raw)
                if not host:
                    continue
                entry = self._data.get(host)
                if entry is None:
                    self._data[host] = {
                        "first": round(ts, 3), "last": round(ts, 3),
                        "hits": 1, "sources": [source],
                        "kind": classify(host),
                    }
                    fresh += 1
                else:
                    entry["last"] = round(ts, 3)
                    entry["hits"] = int(entry.get("hits", 0)) + 1
                    srcs = entry.setdefault("sources", [])
                    if source not in srcs:
                        srcs.append(source)
                    # 分类可能变：清单更新之后，原来的 related 变成 known
                    entry["kind"] = classify(host)
            if fresh or self._data:
                self._flush()
        return fresh

    def all(self) -> dict[str, dict]:
        with self._lock:
            self._load()
            return {k: dict(v) for k, v in self._data.items()}

    def new_domains(self) -> dict[str, dict]:
        """只要清单里**没有**的（related + unknown）。"""
        return {k: v for k, v in self.all().items()
                if v.get("kind") != KIND_KNOWN}

    def clear(self) -> None:
        with self._lock:
            self._data = {}
            self._loaded = True
            self._flush()


# ─────────────────────────────────────────────────────── 扫本机安装

def scan_installed(*, cli_binary: Optional[Path] = None,
                   desktop_asar: Optional[Path] = None,
                   max_bytes: int = 400 * 1024 * 1024) -> dict[str, tuple[str, ...]]:
    """扫本机装的 Claude Code / 桌面端，抽出里面写死的 Claude 相关域名。

    **只读文件，不解密、不注入、不修改任何东西** —— 和 `telemetry.py`
    是同一套做法，边界说明见那个模块。

    返回 `{来源: (域名, …)}`。读不到就返回空，不抛异常。
    """
    from .telemetry import latest_binary

    out: dict[str, tuple[str, ...]] = {}

    targets: list[tuple[str, Optional[Path]]] = [
        ("cli-strings", cli_binary or latest_binary()),
        ("desktop-asar", desktop_asar or _desktop_asar()),
    ]
    for source, path in targets:
        if not path or not Path(path).is_file():
            continue
        try:
            size = Path(path).stat().st_size
            if size > max_bytes:
                continue
            blob = Path(path).read_bytes().decode("utf-8", errors="ignore")
        except OSError:
            continue
        hosts = extract_domains(blob)
        if hosts:
            out[source] = hosts
    return out


def _desktop_asar() -> Optional[Path]:
    p = Path("/Applications/Claude.app/Contents/Resources/app.asar")
    return p if p.is_file() else None


__all__ = [
    "CLAUDE_PARENTS",
    "DiscoveryStore",
    "KIND_KNOWN",
    "KIND_RELATED",
    "KIND_UNKNOWN",
    "classify",
    "extract_domains",
    "from_connections",
    "normalise",
    "parent_of",
    "scan_installed",
]
