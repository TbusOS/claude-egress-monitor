"""三个入口各自走哪条网络路径 —— 这是整个工具的核心概念。

同一台机器上，Claude Code、Claude 桌面端、浏览器里的 claude.ai
**并不共用一条出网路径**，因为它们读的代理配置不是同一份：

| 入口 | 读什么代理配置 | 结果 |
|---|---|---|
| Claude Code（CLI，Node 运行时） | 只认 `HTTPS_PROXY` / `HTTP_PROXY` 环境变量；没设就直连 | 直连时若本机开了 TUN/透明代理，由**分流规则按 IP** 决定出口 |
| Claude 桌面端（Electron / Chromium） | 认 **macOS 系统代理**设置 | 由分流规则**按域名**决定出口 |
| 浏览器里的 claude.ai | 认系统代理（除非装了代理插件自己接管） | 同上，但插件可以单独改写 |

"按 IP 分流"和"按域名分流"是两套不同的匹配过程，命中的规则可以不同，
所以**同一个域名从 CLI 出去和从桌面端出去，落地国家可以不一样**。
这个工具做的事就是把这件事量出来，而不是让人凭感觉猜。

这里为每个入口造一条**等价探测路径**：用和该入口相同的代理配置去问
`cdn-cgi/trace`，于是"目的地眼里的你"就是该入口真实的出口。
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

SURFACE_CLI = "cli"
SURFACE_DESKTOP = "desktop"
SURFACE_WEB = "web"

SURFACE_LABELS = {
    SURFACE_CLI: "Claude Code",
    SURFACE_DESKTOP: "Claude 桌面端",
    SURFACE_WEB: "浏览器 claude.ai",
}


@dataclass(frozen=True)
class Path:
    """一条可探测的网络路径。"""

    id: str
    label: str
    surfaces: tuple[str, ...]
    proxy: Optional[tuple[str, int]]   # None = 直连
    source: str                        # 这条路径的配置是从哪读出来的
    detail: str


def _parse_proxy_url(raw: str) -> Optional[tuple[str, int]]:
    """把 `http://host:port` / `host:port` 解析成 (host, port)。"""
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        return None
    return (parsed.hostname, parsed.port or 8080)


def env_proxy() -> Optional[tuple[str, int]]:
    """Claude Code 会用的代理：只看环境变量，大小写都认。"""
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        got = _parse_proxy_url(os.environ.get(key, ""))
        if got:
            return got
    return None


# 键必须以字母开头：`scutil --proxy` 的输出里嵌着数组，
# 数组元素长成 `0 : 127.0.0.1`，用 \w+ 会把下标 0、1 当成配置项收进表里。
_SCUTIL_LINE = re.compile(r"^\s*([A-Za-z]\w*)\s*:\s*(.+?)\s*$")


def parse_scutil_proxy(text: str) -> dict[str, str]:
    """解析 `scutil --proxy` 的输出。纯函数，便于测试。"""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _SCUTIL_LINE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def system_proxy(text: Optional[str] = None) -> Optional[tuple[str, int]]:
    """macOS 系统代理 —— 桌面端和浏览器读的就是这份。

    只认 HTTPS 那一组：Claude 的流量全是 https，HTTP 那一组不影响它。
    PAC（自动配置脚本）这里**不解析**，因为 PAC 的结果依赖目标 URL，
    没有"一个"代理可言；检测到 PAC 会在 detail 里说明并退回直连。
    """
    if text is None:
        try:
            text = subprocess.run(
                ["scutil", "--proxy"], capture_output=True, text=True, timeout=5,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return None
    conf = parse_scutil_proxy(text or "")
    if conf.get("HTTPSEnable") == "1" and conf.get("HTTPSProxy"):
        try:
            return (conf["HTTPSProxy"], int(conf.get("HTTPSPort", "0")) or 8080)
        except ValueError:
            return None
    return None


def system_proxy_is_pac(text: Optional[str] = None) -> bool:
    if text is None:
        try:
            text = subprocess.run(
                ["scutil", "--proxy"], capture_output=True, text=True, timeout=5,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return False
    return parse_scutil_proxy(text or "").get("ProxyAutoConfigEnable") == "1"


def discover() -> tuple[Path, ...]:
    """按当前这台机器的真实配置，造出该探测哪几条路径。

    路径是**发现**出来的，不是写死的：机器上没开系统代理时，
    桌面端和 CLI 其实同路，这时候造两条一样的路径只是浪费探测次数
    —— 但仍然分别标出来，因为读者需要看到"这两个入口此刻是同路的"这个结论。
    """
    ev = env_proxy()
    sysp = system_proxy()
    pac = system_proxy_is_pac()

    cli = Path(
        id="cli",
        label="Claude Code",
        surfaces=(SURFACE_CLI,),
        proxy=ev,
        source="HTTPS_PROXY / HTTP_PROXY 环境变量" if ev else "无代理环境变量 → 直连",
        detail=(
            f"CLI 会把流量发给 {ev[0]}:{ev[1]}。" if ev else
            "CLI 直连。若本机开着 TUN / 透明代理，出口由分流规则按 IP 匹配决定；"
            "没有的话就是本地宽带出口。"
        ),
    )

    if pac:
        desktop_detail = ("系统代理用的是 PAC 自动配置脚本 —— 代理选择依赖具体 URL，"
                          "没有单一代理可探测，这里退回直连，结论仅供参考。")
    elif sysp:
        desktop_detail = f"桌面端 / 浏览器把流量发给系统代理 {sysp[0]}:{sysp[1]}。"
    else:
        desktop_detail = "系统代理未开启，桌面端和浏览器直连，与 CLI 同路。"

    desktop = Path(
        id="desktop",
        label="Claude 桌面端",
        surfaces=(SURFACE_DESKTOP, SURFACE_WEB),
        proxy=sysp,
        source="macOS 系统代理（scutil --proxy）",
        detail=desktop_detail,
    )

    baseline = Path(
        id="baseline",
        label="对照组（直连）",
        surfaces=(),
        proxy=None,
        source="强制不用任何代理",
        detail="不带任何代理配置的直连基准，用来判断差异是代理造成的还是网络本身。",
    )

    paths = [cli, desktop]
    if ev is not None:
        # CLI 走了代理，直连基准就有独立价值了。
        paths.append(baseline)
    return tuple(paths)


def path_for_surface(paths: tuple[Path, ...], surface: str) -> Optional[Path]:
    for p in paths:
        if surface in p.surfaces:
            return p
    return None


def same_route(a: Path, b: Path) -> bool:
    return a.proxy == b.proxy


__all__ = [
    "Path",
    "SURFACE_CLI",
    "SURFACE_DESKTOP",
    "SURFACE_LABELS",
    "SURFACE_WEB",
    "discover",
    "env_proxy",
    "parse_scutil_proxy",
    "path_for_surface",
    "same_route",
    "system_proxy",
    "system_proxy_is_pac",
]
