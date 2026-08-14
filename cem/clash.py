"""可选：从本地分流器的控制接口读连接表，补上 lsof 看不到的那一半。

`lsof` 对走本机 HTTP 代理的进程只能看到"它连了代理"，真实目的地要问代理。
Clash / mihomo / Clash Verge / sing-box(clash-api 兼容) 都提供
`GET /connections`，返回的每条记录带着：

- `metadata.host` —— 真实目标域名（不是占位地址）
- `rule` / `rulePayload` —— 命中了哪条分流规则
- `chains` —— 走了哪个出口节点（这就是"从哪个地区出去"的直接答案）
- `upload` / `download` —— 这条连接的流量

**默认关闭**，因为它需要用户主动开 external-controller 并把地址交给本工具。
开启方法与安全注意事项写在 docs/03-routing.md。

密钥只从命令行参数或环境变量读，**不写进任何落盘文件**。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from .net import timed_get


@dataclass(frozen=True)
class ClashConn:
    id: str
    host: Optional[str]
    dest_ip: Optional[str]
    dest_port: Optional[str]
    process: Optional[str]
    rule: Optional[str]
    rule_payload: Optional[str]
    chains: tuple[str, ...]
    upload: int = 0
    download: int = 0
    network: Optional[str] = None

    @property
    def exit_node(self) -> Optional[str]:
        """出口节点名。chains 是倒序的，第一个是最终出口。"""
        return self.chains[0] if self.chains else None


def parse_connections(payload: str) -> tuple[ClashConn, ...]:
    """解析 /connections 的响应。纯函数。

    字段做了防御性读取：mihomo 和上游 clash 的字段在不同版本里有增减，
    缺字段应该降级成 None，而不是让整个采样挂掉。
    """
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return ()
    items = data.get("connections") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return ()
    out: list[ClashConn] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        meta = item.get("metadata") or {}
        chains = item.get("chains") or []
        out.append(ClashConn(
            id=str(item.get("id", "")),
            host=(meta.get("host") or None),
            dest_ip=(meta.get("destinationIP") or None),
            dest_port=(str(meta.get("destinationPort")) if meta.get("destinationPort") else None),
            process=(meta.get("processPath") or meta.get("process") or None),
            rule=(item.get("rule") or None),
            rule_payload=(item.get("rulePayload") or None),
            chains=tuple(str(c) for c in chains if c),
            upload=int(item.get("upload") or 0),
            download=int(item.get("download") or 0),
            network=(meta.get("network") or None),
        ))
    return tuple(out)


def fetch_connections(
    base_url: str,
    *,
    secret: Optional[str] = None,
    timeout: float = 4.0,
) -> tuple[tuple[ClashConn, ...], Optional[str]]:
    """返回 (连接列表, 错误说明)。控制接口不通不是致命错误，降级即可。"""
    url = base_url.rstrip("/") + "/connections"
    headers = {"Authorization": f"Bearer {secret}"} if secret else None
    res = timed_get(url, timeout=timeout, headers=headers)
    if not res.ok:
        return (), res.error or f"HTTP {res.status}"
    return parse_connections(res.body), None


def filter_claude(conns: tuple[ClashConn, ...],
                  hosts: tuple[str, ...]) -> tuple[ClashConn, ...]:
    """只留和 Claude 相关的连接。

    两条判据都用：域名在清单里，**或者**发起进程是 Claude。
    只用域名会漏掉未收录的域名；只用进程会漏掉浏览器里的 claude.ai
    （浏览器进程还连着几十个别的站）。
    """
    hostset = set(hosts)
    out = []
    for c in conns:
        host_hit = c.host in hostset or any(
            c.host and c.host.endswith("." + h) for h in hostset
        )
        proc = (c.process or "").lower()
        proc_hit = "claude" in proc or "/versions/" in proc
        if host_hit or proc_hit:
            out.append(c)
    return tuple(out)


def exit_summary(conns: tuple[ClashConn, ...]) -> dict[str, int]:
    """按出口节点统计连接数 —— 一眼看出流量主要从哪个节点出去。"""
    tally: dict[str, int] = {}
    for c in conns:
        node = c.exit_node or "(直连)"
        tally = {**tally, node: tally.get(node, 0) + 1}
    return dict(sorted(tally.items(), key=lambda kv: -kv[1]))


__all__ = [
    "ClashConn",
    "exit_summary",
    "fetch_connections",
    "filter_claude",
    "parse_connections",
]
