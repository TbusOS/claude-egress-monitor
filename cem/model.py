"""不可变数据模型。

所有采样结果都是 frozen dataclass —— 采完就不再改，需要变化时构造新对象。
理由：采样结果会同时被后台线程写、被 HTTP 线程读、被 JSONL 落盘，
可变对象在这三个地方之间传递必然出竞态。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any, Optional


def _clean(obj: Any) -> Any:
    """把 dataclass 树转成可 JSON 序列化的普通结构。"""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _clean(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    return obj


@dataclass(frozen=True)
class Timing:
    """一次 HTTPS 请求的分段耗时，单位毫秒。

    分段而不是只给总时长：总时长慢有四种完全不同的原因，
    修的办法也完全不同（换 DNS / 换出口节点 / 换协议 / 等服务端）。
    """

    dns_ms: Optional[float] = None
    tcp_ms: Optional[float] = None
    tls_ms: Optional[float] = None
    ttfb_ms: Optional[float] = None
    total_ms: Optional[float] = None


@dataclass(frozen=True)
class TraceView:
    """一次 `cdn-cgi/trace` 采样 —— "目的地眼里的你"。

    egress_ip 是 Cloudflare 那一侧真实看到的源地址，不是本机接口地址。
    这是全仓最重要的一个字段：决定风控看到你在哪的就是它。
    """

    target: str                      # 探测的域名，例如 claude.ai
    path: str                        # 走的路径 id，见 paths.py
    ok: bool = False
    egress_ip: Optional[str] = None  # trace 里的 ip=
    country: Optional[str] = None    # loc=
    colo: Optional[str] = None       # colo=，Cloudflare 边缘机房三字码
    http: Optional[str] = None       # http=
    tls: Optional[str] = None        # tls=
    warp: Optional[str] = None       # warp=
    peer_ip: Optional[str] = None    # 本机这条 TCP 实际连到的对端地址
    timing: Timing = field(default_factory=Timing)
    error: Optional[str] = None

    @property
    def is_ipv6(self) -> bool:
        return bool(self.egress_ip) and ":" in (self.egress_ip or "")


@dataclass(frozen=True)
class AsnInfo:
    """一个 IP 的归属。source 记清是哪儿查来的，便于判断可信度。"""

    ip: str
    asn: Optional[str] = None
    prefix: Optional[str] = None
    country: Optional[str] = None
    org: Optional[str] = None
    city: Optional[str] = None
    anycast: Optional[bool] = None
    source: Optional[str] = None


@dataclass(frozen=True)
class ResolveView:
    """一个域名的解析真相对照。

    system 是本机 getaddrinfo 的结果，doh 是公网权威链路的结果。
    两者不一致就说明本机 DNS 被改写了（代理 fake-ip、split-DNS、hosts）——
    这是"我以为流量走 A、其实走 B"最常见的起点。
    """

    host: str
    system: tuple[str, ...] = ()
    doh: tuple[str, ...] = ()
    doh_source: Optional[str] = None
    resolver: Optional[str] = None    # macOS 对这个域名会用的 nameserver
    kind: str = "unknown"             # real / fake-ip / split-dns / mismatch / error
    note: Optional[str] = None


@dataclass(frozen=True)
class Connection:
    """一条实时连接（lsof 或 Clash API 观测到的）。"""

    pid: int
    command: str
    surface: str                     # cli / desktop / web / other
    local: str
    remote_ip: str
    remote_port: int
    kind: str                        # real / fake-ip / local-proxy / private
    host: Optional[str] = None       # 能反查出域名时填
    service: Optional[str] = None    # 归到哪个服务，见 endpoints.py
    asn: Optional[AsnInfo] = None
    source: str = "lsof"


@dataclass(frozen=True)
class Sample:
    """一轮完整采样。UI 上看到的每一个数字都来自这里。"""

    ts: float
    seq: int
    traces: tuple[TraceView, ...] = ()
    resolves: tuple[ResolveView, ...] = ()
    connections: tuple[Connection, ...] = ()
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return _clean(self)


__all__ = [
    "AsnInfo",
    "Connection",
    "ResolveView",
    "Sample",
    "Timing",
    "TraceView",
    "replace",
]
