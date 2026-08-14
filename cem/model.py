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
class AsnInfo:
    """一个 IP 的归属。source 记清是哪儿查来的，便于判断可信度。"""

    ip: str
    asn: Optional[str] = None
    prefix: Optional[str] = None
    country: Optional[str] = None
    org: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None       # 省 / 州
    timezone: Optional[str] = None     # 该地址所在时区，可与本机时区对照
    loc: Optional[str] = None          # "纬度,经度"
    rdns: Optional[str] = None         # 反向解析，常能看出机房归属
    anycast: Optional[bool] = None
    # 三个分类标志，来自 ip-api 免费接口。它们是业界通用判据，
    # 但**都不是 100% 准的**，所以 kind_evidence 会说明结论从哪来。
    hosting: Optional[bool] = None     # 机房 / 云主机
    mobile: Optional[bool] = None      # 移动蜂窝网络
    proxy_flag: Optional[bool] = None  # 已知代理 / VPN 出口
    # 命中了哪家云厂商**自己发布**的地址段。这是唯一一个"确证"级证据：
    # AWS 说这个段是它的，那就是它的，不存在判断失误。
    cloud_provider: Optional[str] = None
    cloud_prefix: Optional[str] = None
    # RIR 注册信息（RDAP）。它是**注册时登记的事实**，比第三方推断硬一档，
    # 但仍不是确证：登记可能陈旧，命名习惯各家不同，没有统一规范。
    rir: Optional[str] = None            # 哪个注册局
    rir_name: Optional[str] = None       # 网段名
    rir_type: Optional[str] = None       # 分配类型
    rir_hint: Optional[str] = None       # 从注册信息读出的用途线索
    source: Optional[str] = None

    # ── 出口类型：机房还是家宽 ──────────────────────────────────
    # 为什么值得单独判：风控对**机房 IP** 明显更敏感（绝大多数爬虫和批量
    # 注册来自机房），住宅宽带被视为更"干净"。同一个国家里，一个机房出口
    # 和一个家宽出口的风险完全不是一回事。

    KIND_DATACENTER = "datacenter"
    # 注意这一档叫 non-datacenter 而不是 residential：免费数据源给的是
    # `hosting` 布尔值，它只区分"是不是机房"，**没有住宅 vs 企业这个维度**。
    # 家里的宽带和公司办公室的宽带在这里是同一档，公开的 BGP / WHOIS
    # 数据里也没有可靠标志能把它们分开。能分的数据源（IPinfo Privacy
    # Detection、IP2Location usage_type、MaxMind ISP）都要付费。
    KIND_RESIDENTIAL = "non-datacenter"
    KIND_MOBILE = "mobile"
    KIND_UNKNOWN = "unknown"

    # ── 置信度：结论到底有多硬 ──────────────────────────────────
    # 不标出来的话，「厂商官方地址段命中」和「组织名里有 cloud 这个词」
    # 会长得一模一样，而它们的可信度差着两个数量级。
    CONF_CONFIRMED = "confirmed"   # 权威来源直接说的，不是判断
    CONF_LIKELY = "likely"         # 第三方数据源的判断，通常准
    CONF_GUESS = "guess"           # 只有单一弱线索（组织名 / rDNS 形态）
    CONF_UNKNOWN = "unknown"       # 判不出来

    CONF_LABEL = {
        CONF_CONFIRMED: "确证",
        CONF_LIKELY: "较可能",
        CONF_GUESS: "推测",
        CONF_UNKNOWN: "判不出",
    }

    @property
    def kind_confidence(self) -> str:
        """这个 kind 判断有多硬。"""
        if self.cloud_provider:
            return self.CONF_CONFIRMED
        if self.mobile or self.hosting is not None:
            return self.CONF_LIKELY
        if self.rir_hint:
            # RIR 注册信息是官方登记的，比纯组织名猜测硬，但不到确证
            return self.CONF_LIKELY
        if self._guess_kind() != self.KIND_UNKNOWN:
            return self.CONF_GUESS
        return self.CONF_UNKNOWN

    @property
    def kind_confidence_label(self) -> str:
        return self.CONF_LABEL[self.kind_confidence]

    @property
    def kind(self) -> str:
        """机房 / 家宽 / 移动 / 不确定。

        优先用数据源的标志位；拿不到时退回启发式（组织名关键词 + rDNS 形态）。
        判不出来就返回 unknown —— **不猜**，因为猜错的方向正好是最危险的
        那个：把机房猜成家宽会让人以为风险更低。
        """
        # 厂商官方地址段最硬，排最前面
        if self.cloud_provider:
            return self.KIND_DATACENTER
        if self.mobile:
            return self.KIND_MOBILE
        if self.hosting:
            return self.KIND_DATACENTER
        if self.hosting is False and self.mobile is False:
            return self.KIND_RESIDENTIAL
        return self._guess_kind()

    def _guess_kind(self) -> str:
        """没有标志位时的启发式兜底。RIR 登记的用途线索优先于组织名。"""
        if self.rir_hint == "datacenter":
            return self.KIND_DATACENTER
        if self.rir_hint == "residential-ish":
            return self.KIND_RESIDENTIAL
        blob = " ".join(filter(None,
                               [self.org, self.rdns, self.rir_name])).lower()
        if not blob:
            return self.KIND_UNKNOWN
        dc_words = ("hosting", "cloud", "vps", "datacenter", "data center",
                    "server", "idc", "colo", "amazon", "google", "azure",
                    "digitalocean", "vultr", "linode", "hetzner", "ovh",
                    "contabo", "leaseweb", "oracle")
        home_words = ("broadband", "telecom", "communications", "cable",
                      "dsl", "fiber", "ftth", "residential", "ppp", "dialup")
        if any(w in blob for w in dc_words):
            return self.KIND_DATACENTER
        if any(w in blob for w in home_words):
            return self.KIND_RESIDENTIAL
        return self.KIND_UNKNOWN

    @property
    def kind_evidence(self) -> str:
        """这个判断是从哪来的。没有它，读者无法判断该不该信。"""
        if self.cloud_provider:
            return (f"命中 {self.cloud_provider} 官方发布的地址段 "
                    f"{self.cloud_prefix or ''} —— 这是厂商自己承认的，"
                    f"不是第三方推断")
        if self.mobile:
            return "数据源标记为移动蜂窝网络"
        if self.rir_hint and self.hosting is None:
            return (f"RIR 注册信息（{self.rir or '?'}）：网段名 "
                    f"{self.rir_name or '—'}，类型 {self.rir_type or '—'} —— "
                    f"这是分配时登记的，比第三方推断硬，但登记可能陈旧")
        if self.hosting is True:
            return "数据源标记为机房 / 托管网络"
        if self.hosting is False and self.mobile is False:
            return ("数据源标记为非机房、非移动。它只能到这一档 —— "
                    "免费数据源给的是「是不是机房」这一个布尔值，没有"
                    "「住宅 vs 企业」的维度，所以家里的宽带和公司办公室的"
                    "宽带在这里分不开。要分得靠付费数据源。")
        if self._guess_kind() == self.KIND_UNKNOWN:
            return "数据源没给分类标志，组织名和 rDNS 也看不出来 —— 不猜"
        return "数据源没给标志，按组织名 / rDNS 形态推断（可信度较低）"

    @property
    def proxy_suspected(self) -> bool:
        return bool(self.proxy_flag)

    @property
    def where(self) -> Optional[str]:
        """人读的地理位置：城市 · 省 · 国家，缺哪段跳哪段。

        国家相同但地址不同的时候，城市是**唯一**能把两个出口区分开的
        人类可读信息 —— 「都是新加坡」和「一个新加坡一个吉隆坡」
        是完全不同的两件事。
        """
        parts = [p for p in (self.city, self.region, self.country) if p]
        # 城市和省常常同名（Singapore / Singapore），去重
        deduped: list[str] = []
        for p in parts:
            if p not in deduped:
                deduped.append(p)
        return " · ".join(deduped) if deduped else None

    @property
    def short_org(self) -> Optional[str]:
        """把 "EXMPL-SG-AP - Example Telecom Pte Ltd, SG" 压成 "Example Telecom"。

        Cymru 的组织名格式是 `HANDLE - 全名, 国家`，整串放进卡片会撑爆一行，
        而读者真正要认的是中间那个公司名。
        """
        if not self.org:
            return None
        name = self.org.split(" - ", 1)[-1]
        name = name.rsplit(",", 1)[0].strip()
        for tail in (" Pte Ltd", " Co., Ltd", " Ltd", " LLC", " Inc.", " KK",
                     " PBC", " GmbH", " B.V.", " Corp", " AB", " SA"):
            if name.endswith(tail):
                name = name[: -len(tail)].strip()
        # 削掉后缀后常留下一个尾逗号（"Anthropic, PBC" → "Anthropic,"）
        return name.rstrip(" ,.-") or None


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
    egress_asn: Optional["AsnInfo"] = None   # 出口地址属于谁的网络
    peer_asn: Optional["AsnInfo"] = None     # 对端地址属于谁
    tls_info: Optional[dict] = None          # 证书信息，见 net.TlsInfo
    clock_skew_s: Optional[float] = None     # 本机时钟与服务端的差（秒）

    @property
    def is_ipv6(self) -> bool:
        return bool(self.egress_ip) and ":" in (self.egress_ip or "")

    @property
    def family(self) -> Optional[str]:
        if not self.egress_ip:
            return None
        return "IPv6" if self.is_ipv6 else "IPv4"

    @property
    def tun_shortcut(self) -> bool:
        """TCP 握手是不是被本机的 TUN 直接接下了。

        判据：TCP 段 < 5ms 但 TLS 段 > 50ms。透明代理/TUN 会在本地**立刻**
        完成三次握手，再自己去连真实目标，于是真实的往返成本全部挤进 TLS
        和首字节里。不标出来，读者会看到「TCP 0.5ms」然后得出
        「网络这一段没问题」的错误结论。
        """
        tcp, tls = self.timing.tcp_ms, self.timing.tls_ms
        return bool(tcp is not None and tls is not None and tcp < 5 and tls > 50)


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
class Check:
    """一项环境级检查。

    和 TraceView 的区别：TraceView 是"某个域名某条路径"的观测，
    Check 是"这台机器此刻"的事实（IPv6 通不通、时钟准不准、
    证书有没有被换过）。这些和具体域名无关，一轮只需要一份。
    """

    id: str
    label: str
    ok: bool
    value: Optional[str] = None
    detail: Optional[str] = None
    severity: str = "info"        # ok / info / warn / critical


@dataclass(frozen=True)
class Sample:
    """一轮完整采样。UI 上看到的每一个数字都来自这里。"""

    ts: float
    seq: int
    traces: tuple[TraceView, ...] = ()
    resolves: tuple[ResolveView, ...] = ()
    connections: tuple[Connection, ...] = ()
    # 每个入口当前有几个进程在跑。用来区分界面上两件**完全不同**的事：
    #   出口卡  = 「如果这个入口现在发流量，会从哪出去」（按它的代理配置探测）
    #   实时连接 = 「它此刻正连着谁」（lsof 真实观测）
    # 桌面端没运行时出口卡照样有值 —— 那是推算，不是观测。
    # 不把这件事写在界面上，读者会把推算当成观测。
    processes: tuple[tuple[str, int], ...] = ()
    checks: tuple[Check, ...] = ()
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return _clean(self)


__all__ = [
    "AsnInfo",
    "Check",
    "Connection",
    "ResolveView",
    "Sample",
    "Timing",
    "TraceView",
    "replace",
]
