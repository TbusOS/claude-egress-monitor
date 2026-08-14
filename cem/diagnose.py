"""出口画像、稳定性分析、以及「现象 → 成因 → 解决方案」的诊断。

这个模块回答的是使用者真正会问的那个问题：**我的出口 IP 一直在变，
这正常吗，要不要管，怎么管。**

三层递进：

1. `egress_profile()` —— 一轮之内，每条路径的出口长什么样。
   关键在于不把"国家相同"当成"出口相同"：同一个国家里换了地址，
   可能是同一台机器的 v4/v6 双栈（无所谓），也可能是节点组换了另一台
   服务器（要知道）。这两件事的处置完全不同，所以要分级，不能两档了事。

2. `stability()` —— 跨轮次的漂移：出现过几个出口、几个网络、变了几次。

3. `diagnose()` —— 把上面两层的观测翻译成带**判据**和**可执行方案**的
   条目。每条诊断都必须带上算出它的那几个数字，否则读者没法判断
   这条建议值不值得照做。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import endpoints as ep
from . import probe
from .model import Sample, TraceView

# ── 一致性分级 ──────────────────────────────────────────────────────
# 从"完全没问题"到"必须处理"。级别名同时也是界面上的样式键。
LEVEL_IDENTICAL = "identical"        # 只有一个出口地址
LEVEL_DUAL_STACK = "dual-stack"      # 多个地址，同一个网络，v4/v6 各一
LEVEL_SAME_NETWORK = "same-network"  # 多个地址，同一个 ASN
LEVEL_MULTI_NETWORK = "multi-network"  # 多个 ASN，同一个国家
LEVEL_MULTI_COUNTRY = "multi-country"  # 落在多个国家

LEVEL_ORDER = (LEVEL_IDENTICAL, LEVEL_DUAL_STACK, LEVEL_SAME_NETWORK,
               LEVEL_MULTI_NETWORK, LEVEL_MULTI_COUNTRY)

LEVEL_LABEL = {
    LEVEL_IDENTICAL: "单一出口",
    LEVEL_DUAL_STACK: "同节点双栈",
    LEVEL_SAME_NETWORK: "同一网络多地址",
    LEVEL_MULTI_NETWORK: "跨网络",
    LEVEL_MULTI_COUNTRY: "跨国家",
}

LEVEL_MEANING = {
    LEVEL_IDENTICAL:
        "这条路径下所有 Claude 域名都从同一个地址出去，最理想的状态。",
    LEVEL_DUAL_STACK:
        "出现了多个地址，但它们属于同一个 ASN，且分别是 IPv4 和 IPv6 —— "
        "这是同一个出口节点的双栈地址，风控看到的是同一个网络，不用处理。",
    LEVEL_SAME_NETWORK:
        "多个地址属于同一家运营商（同 ASN）。通常是节点组里有多台服务器，"
        "或者出口做了负载均衡。风控看到的仍是同一个网络，但地址会跳。",
    LEVEL_MULTI_NETWORK:
        "地址分属不同 ASN —— 是不同的网络，只是恰好在同一个国家。"
        "分流规则把不同域名送去了不同节点，或者节点组在自动择优。",
    LEVEL_MULTI_COUNTRY:
        "落在了不同国家。同一个账号的流量从多个国家出去，是风控最敏感的"
        "一种形态，也几乎总是分流规则没覆盖全造成的。",
}

KIND_LABEL = {
    "datacenter": "机房 / 云主机",
    "non-datacenter": "非机房宽带（住宅或企业）",
    "mobile": "移动蜂窝网络",
    "unknown": "判不出来",
}

# 出口类型对风控意味着什么。这是使用者真正关心的部分 ——
# 单说"这是机房 IP"没有用，要说清它带来什么后果。
KIND_MEANING = {
    "datacenter":
        "机房 IP 在各家风控里普遍权重更低 —— 绝大多数爬虫和批量注册来自机房，"
        "所以同样的行为从机房 IP 出去更容易被要求验证。这不代表一定有问题，"
        "但它是一个持续存在的减分项。",
    "non-datacenter":
        "非机房地址被风控视为更干净的来源。要注意数据源只能判到这一档 —— "
        "免费数据源给的是「是不是机房」这一个布尔值，没有「住宅 vs 企业」"
        "的维度，所以家里的宽带和公司办公室的宽带在这里是同一类，分不开。"
        "代价是这类线路常常是动态 IP，地址会周期性变化，看下面的漂移统计。",
    "mobile":
        "移动网络在 CGNAT 后面，很多人共用同一个出口地址。你的信誉会受"
        "同网段其他人的行为影响，而这一点完全不在你的控制范围内。",
    "unknown":
        "数据源没给分类标志，组织名和 rDNS 也看不出来。这里不猜 —— "
        "把机房猜成家宽会让人以为风险更低，那是最危险的方向。",
}


# ── 诊断严重度 ─────────────────────────────────────────────────────
SEV_CRITICAL = "critical"   # 账号风险，立刻处理
SEV_WARN = "warn"           # 配置有问题，该修
SEV_INFO = "info"           # 是这样，知道即可
SEV_OK = "ok"               # 检查通过

SEV_ORDER = {SEV_CRITICAL: 0, SEV_WARN: 1, SEV_INFO: 2, SEV_OK: 3}

RESTRICTED_CC = {
    "CN": "中国大陆", "HK": "香港", "MO": "澳门", "RU": "俄罗斯",
    "KP": "朝鲜", "IR": "伊朗", "SY": "叙利亚", "CU": "古巴",
    "BY": "白俄罗斯", "VE": "委内瑞拉",
}


@dataclass(frozen=True)
class ExitAddress:
    """一个出口地址，以及它覆盖了哪些域名。"""

    ip: str
    family: str                       # IPv4 / IPv6
    country: Optional[str]
    colo: Optional[str]
    asn: Optional[str]
    org: Optional[str]
    hosts: tuple[str, ...]
    city: Optional[str] = None
    kind: str = "unknown"          # datacenter / residential / mobile / unknown
    kind_evidence: Optional[str] = None
    proxy_flagged: bool = False

    @property
    def network_key(self) -> str:
        """判断"是不是同一个网络"用的键。

        有 ASN 就用 ASN；查不到就退回国家 —— 退回之后只能得出更弱的结论，
        所以 `unknown:` 前缀让上层知道这个判断的可信度较低。
        """
        return self.asn or f"unknown:{self.country or '?'}"


@dataclass(frozen=True)
class PathProfile:
    """一条路径在一轮采样里的出口画像。"""

    path_id: str
    addresses: tuple[ExitAddress, ...]
    level: str
    countries: tuple[str, ...]
    networks: tuple[str, ...]
    domains: int

    @property
    def primary(self) -> Optional[ExitAddress]:
        return self.addresses[0] if self.addresses else None

    @property
    def restricted(self) -> tuple[str, ...]:
        return tuple(c for c in self.countries if c in RESTRICTED_CC)


def _address_of(traces: list[TraceView]) -> ExitAddress:
    head = traces[0]
    info = head.egress_asn
    return ExitAddress(
        ip=head.egress_ip or "",
        family=head.family or "IPv4",
        country=head.country,
        colo=head.colo,
        asn=(info.asn if info else None),
        org=(info.short_org if info else None),
        hosts=tuple(sorted({t.target for t in traces})),
        city=(info.city if info else None),
        kind=(info.kind if info else "unknown"),
        kind_evidence=(info.kind_evidence if info else None),
        proxy_flagged=bool(info and info.proxy_suspected),
    )


def classify_level(addresses: tuple[ExitAddress, ...]) -> str:
    """给一组出口地址定一致性级别。纯函数 —— 这是全模块最该被测的一段。"""
    if len(addresses) <= 1:
        return LEVEL_IDENTICAL
    countries = {a.country for a in addresses if a.country}
    if len(countries) > 1:
        return LEVEL_MULTI_COUNTRY
    networks = {a.network_key for a in addresses}
    if len(networks) > 1:
        return LEVEL_MULTI_NETWORK
    families = {a.family for a in addresses}
    if len(addresses) == 2 and families == {"IPv4", "IPv6"}:
        return LEVEL_DUAL_STACK
    return LEVEL_SAME_NETWORK


def egress_profile(sample: Sample) -> dict[str, PathProfile]:
    """每条路径的出口画像。只看 Claude 自己的域名，排除对照组。"""
    by_path: dict[str, list[TraceView]] = {}
    for t in probe.claude_traces(sample):
        by_path.setdefault(t.path, []).append(t)

    out: dict[str, PathProfile] = {}
    for path_id, traces in by_path.items():
        by_ip: dict[str, list[TraceView]] = {}
        for t in traces:
            by_ip.setdefault(t.egress_ip, []).append(t)
        addresses = tuple(
            _address_of(group) for _ip, group in
            sorted(by_ip.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        )
        out[path_id] = PathProfile(
            path_id=path_id,
            addresses=addresses,
            level=classify_level(addresses),
            countries=tuple(sorted({a.country for a in addresses if a.country})),
            networks=tuple(sorted({a.network_key for a in addresses})),
            domains=len(traces),
        )
    return out


@dataclass(frozen=True)
class Stability:
    """一条路径跨轮次的出口漂移统计。"""

    path_id: str
    rounds: int
    ips: tuple[str, ...]
    networks: tuple[str, ...]
    countries: tuple[str, ...]
    ip_changes: int
    network_changes: int
    country_changes: int

    @property
    def stable(self) -> bool:
        return self.ip_changes == 0

    @property
    def drift_rate(self) -> float:
        """每轮平均变更次数。0 = 完全稳定。"""
        if self.rounds <= 1:
            return 0.0
        return round(self.ip_changes / (self.rounds - 1), 3)


def stability(samples: tuple[Sample, ...], path_id: str) -> Stability:
    """统计一条路径的出口在窗口内漂移了多少。

    用**主出口**（覆盖域名最多的那个）代表这一轮，否则同一轮内的
    v4/v6 并存会被误算成一次"变更"。
    """
    ips: list[str] = []
    nets: list[str] = []
    ccs: list[str] = []
    for s in samples:
        prof = egress_profile(s).get(path_id)
        if not prof or not prof.primary:
            continue
        ips.append(prof.primary.ip)
        nets.append(prof.primary.network_key)
        ccs.append(prof.primary.country or "?")

    def changes(seq: list[str]) -> int:
        return sum(1 for a, b in zip(seq, seq[1:]) if a != b)

    return Stability(
        path_id=path_id,
        rounds=len(ips),
        ips=tuple(dict.fromkeys(ips)),
        networks=tuple(dict.fromkeys(nets)),
        countries=tuple(dict.fromkeys(ccs)),
        ip_changes=changes(ips),
        network_changes=changes(nets),
        country_changes=changes(ccs),
    )


NATURE_DYNAMIC = "dynamic"
NATURE_STEADY = "steady-so-far"
NATURE_UNKNOWN = "insufficient-data"

# 少于这个观测时长就不下结论。家宽的动态 IP 往往几小时甚至几天才换一次，
# 观测二十分钟就说"是静态 IP"是没有依据的。
NATURE_MIN_HOURS = 6.0


@dataclass(frozen=True)
class AddressNature:
    """出口地址是动态还是静态。

    **单次观测答不了这个问题** —— 只能靠观测时长 + 变更次数推断，
    所以这里必须把观测窗口一起报出来，让读者自己判断结论有多硬。
    """

    path_id: str
    nature: str
    hours_observed: float
    unique_ips: int
    ip_changes: int
    same_network: bool
    detail: str


def address_nature(samples: tuple[Sample, ...], path_id: str) -> AddressNature:
    st = stability(samples, path_id)
    # 用 `is not None` 而不是真值判断：ts=0 是合法时间戳，
    # 写成 `if s.ts` 会把它当成缺失值丢掉，观测窗口算出来就是 0 小时。
    times = [s.ts for s in samples if s.ts is not None]
    hours = round((max(times) - min(times)) / 3600.0, 2) if len(times) >= 2 else 0.0
    same_net = len(st.networks) <= 1

    if hours < NATURE_MIN_HOURS and st.ip_changes == 0:
        nature = NATURE_UNKNOWN
        detail = (f"只观测了 {hours} 小时，期间没变过。家宽的动态 IP 常常几小时"
                  f"到几天才换一次，这个时长还不足以判断是静态还是没赶上变更 —— "
                  f"至少连续观测 {NATURE_MIN_HOURS:g} 小时再看。")
    elif st.ip_changes > 0:
        nature = NATURE_DYNAMIC
        detail = (f"{hours} 小时内换过 {st.ip_changes} 次地址，出现过 "
                  f"{len(st.ips)} 个不同地址"
                  + ("，且始终在同一个 ASN 内 —— 典型的动态分配。"
                     if same_net else
                     "，而且跨了多个 ASN —— 是节点组在切换，不只是地址在变。"))
    else:
        nature = NATURE_STEADY
        detail = (f"连续观测 {hours} 小时没有变过，地址是 {st.ips[0] if st.ips else '—'}。"
                  f"这只能说明观测期内稳定，不等于运营商承诺了静态 IP。")

    return AddressNature(
        path_id=path_id, nature=nature, hours_observed=hours,
        unique_ips=len(st.ips), ip_changes=st.ip_changes,
        same_network=same_net, detail=detail,
    )


@dataclass(frozen=True)
class Finding:
    """一条诊断。

    四个字段缺一不可：
    - `evidence` 是算出这条结论的实测数字。没有它，读者无法判断
      这条建议值不值得照做。
    - `cause` 是成因，不是现象的复述。
    - `fix` 是可执行的下一步，不是"建议检查配置"。
    """

    id: str
    severity: str
    title: str
    evidence: str
    cause: str
    fix: str
    docs: Optional[str] = None


def _fmt_addr(a: ExitAddress) -> str:
    bits = [a.ip, a.family]
    if a.country:
        bits.append(a.country)
    if a.org:
        bits.append(a.org)
    elif a.asn:
        bits.append(a.asn)
    return " · ".join(bits)


def _path_label(path_id: str) -> str:
    return {"cli": "Claude Code", "desktop": "桌面端 / 浏览器",
            "baseline": "直连对照"}.get(path_id, path_id)


def diagnose(
    sample: Optional[Sample],
    samples: tuple[Sample, ...] = (),
) -> tuple[Finding, ...]:
    """把观测翻译成带判据和方案的诊断条目，按严重度排序。"""
    if sample is None:
        return ()
    found: list[Finding] = []
    profiles = egress_profile(sample)

    # ── D1 出口落在受限地区 ───────────────────────────────────────
    for path_id, prof in sorted(profiles.items()):
        for cc in prof.restricted:
            hosts = [a for a in prof.addresses if a.country == cc]
            found.append(Finding(
                id=f"restricted-{path_id}-{cc}",
                severity=SEV_CRITICAL,
                title=f"{_path_label(path_id)} 的出口落在受限地区：{RESTRICTED_CC[cc]}",
                evidence=f"出口 {_fmt_addr(hosts[0])}，覆盖 "
                         f"{len(hosts[0].hosts)} 个 Claude 域名",
                cause="Claude 的服务条款把这些地区列为受限。从这里访问是"
                      "账号风控最直接的触发条件，和网速无关。",
                fix="立刻把这条路径的出口换到非受限地区，然后重新采一轮确认。"
                    "受限地区名单以官方条款为准，本工具只负责提醒你去核对。",
                docs="docs/03-routing.md#六受限地区",
            ))

    # ── D2 入口之间出口不一致 ─────────────────────────────────────
    cross = {}
    for path_id, prof in profiles.items():
        if prof.primary:
            cross[path_id] = prof.primary
    if len(cross) > 1:
        ccs = {a.country for a in cross.values() if a.country}
        nets = {a.network_key for a in cross.values()}
        detail = "；".join(
            f"{_path_label(p)} → {_fmt_addr(a)}" for p, a in sorted(cross.items())
        )
        if len(ccs) > 1:
            found.append(Finding(
                id="cross-surface-country",
                severity=SEV_WARN,
                title="两个入口的出口落在不同国家",
                evidence=detail,
                cause="Claude Code 是 Node 程序，只认 HTTPS_PROXY / HTTP_PROXY "
                      "环境变量，不读系统代理；而桌面端和浏览器读的是系统代理。"
                      "两份配置不同，出口自然不同。",
                fix="要统一，给 CLI 显式设上和系统代理一样的地址：\n"
                    "  export HTTPS_PROXY=http://<代理地址>\n"
                    "  export HTTP_PROXY=http://<代理地址>\n"
                    "  export NO_PROXY=localhost,127.0.0.1,::1\n"
                    "写进 shell 配置后重开终端，再采一轮确认两张卡一致。",
                docs="docs/03-routing.md#五把配置改成一致的",
            ))
        elif len(nets) > 1:
            found.append(Finding(
                id="cross-surface-network",
                severity=SEV_INFO,
                title="两个入口国家相同，但走的是不同网络",
                evidence=detail,
                cause="两个入口命中了不同的节点。国家一样，但 ASN 不同 —— "
                      "对风控来说这是两个不同的来源网络。",
                fix="不影响可用性。想彻底一致，同样是给 CLI 设上 HTTPS_PROXY，"
                    "让两个入口走同一条链路。",
                docs="docs/03-routing.md",
            ))

    # ── D3 单条路径内部的一致性分级 ───────────────────────────────
    for path_id, prof in sorted(profiles.items()):
        if prof.level == LEVEL_IDENTICAL:
            found.append(Finding(
                id=f"path-consistent-{path_id}",
                severity=SEV_OK,
                title=f"{_path_label(path_id)}：所有 Claude 域名同一个出口",
                evidence=f"{prof.domains} 个域名 → {_fmt_addr(prof.primary)}",
                cause="分流规则覆盖到了全部 Claude 域名。",
                fix="不用动。",
            ))
            continue

        addrs = "；".join(
            f"{_fmt_addr(a)}（{len(a.hosts)} 个域名：{'、'.join(a.hosts[:3])}"
            f"{' 等' if len(a.hosts) > 3 else ''}）"
            for a in prof.addresses
        )
        if prof.level == LEVEL_DUAL_STACK:
            found.append(Finding(
                id=f"dual-stack-{path_id}",
                severity=SEV_INFO,
                title=f"{_path_label(path_id)}：出现两个地址，但是同一个节点的双栈",
                evidence=addrs,
                cause="出口节点同时有 IPv4 和 IPv6 地址，每条连接走哪个协议栈"
                      "由节点自己决定。两个地址属于同一个 ASN，风控看到的是"
                      "同一个网络。",
                fix="不用处理。如果你希望地址完全固定（比如要给某个服务"
                    "报备白名单），可以在分流器里关掉 IPv6，或者在规则里"
                    "只允许 IPv4 出站。",
                docs="docs/03-routing.md",
            ))
        elif prof.level == LEVEL_SAME_NETWORK:
            found.append(Finding(
                id=f"same-network-{path_id}",
                severity=SEV_INFO,
                title=f"{_path_label(path_id)}：同一家运营商的多个出口地址",
                evidence=addrs,
                cause="节点组里有多台服务器，或者出口侧做了负载均衡，"
                      "不同连接落在不同地址上。ASN 相同，所以仍是同一个网络。",
                fix="要地址固定，把这些 Claude 域名指到单个节点而不是"
                    "节点组（分流器里选具体节点，不要选 url-test / "
                    "load-balance 这类自动组）。",
                docs="docs/03-routing.md",
            ))
        elif prof.level == LEVEL_MULTI_NETWORK:
            found.append(Finding(
                id=f"multi-network-{path_id}",
                severity=SEV_WARN,
                title=f"{_path_label(path_id)}：Claude 的域名分散在不同网络",
                evidence=addrs,
                cause="分流规则是按域名逐条匹配的。有的 Claude 域名命中了"
                      "你指定的节点，有的没被规则覆盖、落到了兜底出口。",
                fix="把全部 Claude 域名收进同一条规则。域名清单可以直接生成：\n"
                    "  python3 -m cem endpoints --json\n"
                    "然后在分流器里建一个规则集合指向同一个节点组。",
                docs="docs/03-routing.md#五把配置改成一致的",
            ))
        elif prof.level == LEVEL_MULTI_COUNTRY:
            found.append(Finding(
                id=f"multi-country-{path_id}",
                severity=SEV_WARN,
                title=f"{_path_label(path_id)}：Claude 的域名落在不同国家",
                evidence=addrs,
                cause="同上 —— 规则漏了一部分域名，它们走了兜底出口，"
                      "而兜底出口在另一个国家。",
                fix="同上：把全部 Claude 域名收进同一条规则。"
                    "这一条比「跨网络」更要紧，因为同一账号从多个国家出去"
                    "是风控最敏感的形态。",
                docs="docs/03-routing.md#五把配置改成一致的",
            ))

    # ── D4 跨轮次漂移 ─────────────────────────────────────────────
    for path_id in sorted(profiles):
        st = stability(samples, path_id)
        if st.rounds < 2:
            continue
        if st.country_changes:
            found.append(Finding(
                id=f"drift-country-{path_id}",
                severity=SEV_WARN,
                title=f"{_path_label(path_id)}：出口国家在这段时间里变过 "
                      f"{st.country_changes} 次",
                evidence=f"{st.rounds} 轮里出现过 {len(st.countries)} 个国家："
                         f"{'、'.join(st.countries)}",
                cause="节点组在自动择优或轮询，而组里的节点分布在不同国家。",
                fix="把 Claude 的域名指到固定的单个节点，或者建一个只含"
                    "同一国家节点的组。跨国漂移会让风控看到一个来回跳国家的账号。",
                docs="docs/03-routing.md",
            ))
        elif st.network_changes:
            found.append(Finding(
                id=f"drift-network-{path_id}",
                severity=SEV_INFO,
                title=f"{_path_label(path_id)}：出口换过 {st.network_changes} 次网络",
                evidence=f"{st.rounds} 轮里出现过 {len(st.networks)} 个 ASN、"
                         f"{len(st.ips)} 个地址",
                cause="节点组在轮询或自动择优，换到了另一家运营商的服务器。",
                fix="要稳定就锁定单个节点。若只是想知道正不正常 —— 同国家内"
                    "换网络对可用性没影响。",
            ))
        elif st.ip_changes:
            found.append(Finding(
                id=f"drift-ip-{path_id}",
                severity=SEV_INFO,
                title=f"{_path_label(path_id)}：出口地址变过 {st.ip_changes} 次，"
                      f"但一直在同一个网络里",
                evidence=f"{st.rounds} 轮里出现过 {len(st.ips)} 个地址，"
                         f"ASN 始终是 {st.networks[0] if st.networks else '—'}",
                cause="同一家运营商的多个地址（双栈或多机），或者出口是动态 IP。",
                fix="风控看的是网络归属，同 ASN 内换地址通常无害。"
                    "确实需要固定 IP 的话，得用带静态出口的服务。",
            ))
        elif st.rounds >= 3:
            found.append(Finding(
                id=f"drift-stable-{path_id}",
                severity=SEV_OK,
                title=f"{_path_label(path_id)}：出口在 {st.rounds} 轮里没有变过",
                evidence=f"始终是 {st.ips[0] if st.ips else '—'}",
                cause="节点固定，规则稳定。",
                fix="不用动。",
            ))

    # ── D4b 出口类型：机房还是家宽 ────────────────────────────────
    for path_id, prof in sorted(profiles.items()):
        primary = prof.primary
        if not primary:
            continue
        kind = primary.kind
        sev = SEV_INFO if kind != "unknown" else SEV_INFO
        found.append(Finding(
            id=f"exit-kind-{path_id}",
            severity=sev,
            title=f"{_path_label(path_id)} 的出口类型：{KIND_LABEL.get(kind, kind)}",
            evidence=f"{primary.ip}"
                     + (f" · {primary.city}" if primary.city else "")
                     + (f" · {primary.org}" if primary.org else "")
                     + f"；判据：{primary.kind_evidence or '无'}",
            cause=KIND_MEANING.get(kind, ""),
            fix=("这是事实陈述，不一定要处理。真要换类型，只能换出口线路 —— "
                 "住宅代理比机房代理贵得多，是否值得取决于你的使用强度。"
                 if kind == "datacenter" else
                 "不用处理。" if kind == "non-datacenter" else
                 "换一条非移动网络的线路可以摆脱共用地址的影响。"
                 if kind == "mobile" else
                 "想确认的话，手工查一下这个地址的 rDNS 和 ASN 用途。"),
            docs="docs/03-routing.md",
        ))
        if primary.proxy_flagged:
            found.append(Finding(
                id=f"exit-proxy-flag-{path_id}",
                severity=SEV_WARN,
                title=f"{_path_label(path_id)} 的出口被数据源标记为已知代理 / VPN",
                evidence=f"{primary.ip} · {primary.org or primary.asn or ''}",
                cause="这个地址出现在公开的代理 / VPN 地址库里。风控厂商用的"
                      "多半是同一批库，所以对方大概率也知道。",
                fix="换一条没被收录的线路。用得多的公共机场节点几乎必然会被收录，"
                    "自建或住宅线路收录概率低得多。",
            ))

    # ── D4c 地址是动态还是静态 ────────────────────────────────────
    for path_id in sorted(profiles):
        nat = address_nature(samples, path_id)
        if nat.nature == NATURE_UNKNOWN:
            found.append(Finding(
                id=f"nature-{path_id}",
                severity=SEV_INFO,
                title=f"{_path_label(path_id)}：还判断不了是动态还是静态 IP",
                evidence=f"观测 {nat.hours_observed} 小时 · "
                         f"{nat.unique_ips} 个地址 · {nat.ip_changes} 次变更",
                cause="单次或短时观测答不了这个问题 —— 动态 IP 常常几小时到"
                      "几天才换一次。",
                fix=f"把监控开着连续跑 {NATURE_MIN_HOURS:g} 小时以上，"
                    f"这一条会自动变成明确结论。历史会按天归档，占不了多少空间。",
            ))
        elif nat.nature == NATURE_DYNAMIC:
            found.append(Finding(
                id=f"nature-{path_id}",
                severity=SEV_INFO,
                title=f"{_path_label(path_id)}：出口是动态地址",
                evidence=f"观测 {nat.hours_observed} 小时 · "
                         f"{nat.unique_ips} 个地址 · {nat.ip_changes} 次变更",
                cause=nat.detail,
                fix="需要固定出口（比如要报备 IP 白名单）就得换成带静态地址的"
                    "线路。只是自己用的话，同一个 ASN 内换地址通常无害。",
            ))
        else:
            found.append(Finding(
                id=f"nature-{path_id}",
                severity=SEV_OK,
                title=f"{_path_label(path_id)}：观测期内地址稳定",
                evidence=f"观测 {nat.hours_observed} 小时没有变更",
                cause=nat.detail,
                fix="不用动。注意这只是观测结论，不等于运营商承诺静态 IP。",
            ))

    # ── D5 fake-ip：本机解析不可信 ────────────────────────────────
    fake = [r for r in sample.resolves if r.kind == "fake-ip"]
    if fake:
        found.append(Finding(
            id="fake-ip",
            severity=SEV_INFO,
            title=f"{len(fake)} 个域名的本机解析是 fake-ip 占位地址",
            evidence="、".join(r.host for r in fake[:4]) +
                     (f" 等 {len(fake)} 个" if len(fake) > 4 else ""),
            cause="本机开着 TUN / 透明代理，它拦下 DNS 查询、给每个域名发一个"
                  "198.18.x.x 的占位地址，自己记住对应关系。",
            fix="不要拿 `dig` 的结果判断流量走哪 —— 那个地址不是真实主机，"
                "查它的归属毫无意义。判断出口只看「目的地那侧看到的源地址」，"
                "也就是本工具的出口 IP 那一列。",
            docs="docs/03-routing.md#陷阱一fake-ip--dig-查出来的地址是假的",
        ))

    # ── D6 split-DNS：域名被分派给专用解析器 ──────────────────────
    split = [r for r in sample.resolves if r.resolver]
    if split:
        resolvers = sorted({r.resolver for r in split if r.resolver})
        found.append(Finding(
            id="split-dns",
            severity=SEV_INFO,
            title=f"{len(split)} 个域名走了专用 DNS 解析器",
            evidence=f"解析器 {'、'.join(resolvers)}；"
                     f"涉及 {'、'.join(r.host for r in split[:3])} 等",
            cause="系统里配了按域名分派的解析器（VPN、Tailscale MagicDNS、"
                  "企业配置都会写）。解析走哪条隧道，流量通常也走那条 —— "
                  "这解释了为什么这些域名的行为和其他域名不同。",
            fix="如果这不是你有意配置的，检查是不是某个 VPN 客户端在后台"
                "接管了这些域名：`scutil --dns | grep -B2 -A2 anthropic`。",
            docs="docs/03-routing.md#陷阱二按域名分派的解析器split-dns",
        ))

    # ── D7 TUN 让 TCP 段失真 ──────────────────────────────────────
    shortcut = [t for t in sample.traces if t.tun_shortcut]
    if shortcut:
        found.append(Finding(
            id="tun-timing",
            severity=SEV_INFO,
            title="延迟里的 TCP 段被本机 TUN 吃掉了，不能按字面读",
            evidence=f"{len(shortcut)} 条探测的 TCP 段 < 5ms 而 TLS 段 > 50ms，"
                     f"例如 {shortcut[0].target}："
                     f"TCP {shortcut[0].timing.tcp_ms}ms / "
                     f"TLS {shortcut[0].timing.tls_ms}ms",
            cause="透明代理会在本地立刻完成三次握手，然后自己去连真实目标。"
                  "于是真实的往返成本全部挤进了 TLS 和首字节里。",
            fix="判断网络快慢看 TLS + 首字节，不要看 TCP 段。"
                "TCP 段在这种环境下只说明「本机 TUN 响应很快」。",
            docs="docs/04-latency.md",
        ))

    # ── D8 遥测与业务出口不同 ─────────────────────────────────────
    tele = [t for t in sample.traces
            if (ep.classify_host(t.target) or None)
            and ep.classify_host(t.target).category == ep.CAT_TELEMETRY]
    unreachable = [t for t in tele if not t.ok]
    if tele and not unreachable:
        found.append(Finding(
            id="telemetry-reachable",
            severity=SEV_INFO,
            title=f"{len(tele)} 个遥测接入点当前可达",
            evidence="、".join(sorted({t.target for t in tele})),
            cause="Claude Code 把客户端运行日志发给 Datadog（US5 站点，"
                  "落地美国 Google Cloud），崩溃上报走 Sentry US 区。",
            fix="想关：`export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`，"
                "或在分流器里给这几个域名配 REJECT。关掉之后回来看这一条"
                "会变成「不可达」，那就是真的关掉了。",
            docs="docs/02-telemetry.md",
        ))
    elif unreachable:
        found.append(Finding(
            id="telemetry-blocked",
            severity=SEV_OK,
            title=f"{len(unreachable)} 个遥测接入点不可达（可能是你拦掉了）",
            evidence="、".join(sorted({t.target for t in unreachable})),
            cause="被分流规则 REJECT、被 DNS 拦掉，或者网络本身不通。",
            fix="如果是你有意拦的，这就是预期结果。如果不是，"
                "检查分流规则里有没有过宽的 REJECT 规则误伤。",
            docs="docs/02-telemetry.md",
        ))

    # ── D9 代理后面的目的地不可见 ─────────────────────────────────
    hidden = [c for c in sample.connections if c.kind == "local-proxy"]
    if hidden:
        found.append(Finding(
            id="proxy-blind-spot",
            severity=SEV_INFO,
            title=f"{len(hidden)} 条连接的真实目的地看不到",
            evidence=f"它们连的是本机代理 {hidden[0].remote_ip}:"
                     f"{hidden[0].remote_port}",
            cause="走 HTTP 代理的进程，`lsof` 只能看到「它连了 127.0.0.1」，"
                  "真实目的地在代理进程内部。",
            fix="打开分流器的控制接口就能补上这一段（它的 /connections 接口"
                "会给出真实域名、命中的规则、以及出口节点名）：\n"
                "  external-controller: 127.0.0.1:9090\n"
                "  secret: \"<设一个随机串>\"\n"
                "只绑 127.0.0.1，一定要设 secret。",
            docs="docs/03-routing.md#四补上第三个陷阱读分流器自己的连接表",
        ))

    found.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.id))
    return tuple(found)


def summary(findings: tuple[Finding, ...]) -> dict[str, int]:
    """按严重度计数，给界面上的徽标用。"""
    out = {SEV_CRITICAL: 0, SEV_WARN: 0, SEV_INFO: 0, SEV_OK: 0}
    for f in findings:
        if f.severity in out:
            out = {**out, f.severity: out[f.severity] + 1}
    return out


__all__ = [
    "AddressNature",
    "ExitAddress",
    "KIND_LABEL",
    "KIND_MEANING",
    "NATURE_DYNAMIC",
    "NATURE_MIN_HOURS",
    "NATURE_STEADY",
    "NATURE_UNKNOWN",
    "address_nature",
    "Finding",
    "LEVEL_DUAL_STACK",
    "LEVEL_IDENTICAL",
    "LEVEL_LABEL",
    "LEVEL_MEANING",
    "LEVEL_MULTI_COUNTRY",
    "LEVEL_MULTI_NETWORK",
    "LEVEL_ORDER",
    "LEVEL_SAME_NETWORK",
    "PathProfile",
    "RESTRICTED_CC",
    "SEV_CRITICAL",
    "SEV_INFO",
    "SEV_OK",
    "SEV_WARN",
    "Stability",
    "classify_level",
    "diagnose",
    "egress_profile",
    "stability",
    "summary",
]
