"""演示数据：一轮**完全虚构**的采样，用来出截图和离线调界面。

为什么要有这个模块：真实采样结果里全是使用者自己的出口 IP、代理端口、
内网地址。想给仓库配一张截图，就得先有一份可以公开的数据。

**所有地址都取自 RFC 5737 / RFC 3849 的文档保留段**：

- `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`(IPv4)
- `2001:db8::/32`(IPv6)

这些段被 IANA 永久保留给文档使用，公网上不会路由到任何主机 ——
所以它们不可能被误当成真实数据，也不会指向任何真实的人。

界面上开了演示模式会显式标出来，不会假装是实测结果。
"""

from __future__ import annotations

import time

from .model import Connection, ResolveView, Sample, Timing, TraceView

DEMO_NOTICE = "演示数据：地址取自 RFC 5737 文档保留段，不是实测结果。"


def _t(dns: float, tcp: float, tls: float, ttfb: float) -> Timing:
    return Timing(dns_ms=dns, tcp_ms=tcp, tls_ms=tls, ttfb_ms=ttfb,
                  total_ms=round(dns + tcp + tls + ttfb, 2))


# 故意造出一个"两个入口落在不同国家"的局面 —— 这正是工具要抓的那种情况。
_CLI_IP = "203.0.113.24"
_DESKTOP_IP = "198.51.100.77"

_CORE = (
    ("api.anthropic.com", 610.0),
    ("claude.ai", 702.0),
    ("code.claude.com", 588.0),
    ("platform.claude.com", 631.0),
    ("a-api.anthropic.com", 574.0),
    ("www.anthropic.com", 845.0),
    ("releases.claude.com", 733.0),
    ("1.1.1.1", 281.0),
)

_TELEMETRY = (
    ("http-intake.logs.us5.datadoghq.com", 342.0),
    ("browser-intake-us5-datadoghq.com", 351.0),
    ("o1158394.ingest.us.sentry.io", 224.0),
)


def _traces(jitter: float = 1.0) -> tuple[TraceView, ...]:
    out: list[TraceView] = []
    for host, base in _CORE:
        total = round(base * jitter, 1)
        # cli 出新加坡，desktop 出日本。另外让 www.anthropic.com 在 cli
        # 路径下落到日本 —— 演示"有 Claude 域名没被分流规则覆盖"这一类结论。
        #
        # 这里必须用**真实的 Claude 域名**制造这个分歧：结论计算会把对照组
        # （1.1.1.1）排除掉，拿对照组制造的分歧根本不会被算进去，
        # 那样演示数据就在广告一个它自己产不出的结论。
        if host == "1.1.1.1":
            cli_cc, cli_colo, cli_ip = "JP", "NRT", _DESKTOP_IP
        elif host == "www.anthropic.com":
            cli_cc, cli_colo, cli_ip = "JP", "NRT", _DESKTOP_IP
        else:
            cli_cc, cli_colo, cli_ip = "SG", "SIN", _CLI_IP
        out.append(TraceView(
            target=host, path="cli", ok=True, egress_ip=cli_ip,
            country=cli_cc, colo=cli_colo, http="http/2", tls="TLSv1.3",
            warp="off", peer_ip="192.0.2.10",
            timing=_t(4.0, round(total * 0.16, 1), round(total * 0.2, 1),
                      round(total * 0.62, 1)),
        ))
        out.append(TraceView(
            target=host, path="desktop", ok=True, egress_ip=_DESKTOP_IP,
            country="JP", colo="NRT", http="http/2", tls="TLSv1.3",
            warp="off", peer_ip="127.0.0.1",
            timing=_t(0.4, 96.0, 82.0, round(total * 0.24, 1)),
        ))
    for host, base in _TELEMETRY:
        total = round(base * jitter, 1)
        for path, peer in (("cli", "192.0.2.30"), ("desktop", "127.0.0.1")):
            out.append(TraceView(
                target=host, path=path, ok=True, peer_ip=peer,
                timing=_t(2.0, round(total * 0.4, 1), round(total * 0.6, 1), 0.0),
            ))
    out.sort(key=lambda t: (t.path, t.target))
    return tuple(out)


def _resolves() -> tuple[ResolveView, ...]:
    return (
        ResolveView(
            host="api.anthropic.com", system=("192.0.2.40",),
            doh=("192.0.2.40",), doh_source="cloudflare", kind="real",
            note="本机解析与公网权威一致，是真实地址。",
        ),
        ResolveView(
            host="claude.ai", system=("198.18.0.57",), doh=("192.0.2.41",),
            doh_source="cloudflare", kind="fake-ip",
            note="本机解析出的是 fake-ip 占位地址，说明这个域名交给了本地分流器。",
        ),
        ResolveView(
            host="http-intake.logs.us5.datadoghq.com",
            system=("198.18.0.140",), doh=("192.0.2.42",),
            doh_source="google", kind="fake-ip",
            note="本机解析出的是 fake-ip 占位地址，查这个地址的归属没有意义。",
        ),
        ResolveView(
            host="code.claude.com", system=("192.0.2.43",), doh=("192.0.2.44",),
            doh_source="cloudflare", resolver="192.0.2.254", kind="mismatch",
            note="这个域名被分派给了专用解析器，本机解析结果和公网权威不一致。",
        ),
    )


def _connections() -> tuple[Connection, ...]:
    from .model import AsnInfo
    anthropic = AsnInfo(
        ip="192.0.2.40", asn="AS399358", prefix="192.0.2.0/24", country="US",
        org="ANTHROPIC - Anthropic, PBC, US", city="San Francisco",
        anycast=True, source="cymru+ipinfo",
    )
    out = [
        Connection(
            pid=1001, command="2.1.x", surface="cli", local="192.0.2.9:51234",
            remote_ip="192.0.2.40", remote_port=443, kind="real",
            host="api.anthropic.com", service="api", asn=anthropic,
        )
        for _ in range(7)
    ]
    out += [
        Connection(
            pid=1001, command="2.1.x", surface="cli", local="198.18.0.1:51851",
            remote_ip="198.18.0.140", remote_port=443, kind="fake-ip",
            host="http-intake.logs.us5.datadoghq.com", service="telemetry",
        )
        for _ in range(2)
    ]
    out.append(Connection(
        pid=2002, command="Claude", surface="desktop", local="127.0.0.1:52044",
        remote_ip="127.0.0.1", remote_port=7890, kind="local-proxy",
    ))
    return tuple(out)


def sample(seq: int = 1, jitter: float = 1.0) -> Sample:
    """造一轮演示采样。ts 用调用时刻，其余全部是固定的虚构值。

    jitter 只缩放耗时，让多轮之间的分位数不至于全等 —— 用固定倍数而不是
    随机数，截图才能复现。
    """
    notes = (
        DEMO_NOTICE,
        "6 个域名的出口国家在不同入口之间不一致（cli → SG，desktop → JP）："
        "a-api.anthropic.com、api.anthropic.com、claude.ai、code.claude.com "
        "等 6 个域名。同一台机器上两个入口读的是两份不同的代理配置，"
        "分流结果因此不同。",
        "cli 这条路径下，Claude 的域名落在了 2 个不同国家：JP 有 1 个"
        "（www.anthropic.com）；SG 有 6 个（a-api.anthropic.com、"
        "api.anthropic.com、claude.ai）。分流规则按域名逐条命中，"
        "说明有域名没被规则覆盖到、落到了兜底出口。",
        "有 1 条连接是发给本机代理的，lsof 只能看到「它连了代理」，"
        "真实目的地拿不到。要补上这一段，需要打开分流器的控制接口"
        "（见 docs/03-routing.md）。",
    )
    return Sample(
        ts=time.time(), seq=seq, traces=_traces(jitter), resolves=_resolves(),
        connections=_connections(), notes=notes,
    )


JITTERS: tuple[float, ...] = (0.88, 0.96, 1.0, 1.07, 1.31)


def paths():
    """演示用的路径描述。

    刻意**不用**本机真实发现的路径：那里面有使用者自己的代理端口，
    而演示模式的产物（截图）是要公开的。7890 是 Clash 的默认端口，
    在这里只是一个通用示例值。
    """
    from .paths import SURFACE_CLI, SURFACE_DESKTOP, SURFACE_WEB, Path
    return (
        Path(
            id="cli", label="Claude Code", surfaces=(SURFACE_CLI,), proxy=None,
            source="无代理环境变量 → 直连",
            detail="CLI 直连。若本机开着 TUN / 透明代理，出口由分流规则按 IP "
                   "匹配决定；没有的话就是本地宽带出口。",
        ),
        Path(
            id="desktop", label="Claude 桌面端",
            surfaces=(SURFACE_DESKTOP, SURFACE_WEB), proxy=("127.0.0.1", 7890),
            source="macOS 系统代理（scutil --proxy）",
            detail="桌面端 / 浏览器把流量发给系统代理 127.0.0.1:7890。"
                   "（演示值，不是任何人的真实配置。）",
        ),
    )


def seed(history, sampler=None, count: int = len(JITTERS)) -> int:
    """往 History 里塞几轮演示采样，返回塞了几轮。

    给了 sampler 就顺手把它的路径也换成演示路径，否则界面上「本机的路径」
    那张卡还会显示真实配置，和其余全虚构的数据混在一起。
    """
    for i in range(count):
        history.add(sample(seq=i + 1, jitter=JITTERS[i % len(JITTERS)]))
    if sampler is not None:
        sampler.override_routes(paths())
    return count


__all__ = ["DEMO_NOTICE", "sample"]
