"""环境级检查：和具体域名无关、一轮只需要做一次的那些事实。

每一项都回答一个「排查网络问题时早晚会问到、但很少有人主动查」的问题：

| 检查 | 回答什么 | 查不出来会怎样 |
|---|---|---|
| IPv6 可达性 | 这台机器到底有没有能用的 IPv6 | 出口在 v4/v6 之间跳，却以为是节点在换 |
| 时钟偏移 | 本机时间准不准 | TLS 握手报「证书未生效/已过期」，报错完全不提时间 |
| 证书一致性 | TLS 有没有被中间人拆开 | 企业管控软件、劫持型客户端全都看不见 |
| DoH 交叉验证 | 两个独立权威源的解析是否一致 | 单一 DoH 源被污染时毫无察觉 |
| 出口时区自洽 | 出口所在时区与本机时区差多少 | 风控会拿这个当异常信号，而你不知道自己暴露了 |
| 代理端口存活 | 系统代理配了但进程没起 | 表现为"网全断了"，查半天才发现是代理挂了 |

严重度分级和 diagnose 一致，界面上共用一套颜色。
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Optional

from .model import Check, Sample
from .net import DEFAULT_TIMEOUT, timed_get
from .resolve import parse_doh

SEV_OK = "ok"
SEV_INFO = "info"
SEV_WARN = "warn"
SEV_CRITICAL = "critical"

# 时钟偏移超过这个秒数就该管了。TLS 通常容忍几分钟，
# 但超过 5 分钟很多服务端的签名校验会开始拒绝。
CLOCK_WARN_S = 60
CLOCK_CRITICAL_S = 300

# 公共 CA 白名单。不在这里面**不代表就是劫持**，只代表值得看一眼。
KNOWN_CAS = (
    "let's encrypt", "google trust services", "digicert", "sectigo",
    "amazon", "cloudflare", "globalsign", "isrg", "entrust", "identrust",
    "microsoft", "apple", "ssl corp", "ssl.com", "buypass", "zerossl",
    "actalis", "certum", "gts", "starfield", "go daddy",
)


def check_ipv6(timeout: float = 5.0) -> Check:
    """本机有没有真正可用的 IPv6。

    只做 TCP 连接，不发请求。用 Cloudflare 的 v6 地址当靶子，
    它和 Claude 同在 Cloudflare 上，结论可以直接迁移。
    """
    target = ("2606:4700:4700::1111", 443)
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(target)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        return Check(
            id="ipv6", label="IPv6 可达性", ok=True, value=f"{ms} ms",
            severity=SEV_INFO,
            detail="本机能走 IPv6。出口地址在 v4 和 v6 之间变化时，"
                   "那通常是同一个节点的双栈地址，不是换了节点。",
        )
    except OSError as exc:
        return Check(
            id="ipv6", label="IPv6 可达性", ok=False, value="不可达",
            severity=SEV_INFO,
            detail=f"本机走不通 IPv6（{type(exc).__name__}）。"
                   f"那么所有出口都会是 IPv4，看到的地址变化不会是双栈造成的。",
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def check_clock(sample: Optional[Sample]) -> Optional[Check]:
    """本机时钟和服务端差多少。数据来自各条 trace 里的 ts= 字段。"""
    if sample is None:
        return None
    skews = [t.clock_skew_s for t in sample.traces if t.clock_skew_s is not None]
    if not skews:
        return None
    skews.sort()
    median = skews[len(skews) // 2]
    magnitude = abs(median)
    if magnitude >= CLOCK_CRITICAL_S:
        sev, ok = SEV_CRITICAL, False
        detail = ("偏差已经大到会让 TLS 握手失败（证书「尚未生效」或「已过期」），"
                  "而报错信息完全不会提到时间。先校准系统时间："
                  "系统设置 → 通用 → 日期与时间 → 自动设置。")
    elif magnitude >= CLOCK_WARN_S:
        sev, ok = SEV_WARN, False
        detail = ("偏差偏大。部分签名校验会开始拒绝，"
                  "建议打开系统的自动时间同步。")
    else:
        sev, ok = SEV_OK, True
        detail = "本机时间和服务端一致，不会影响 TLS 与签名校验。"
    return Check(
        id="clock", label="系统时钟偏移", ok=ok,
        value=f"{median:+.2f} 秒", severity=sev, detail=detail,
    )


def check_certificates(sample: Optional[Sample]) -> Optional[Check]:
    """所有 TLS 证书是不是都由公共 CA 签发、且域名对得上。

    这是本工具里唯一一项**安全**检查。中间人拆 TLS 时，
    证书的颁发者会变成一个本地信任的根（企业管控、某些"加速"客户端、
    也包括真正的攻击）。
    """
    if sample is None:
        return None
    infos = [(t.target, t.tls_info) for t in sample.traces if t.tls_info]
    if not infos:
        return None

    suspicious: list[str] = []
    mismatched: list[str] = []
    issuers: dict[str, int] = {}
    for target, info in infos:
        issuer = (info or {}).get("issuer") or "?"
        issuers[issuer] = issuers.get(issuer, 0) + 1
        if not any(ca in issuer.lower() for ca in KNOWN_CAS):
            suspicious.append(f"{target} ← {issuer}")
        if (info or {}).get("san_match") is False:
            mismatched.append(target)

    top = sorted(issuers.items(), key=lambda kv: -kv[1])
    value = "、".join(f"{name}×{n}" for name, n in top[:3])

    if mismatched:
        return Check(
            id="tls-chain", label="TLS 证书", ok=False, value=value,
            severity=SEV_CRITICAL,
            detail=f"这些域名拿到的证书 SAN 对不上：{'、'.join(mismatched[:3])}。"
                   f"正常情况下不该发生 —— 说明中间有东西替换了证书。",
        )
    if suspicious:
        return Check(
            id="tls-chain", label="TLS 证书", ok=False, value=value,
            severity=SEV_WARN,
            detail=f"出现了不在公共 CA 名单里的颁发者：{'；'.join(suspicious[:2])}。"
                   f"常见原因是公司设备管理软件或本地抓包工具在拆 TLS。"
                   f"不在名单里不等于就是劫持，但值得看一眼。",
        )
    return Check(
        id="tls-chain", label="TLS 证书", ok=True, value=value,
        severity=SEV_OK,
        detail="全部由公共 CA 签发且域名匹配，没有中间人拆包的迹象。",
    )


def check_doh_consistency(host: str = "api.anthropic.com",
                          timeout: float = 6.0) -> Optional[Check]:
    """两个独立 DoH 源交叉验证。

    单一权威源被污染时毫无察觉，两个源对不上就说明其中一个不可信。
    """
    sources = (
        ("Cloudflare", f"https://cloudflare-dns.com/dns-query?name={host}&type=A"),
        ("Google", f"https://dns.google/resolve?name={host}&type=A"),
    )
    got: dict[str, tuple[str, ...]] = {}
    for name, url in sources:
        res = timed_get(url, timeout=timeout,
                        headers={"accept": "application/dns-json"})
        if res.ok:
            answers = parse_doh(res.body)
            if answers:
                got[name] = answers
    if len(got) < 2:
        return Check(
            id="doh", label="DNS 交叉验证", ok=False,
            value=f"只有 {len(got)} 个源可用", severity=SEV_INFO,
            detail="拿不到两个独立权威源，无法交叉验证。"
                   "可能是网络限制，也可能是 DoH 被拦。",
        )
    sets = [set(v) for v in got.values()]
    same = bool(sets[0] & sets[1])
    joined = "；".join(f"{k}: {', '.join(v)}" for k, v in got.items())
    return Check(
        id="doh", label="DNS 交叉验证", ok=same,
        value=host, severity=(SEV_OK if same else SEV_WARN),
        detail=(f"两个权威源结果一致（{joined}）。" if same else
                f"两个权威源给出的地址不一致（{joined}）—— "
                f"其中一条 DoH 链路可能被劫持或被改写。"),
    )


def check_proxy_alive(proxy: Optional[tuple[str, int]],
                      timeout: float = 3.0) -> Optional[Check]:
    """系统代理配了，但那个端口上到底有没有进程在听。

    "代理配着但进程挂了"表现为整个网络都不通，而系统设置里看起来
    一切正常 —— 这是最容易查半天的一类故障。
    """
    if not proxy:
        return None
    host, port = proxy
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return Check(
            id="proxy-alive", label="系统代理端口", ok=True,
            value=f"{host}:{port} 在监听", severity=SEV_OK,
            detail="代理进程活着，桌面端和浏览器能用它出网。",
        )
    except OSError as exc:
        return Check(
            id="proxy-alive", label="系统代理端口", ok=False,
            value=f"{host}:{port} 连不上", severity=SEV_CRITICAL,
            detail=f"系统里配了这个代理，但端口上没有进程在听（"
                   f"{type(exc).__name__}）。桌面端和浏览器会整个断网，"
                   f"而系统设置看起来完全正常。先确认代理客户端有没有退出。",
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def check_timezone_fit(sample: Optional[Sample]) -> Optional[Check]:
    """出口所在时区和本机时区差多少。

    风控会拿这个当信号：一个显示在新加坡的出口，配着一台 UTC+8 的机器，
    是自洽的；配一台 UTC-5 的机器就不太自洽。
    这里只报事实，不下判断 —— 是否要改本机时区是使用者自己的决定。
    """
    if sample is None:
        return None
    zones = [
        t.egress_asn.timezone for t in sample.traces
        if t.egress_asn and t.egress_asn.timezone
    ]
    if not zones:
        return None
    exit_tz = max(set(zones), key=zones.count)
    local_off = -time.timezone if not time.daylight else -time.altzone
    local_hours = local_off / 3600.0
    local_name = time.strftime("%Z")
    return Check(
        id="timezone", label="出口时区自洽性", ok=True,
        value=f"出口 {exit_tz} · 本机 {local_name} (UTC{local_hours:+g})",
        severity=SEV_INFO,
        detail="出口所在时区与本机时区。两者差得远时，"
               "带指纹检测的站点可能把它当成异常信号 —— 这里只报事实。",
    )


def check_path_quality(target: str = "claude.ai",
                       *, cycles: int = 3) -> Optional[Check]:
    """路径质量：跳数、端到端丢包、抖动。需要 mtr，没装或没权限就说清楚。

    这一项补的是四段延迟答不了的那个问题：TLS 握手忽快忽慢，
    是距离远还是链路在丢包。
    """
    from . import pathtrace
    if not pathtrace.available():
        return Check(
            id="path", label="路径质量", ok=False, value="未安装 mtr",
            severity=SEV_INFO,
            detail="装了 mtr 之后这里会显示跳数、每跳延迟和端到端丢包 —— "
                   "那是四段延迟答不了的维度（TLS 忽快忽慢是距离远还是丢包）。"
                   "跑 scripts/install-deps.sh 安装。其余功能不受影响。",
        )
    report = pathtrace.trace(target, cycles=cycles)
    if not report.ok:
        return Check(
            id="path", label="路径质量", ok=False, value="跑不起来",
            severity=SEV_INFO, detail=report.error or "未知错误",
        )
    loss = report.end_to_end_loss
    sev = SEV_OK if (loss or 0) < pathtrace.LOSS_WARN_PCT else SEV_WARN
    return Check(
        id="path", label="路径质量", ok=(sev == SEV_OK),
        value=f"{report.hop_count} 跳 · 丢包 {loss}% · 抖动 {report.jitter_ms}ms",
        severity=sev,
        detail=(f"到 {target} 共 {report.hop_count} 跳，终点丢包 {loss}%。"
                "注意：中间跳显示的丢包大多是路由器给 ICMP 限速造成的假象，"
                "只有终点的丢包才算数 —— 看到中间某跳 40% 就去换节点，换了也没用。"),
    )


def run_all(
    sample: Optional[Sample] = None,
    *,
    proxy: Optional[tuple[str, int]] = None,
    with_network: bool = True,
    with_path: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[Check, ...]:
    """跑完所有环境检查。

    `with_network=False` 时只做不额外发包的那几项（时钟、证书、时区），
    它们的数据来自已经采好的 sample。
    """
    out: list[Check] = []
    if with_network:
        out.append(check_ipv6(timeout=min(timeout, 5.0)))
        doh = check_doh_consistency(timeout=timeout)
        if doh:
            out.append(doh)
        alive = check_proxy_alive(proxy)
        if alive:
            out.append(alive)
    # 路径质量单独一个开关：mtr 一次要跑好几秒，不该跟着每轮采样跑。
    if with_path:
        got = check_path_quality()
        if got:
            out.append(got)
    for maker in (check_clock, check_certificates, check_timezone_fit):
        got = maker(sample)
        if got:
            out.append(got)
    order = {SEV_CRITICAL: 0, SEV_WARN: 1, SEV_INFO: 2, SEV_OK: 3}
    out.sort(key=lambda c: (order.get(c.severity, 9), c.id))
    return tuple(out)


__all__ = [
    "CLOCK_CRITICAL_S",
    "CLOCK_WARN_S",
    "KNOWN_CAS",
    "check_certificates",
    "check_clock",
    "check_doh_consistency",
    "check_ipv6",
    "check_path_quality",
    "check_proxy_alive",
    "check_timezone_fit",
    "run_all",
]
