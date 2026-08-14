"""解析真相对照：本机怎么解析 vs 公网权威怎么解析。

为什么需要这一层：在装了 Clash / Surge / sing-box 这类工具（尤其开了
TUN + fake-ip）的机器上，`dig api.anthropic.com` 得到的**不是**真实地址，
而是一个 `198.18.x.x` 的占位地址。占位地址是给分流器认域名用的，
不代表任何真实主机。

后果很直接：
- 你在 `lsof` 里看到进程连的是 `198.18.0.140`，查这个 IP 归属毫无意义；
- 你以为"DNS 查出来在美国所以流量走美国"，其实那条 DNS 结果压根没出网。

所以每个域名都要问两次：本机一次（它决定进程实际连哪）、
DoH 一次（它给出这个域名真实指向哪）。两者不一致 = 本机 DNS 被改写。
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
from typing import Optional

from .model import ResolveView
from .net import timed_get

# fake-ip 常用网段。两家实现的默认值都在这里：
#   Clash / mihomo 默认 198.18.0.1/16（RFC 2544 基准测试保留段）
#   sing-box 默认 198.18.0.0/15 与 fc00::/18
# 这些地址在公网上不可路由，出现在 lsof 里就说明它是占位地址。
FAKE_IP_NETS = (
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("240.0.0.0/4"),
)

DOH_SOURCES = (
    ("cloudflare", "https://cloudflare-dns.com/dns-query?name={host}&type={rr}"),
    ("google", "https://dns.google/resolve?name={host}&type={rr}"),
)


def is_fake_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in FAKE_IP_NETS)


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback or addr.is_link_local) \
        and not is_fake_ip(ip)


def system_resolve(host: str, timeout: float = 4.0) -> tuple[str, ...]:
    """本机 getaddrinfo —— 这就是进程真正会连的地址。"""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen: list[str] = []
        for info in infos:
            ip = str(info[4][0])
            if ip not in seen:
                seen.append(ip)
        return tuple(seen)
    except OSError:
        return ()
    finally:
        socket.setdefaulttimeout(old)


def parse_doh(payload: str) -> tuple[str, ...]:
    """从 DoH JSON 里取 A / AAAA 记录。纯函数。"""
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return ()
    answers = data.get("Answer") or []
    out: list[str] = []
    for ans in answers:
        if ans.get("type") in (1, 28):
            val = str(ans.get("data", "")).strip()
            if val and val not in out:
                out.append(val)
    return tuple(out)


def doh_resolve(
    host: str,
    *,
    rr: str = "A",
    proxy: Optional[tuple[str, int]] = None,
    timeout: float = 6.0,
) -> tuple[tuple[str, ...], Optional[str]]:
    """走 DoH 拿真实解析结果，返回 (地址, 数据源)。

    DoH 的报文是端到端加密的，中间的分流器改不了里面的答案 ——
    这就是它能当"真相"用的原因。它自己那条连接被代理无所谓。
    """
    for name, tmpl in DOH_SOURCES:
        res = timed_get(
            tmpl.format(host=host, rr=rr),
            proxy=proxy,
            timeout=timeout,
            headers={"accept": "application/dns-json"},
        )
        if res.ok:
            got = parse_doh(res.body)
            if got:
                return got, name
    return (), None


_SCUTIL_RESOLVER = re.compile(r"^resolver #(\d+)$")


def parse_scutil_dns(text: str) -> dict[str, str]:
    """解析 `scutil --dns`，得到"哪个域名交给哪台 nameserver"。

    macOS 支持按域名分派解析器（VPN / Tailscale split-DNS / 企业配置都会写）。
    这解释了一类很难查的现象：**同一台机器上两个进程解析同一个域名得到
    不同结果**，因为它们走了不同的解析器路径。

    返回 {域名: 第一个 nameserver}。没有 domain 的解析器不进表。
    """
    out: dict[str, str] = {}
    domain: Optional[str] = None
    nameserver: Optional[str] = None

    def flush() -> None:
        if domain and nameserver:
            out.setdefault(domain, nameserver)

    for raw in text.splitlines():
        line = raw.strip()
        if _SCUTIL_RESOLVER.match(line):
            flush()
            domain, nameserver = None, None
            continue
        if line.startswith("domain "):
            domain = line.split(":", 1)[-1].strip().rstrip(".")
        elif line.startswith("nameserver[0]"):
            nameserver = line.split(":", 1)[-1].strip()
    flush()
    return out


def read_scutil_dns() -> dict[str, str]:
    try:
        text = subprocess.run(
            ["scutil", "--dns"], capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_scutil_dns(text or "")


def resolver_for(host: str, table: dict[str, str]) -> Optional[str]:
    """按最长后缀匹配找这个域名会用的 nameserver。"""
    best: Optional[str] = None
    best_len = -1
    for domain, ns in table.items():
        if host == domain or host.endswith("." + domain):
            if len(domain) > best_len:
                best, best_len = ns, len(domain)
    return best


def classify(system: tuple[str, ...], doh: tuple[str, ...],
             resolver: Optional[str]) -> tuple[str, Optional[str]]:
    """给出解析状态与一句人话解释。纯函数，是这个模块最该被测试的部分。"""
    if not system and not doh:
        return "error", "两侧都解析不出来 —— 可能整条链路不通。"
    if system and any(is_fake_ip(ip) for ip in system):
        return "fake-ip", (
            "本机解析出的是 fake-ip 占位地址，说明这个域名交给了本地分流器"
            "（TUN / 透明代理）。查这个地址的归属没有意义，真实出口要看"
            "目的地那侧看到的源地址。"
        )
    if not doh:
        return "unknown", "DoH 没拿到结果，无法对账，只能相信本机解析。"
    if not system:
        return "error", "本机解析不出来，但 DoH 能 —— 本机 DNS 有问题。"
    if set(system) & set(doh):
        return "real", "本机解析与公网权威一致，是真实地址。"
    extra = ""
    if resolver:
        extra = f"这个域名被分派给了专用解析器 {resolver}，"
    return "mismatch", (
        extra + "本机解析结果和公网权威不一致 —— 本机 DNS 被改写了"
        "（split-DNS、hosts、或代理软件接管）。进程会连本机给出的那个地址。"
    )


def resolve_view(
    host: str,
    *,
    dns_table: Optional[dict[str, str]] = None,
    proxy: Optional[tuple[str, int]] = None,
) -> ResolveView:
    table = dns_table if dns_table is not None else read_scutil_dns()
    system = system_resolve(host)
    doh, source = doh_resolve(host, proxy=proxy)
    if not doh:
        doh6, source6 = doh_resolve(host, rr="AAAA", proxy=proxy)
        doh, source = doh6, source6
    resolver = resolver_for(host, table)
    kind, note = classify(system, doh, resolver)
    return ResolveView(
        host=host,
        system=system,
        doh=doh,
        doh_source=source,
        resolver=resolver,
        kind=kind,
        note=note,
    )


def fake_ip_reverse_map(hosts: tuple[str, ...]) -> dict[str, str]:
    """建 fake-ip → 域名 的反查表。

    fake-ip 有个副作用刚好对我们有用：分流器给**每个域名**分配一个独立的
    占位地址。于是 `lsof` 里看到 `198.18.0.140` 就能反推出它是哪个域名 ——
    在别的环境里这是做不到的（多个域名共用一个 CDN IP）。

    只对已知域名建表，未知地址一律不猜。
    """
    out: dict[str, str] = {}
    for host in hosts:
        for ip in system_resolve(host, timeout=2.0):
            if is_fake_ip(ip):
                out.setdefault(ip, host)
    return out


__all__ = [
    "FAKE_IP_NETS",
    "classify",
    "doh_resolve",
    "fake_ip_reverse_map",
    "is_fake_ip",
    "is_private",
    "parse_doh",
    "parse_scutil_dns",
    "read_scutil_dns",
    "resolve_view",
    "resolver_for",
    "system_resolve",
]
