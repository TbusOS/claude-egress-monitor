"""把各个探测拼成一轮完整采样。

一轮采样回答四个问题：

1. **出口** —— 每个入口（CLI / 桌面端 / 浏览器）在每个关键域名上，
   目的地那侧看到的源地址是什么、落在哪个国家、走的哪个边缘机房。
2. **解析** —— 本机对这些域名的解析和公网权威是否一致。
3. **延迟** —— DNS / TCP / TLS / 首字节四段分别多少。
4. **连接** —— 此刻 Claude 的进程实际连着谁。

顺序是有意的：先出口再解析再连接。出口是结论，其余两项是解释出口
为什么是这样的证据链。
"""

from __future__ import annotations

import concurrent.futures as futures
import time
from typing import Callable, Optional

from . import checks as checkmod
from . import endpoints as ep
from . import paths as pathmod
from . import sockets as sockmod
from .asn import AsnCache
from .model import Sample, TraceView, replace
from .net import tcp_probe, timed_get

TRACE_PATH = "/cdn-cgi/trace"
MAX_WORKERS = 8


def parse_trace(text: str) -> dict[str, str]:
    """解析 Cloudflare 的 `cdn-cgi/trace`：纯文本 key=value，一行一个。

    这个端点是 Cloudflare 在**每个**挂在它上面的站点下都提供的，
    所以问 claude.ai 和问 1.1.1.1 用的是同一套字段 —— 这正是它能
    当"跨站点出口对照"用的原因。
    """
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        key, sep, val = line.partition("=")
        if sep:
            out[key.strip()] = val.strip()
    return out


def trace_once(
    host: str,
    path: pathmod.Path,
    *,
    timeout: float = 8.0,
) -> TraceView:
    res = timed_get(
        f"https://{host}{TRACE_PATH}",
        proxy=path.proxy,
        timeout=timeout,
    )
    if not res.ok:
        return TraceView(
            target=host, path=path.id, ok=False,
            peer_ip=res.peer_ip, timing=res.timing,
            error=res.error or f"HTTP {res.status}",
        )
    fields = parse_trace(res.body)
    if "ip" not in fields:
        return TraceView(
            target=host, path=path.id, ok=False,
            peer_ip=res.peer_ip, timing=res.timing,
            error="响应里没有 ip= 字段，这个域名可能不在 Cloudflare 上了",
        )
    # trace 里的 ts= 是服务端时间。和本机对一下就得到时钟偏移 ——
    # 这件事值得查：本机时钟差太多会直接让 TLS 握手失败（证书"尚未生效"
    # 或"已过期"），而报错信息完全不会提到时间。
    skew = None
    try:
        skew = round(time.time() - float(fields.get("ts", "")), 2)
    except (TypeError, ValueError):
        skew = None
    return TraceView(
        target=host,
        path=path.id,
        ok=True,
        egress_ip=fields.get("ip"),
        country=(fields.get("loc") or "").upper() or None,
        colo=fields.get("colo"),
        http=fields.get("http"),
        tls=fields.get("tls"),
        warp=fields.get("warp"),
        peer_ip=res.peer_ip,
        timing=res.timing,
        tls_info=(vars(res.tls) if res.tls else None),
        clock_skew_s=skew,
    )


def latency_once(host: str, path: pathmod.Path, *, timeout: float = 8.0) -> TraceView:
    """给没有 trace 端点的域名（遥测 intake）只量延迟与可达性。

    刻意不发 HTTP 请求 —— 见 net.tcp_probe 的说明。
    """
    res = tcp_probe(host, 443, proxy=path.proxy, timeout=timeout)
    return TraceView(
        target=host, path=path.id, ok=res.ok, peer_ip=res.peer_ip,
        timing=res.timing, error=res.error,
        tls_info=(vars(res.tls) if res.tls else None),
    )


def resolved_reverse_map(resolves) -> dict[str, str]:
    """用解析对账的结果建「真实 IP → 域名」反查表。

    早先只用 fake-ip 建表，于是**真实地址**的连接一律显示不出域名 ——
    而那恰恰是业务主干那几条（连到 Anthropic 自有 anycast 的那些）。
    界面上就变成"知道是 Anthropic 的网络，但不知道是哪个域名"。

    Anthropic 把多个域名放在同一个 anycast 地址上，所以一个 IP 会对应
    多个域名。这种情况全部列出，用 `、` 连接 —— 因为**确实分不清**，
    随便挑一个显示就是在编。
    """
    by_ip: dict[str, list[str]] = {}
    for view_ in resolves:
        for ip in view_.system:
            hosts = by_ip.setdefault(ip, [])
            if view_.host not in hosts:
                hosts.append(view_.host)
    return {ip: "、".join(sorted(hosts)) for ip, hosts in by_ip.items()}


def enrich_traces(
    traces: tuple[TraceView, ...],
    asn_cache: Optional[AsnCache],
) -> tuple[TraceView, ...]:
    """给每条 trace 补上「出口地址属于谁的网络」。

    这是最重要的一块补充信息：出口 IP 变了，可能只是同一家运营商的
    v4/v6 两个地址（那没事），也可能换了另一个 ASN（那是真的换了节点）。
    只看 IP 字符串区分不了这两种，看 ASN 就能。

    按 IP 去重再查，一轮里十几个域名往往共用两三个出口。
    """
    if asn_cache is None:
        return traces
    wanted = {t.egress_ip for t in traces if t.egress_ip}
    wanted |= {t.peer_ip for t in traces if t.peer_ip}
    table: dict[str, object] = {}
    for ip in sorted(wanted):
        info = asn_cache.get(ip)
        if info is not None:
            table[ip] = info
    return tuple(
        replace(
            t,
            egress_asn=table.get(t.egress_ip) if t.egress_ip else None,
            peer_asn=table.get(t.peer_ip) if t.peer_ip else None,
        )
        for t in traces
    )


def _collect_traces(
    targets: tuple[ep.Endpoint, ...],
    routes: tuple[pathmod.Path, ...],
    timeout: float,
) -> tuple[TraceView, ...]:
    jobs: list[tuple[ep.Endpoint, pathmod.Path]] = [
        (e, p) for p in routes for e in targets
    ]
    out: list[TraceView] = []
    with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = {
            pool.submit(
                trace_once if e.probe == "cf-trace" else latency_once,
                e.host, p, timeout=timeout,
            ): (e, p)
            for e, p in jobs
        }
        for fut in futures.as_completed(futs):
            try:
                out.append(fut.result())
            except Exception as exc:                    # noqa: BLE001
                e, p = futs[fut]
                out.append(TraceView(target=e.host, path=p.id, ok=False,
                                     error=f"{type(exc).__name__}: {exc}"))
    out.sort(key=lambda t: (t.path, t.target))
    return tuple(out)


def claude_traces(sample: Sample, path_id: Optional[str] = None) -> tuple[TraceView, ...]:
    """只取「代表 Claude 业务出口」的那些 trace。

    排除两类：**对照组**（1.1.1.1 —— 它不属于 Claude，走默认路由是正常的）
    和**遥测域名**（它们没有出口 IP，而且遥测走哪儿是另一个问题）。

    这个过滤器是所有结论计算的入口。早先各处各自 inline 判断类别，
    结果对照组被算进了「同一路径下出口不一致」，产生一条会让人去改
    一份本来没问题的分流规则的假警报。
    """
    hosts = set(ep.claude_egress_hosts())
    return tuple(
        t for t in sample.traces
        if t.target in hosts
        and t.ok and t.egress_ip
        and (path_id is None or t.path == path_id)
    )


def egress_by_surface(sample: Sample) -> dict[str, dict]:
    """每条路径的出口画像。

    **不再只给一个 IP**：同一条路径下不同域名可以落在不同出口，
    只报第一个会把这件事藏起来。这里报出口集合，并显式标出
    这条路径内部是否一致。
    """
    result: dict[str, dict] = {}
    by_path: dict[str, list[TraceView]] = {}
    for t in claude_traces(sample):
        by_path.setdefault(t.path, []).append(t)

    for path_id, traces in by_path.items():
        by_ip: dict[str, list[str]] = {}
        for t in traces:
            by_ip.setdefault(t.egress_ip, []).append(t.target)
        # 主出口 = 覆盖域名最多的那个，并列时取域名字典序最小的，保证稳定
        primary_ip = sorted(by_ip, key=lambda ip: (-len(by_ip[ip]), ip))[0]
        primary = [t for t in traces if t.egress_ip == primary_ip][0]
        countries = sorted({t.country for t in traces if t.country})
        result = {**result, path_id: {
            "egress_ip": primary.egress_ip,
            "country": primary.country,
            "colo": primary.colo,
            "target": primary.target,
            "targets": tuple(sorted(by_ip[primary_ip])),
            "egress_ips": tuple(sorted(by_ip, key=lambda ip: (-len(by_ip[ip]), ip))),
            "ip_targets": {ip: tuple(sorted(hosts)) for ip, hosts in by_ip.items()},
            "countries": tuple(countries),
            "consistent": len(by_ip) == 1,
            "domains": len(traces),
        }}
    return result


def disagreements(sample: Sample) -> tuple[str, ...]:
    """找出"同一个域名不同入口出口不同"和"同一入口不同域名出口不同"。

    这两种不一致是这个工具存在的理由，所以它们必须被显式算出来、
    显式说出来，而不是留给读者自己在一屏数字里比对。
    """
    notes: list[str] = []
    by_target: dict[str, dict[str, TraceView]] = {}
    for t in claude_traces(sample):
        by_target.setdefault(t.target, {})[t.path] = t

    # 把"这个域名两个入口出口不一致"按**出口组合**归并成一条。
    # 逐域名各写一条的话，同一个结论会以几乎相同的句子重复六七遍，
    # 读者会开始跳过整块内容 —— 而这块正是唯一需要动手的地方。
    grouped: dict[tuple, list[str]] = {}
    for target, per_path in sorted(by_target.items()):
        countries = {v.country for v in per_path.values() if v.country}
        if len(countries) <= 1:
            continue
        signature = tuple(
            (k, v.country) for k, v in sorted(per_path.items()) if v.country
        )
        grouped.setdefault(signature, []).append(target)

    for signature, targets in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        detail = "，".join(f"{path} → {cc}" for path, cc in signature)
        shown = "、".join(targets[:4])
        more = f" 等 {len(targets)} 个域名" if len(targets) > 4 else ""
        notes.append(
            f"{len(targets)} 个域名的出口国家在不同入口之间不一致（{detail}）："
            f"{shown}{more}。同一台机器上两个入口读的是两份不同的代理配置，"
            f"分流结果因此不同。"
        )

    # 同一条路径内部的不一致。只看 Claude 自己的域名 —— 对照组走默认路由
    # 是正常的，把它算进来会产生假警报。
    by_path: dict[str, dict[str, list[str]]] = {}
    for t in claude_traces(sample):
        if t.country:
            by_path.setdefault(t.path, {}).setdefault(t.country, []).append(t.target)
    for path_id, per_cc in sorted(by_path.items()):
        if len(per_cc) > 1:
            detail = "；".join(
                f"{cc} 有 {len(hosts)} 个（{'、'.join(sorted(hosts)[:3])}）"
                for cc, hosts in sorted(per_cc.items())
            )
            notes.append(
                f"{path_id} 这条路径下，Claude 的域名落在了 {len(per_cc)} 个"
                f"不同国家：{detail}。分流规则按域名逐条命中，说明有域名"
                f"没被规则覆盖到、落到了兜底出口。"
            )
    return tuple(notes)


def run_once(
    *,
    seq: int = 0,
    routes: Optional[tuple[pathmod.Path, ...]] = None,
    include_optional: bool = False,
    include_telemetry: bool = True,
    with_resolve: bool = True,
    with_sockets: bool = True,
    with_checks: bool = True,
    with_path: bool = False,
    asn_cache: Optional[AsnCache] = None,
    timeout: float = 8.0,
    on_note: Optional[Callable[[str], None]] = None,
) -> Sample:
    from .resolve import fake_ip_reverse_map, read_scutil_dns, resolve_view

    routes = routes or pathmod.discover()
    targets = list(ep.trace_capable(include_optional=include_optional))
    if include_telemetry:
        targets += [e for e in ep.ENDPOINTS
                    if e.category == ep.CAT_TELEMETRY]
    traces = _collect_traces(tuple(targets), routes, timeout)

    traces = enrich_traces(traces, asn_cache)

    resolves = ()
    if with_resolve:
        dns_table = read_scutil_dns()
        hosts = tuple(e.host for e in ep.ENDPOINTS if not e.optional)
        resolves = tuple(
            resolve_view(h, dns_table=dns_table) for h in hosts
        )

    # 进程数总是要数的（出口卡要用），即使跳过了连接枚举。
    surface_pids = sockmod.discover_surface_pids()
    process_counts = tuple(sorted(
        (surface, sum(1 for _p, s_ in surface_pids.items() if s_ == surface))
        for surface in (pathmod.SURFACE_CLI, pathmod.SURFACE_DESKTOP,
                        pathmod.SURFACE_WEB)
    ))

    connections: tuple = ()
    socket_notes: tuple[str, ...] = ()
    if with_sockets:
        hosts = tuple(e.host for e in ep.ALL)
        fake_map = fake_ip_reverse_map(hosts)
        fake_map = {**resolved_reverse_map(resolves), **fake_map}
        lookup = (asn_cache.get if asn_cache else None)
        cli_path = pathmod.path_for_surface(routes, pathmod.SURFACE_CLI)
        connections, dropped, via_proxy = sockmod.snapshot(
            fake_map=fake_map,
            asn_lookup=lookup,
            proxy=(cli_path.proxy if cli_path else None),
            endpoint_lookup=ep.classify_host,
            surfaces=surface_pids,
        )
        if via_proxy:
            socket_notes = socket_notes + (
                f"有 {via_proxy} 条连接是发给本机代理的，lsof 只能看到「它连了"
                f"代理」，真实目的地拿不到。要补上这一段，需要打开分流器的"
                f"控制接口（见 docs/03-routing.md）。",
            )
        if dropped:
            socket_notes = socket_notes + (
                f"浏览器还有 {dropped} 条连接无法归属到 Claude，已按隐私原则"
                f"不列出、不落盘。",
            )

    sample = Sample(
        ts=time.time(),
        seq=seq,
        traces=traces,
        resolves=resolves,
        connections=connections,
        processes=process_counts,
    )

    # 环境级检查放在最后：时钟、证书、时区都要读已经采好的 trace。
    cli_path = pathmod.path_for_surface(routes, pathmod.SURFACE_CLI)
    desktop_path = pathmod.path_for_surface(routes, pathmod.SURFACE_DESKTOP)
    checks = checkmod.run_all(
        sample,
        proxy=(desktop_path.proxy if desktop_path else
               (cli_path.proxy if cli_path else None)),
        with_network=with_checks,
        with_path=with_path,
        timeout=timeout,
    )

    notes = disagreements(sample) + socket_notes
    if on_note:
        for n in notes:
            on_note(n)
    return Sample(
        ts=sample.ts, seq=seq, traces=traces, resolves=resolves,
        connections=connections, processes=process_counts,
        checks=checks, notes=notes,
    )


__all__ = [
    "disagreements",
    "egress_by_surface",
    "latency_once",
    "parse_trace",
    "run_once",
    "trace_once",
]
