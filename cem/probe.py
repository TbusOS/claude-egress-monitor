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

from . import endpoints as ep
from . import paths as pathmod
from . import sockets as sockmod
from .asn import AsnCache
from .model import Sample, TraceView
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
    )


def latency_once(host: str, path: pathmod.Path, *, timeout: float = 8.0) -> TraceView:
    """给没有 trace 端点的域名（遥测 intake）只量延迟与可达性。

    刻意不发 HTTP 请求 —— 见 net.tcp_probe 的说明。
    """
    res = tcp_probe(host, 443, proxy=path.proxy, timeout=timeout)
    return TraceView(
        target=host, path=path.id, ok=res.ok, peer_ip=res.peer_ip,
        timing=res.timing, error=res.error,
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


def egress_by_surface(sample: Sample) -> dict[str, dict]:
    """把采样折叠成"每个入口一个结论"，这是 UI 顶部 KPI 要的形状。

    结论取该入口下**业务主干域名**（api / auth 类）里第一个成功的 trace ——
    遥测域名的延迟不代表业务出口。
    """
    core = [
        t for t in sample.traces
        if t.ok and t.egress_ip
        and (ep.classify_host(t.target) or ep.Endpoint("", "", (), "", ())).category
        in (ep.CAT_API, ep.CAT_AUTH)
    ]
    result: dict[str, dict] = {}
    for t in core:
        prev = result.get(t.path)
        if prev is None:
            result = {**result, t.path: {
                "egress_ip": t.egress_ip,
                "country": t.country,
                "colo": t.colo,
                "target": t.target,
                "targets": (t.target,),
            }}
        else:
            result = {**result, t.path: {
                **prev, "targets": prev["targets"] + (t.target,),
            }}
    return result


def disagreements(sample: Sample) -> tuple[str, ...]:
    """找出"同一个域名不同入口出口不同"和"同一入口不同域名出口不同"。

    这两种不一致是这个工具存在的理由，所以它们必须被显式算出来、
    显式说出来，而不是留给读者自己在一屏数字里比对。
    """
    notes: list[str] = []
    by_target: dict[str, dict[str, TraceView]] = {}
    for t in sample.traces:
        if t.ok and t.egress_ip:
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

    by_path: dict[str, set[str]] = {}
    for t in sample.traces:
        if t.ok and t.country:
            endpoint = ep.classify_host(t.target)
            if endpoint and endpoint.category in (ep.CAT_API, ep.CAT_AUTH,
                                                  ep.CAT_CONTENT):
                by_path.setdefault(t.path, set()).add(t.country)
    for path_id, countries in sorted(by_path.items()):
        if len(countries) > 1:
            notes.append(
                f"{path_id} 这条路径下，多个 Claude 域名的出口国家不一致"
                f"（{'、'.join(sorted(countries))}）—— 分流规则按域名逐条命中，"
                f"有域名没被规则覆盖到。"
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

    resolves = ()
    if with_resolve:
        dns_table = read_scutil_dns()
        hosts = tuple(e.host for e in ep.ENDPOINTS if not e.optional)
        resolves = tuple(
            resolve_view(h, dns_table=dns_table) for h in hosts
        )

    connections: tuple = ()
    socket_notes: tuple[str, ...] = ()
    if with_sockets:
        hosts = tuple(e.host for e in ep.ALL)
        fake_map = fake_ip_reverse_map(hosts)
        lookup = (asn_cache.get if asn_cache else None)
        cli_path = pathmod.path_for_surface(routes, pathmod.SURFACE_CLI)
        connections, dropped, via_proxy = sockmod.snapshot(
            fake_map=fake_map,
            asn_lookup=lookup,
            proxy=(cli_path.proxy if cli_path else None),
            endpoint_lookup=ep.classify_host,
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
    )
    notes = disagreements(sample) + socket_notes
    if on_note:
        for n in notes:
            on_note(n)
    return Sample(
        ts=sample.ts, seq=seq, traces=traces, resolves=resolves,
        connections=connections, notes=notes,
    )


__all__ = [
    "disagreements",
    "egress_by_surface",
    "latency_once",
    "parse_trace",
    "run_once",
    "trace_once",
]
