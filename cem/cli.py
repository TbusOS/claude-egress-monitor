"""命令行入口。

四个子命令，各自回答一个问题：

    cem doctor      我这台机器上，三个入口分别走哪条路？
    cem probe       现在这一刻，它们的出口 IP / 地区 / 延迟是什么？
    cem endpoints   Claude 到底会连哪些域名，各自干什么？
    cem serve       把界面端起来，开着看。
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path
from typing import Optional

from . import endpoints as ep
from . import paths as pathmod
from . import probe
from . import view
from .asn import AsnCache
from .model import Sample
from .resolve import read_scutil_dns
from .sampler import DEFAULT_INTERVAL_S, Sampler, SamplerConfig
from .server import build_server
from .store import History

DASH = "—"


def _fmt(value: object, unit: str = "") -> str:
    if value is None or value == "":
        return DASH
    return f"{value}{unit}"


def _asn_cache(cache_dir: Optional[Path]) -> AsnCache:
    path = (cache_dir / "asn-cache.json") if cache_dir else None
    return AsnCache(path)


# ------------------------------------------------------------------ doctor


def cmd_doctor(args: argparse.Namespace) -> int:
    routes = pathmod.discover()
    print("入口 → 路径")
    print("=" * 68)
    for p in routes:
        surfaces = "、".join(pathmod.SURFACE_LABELS.get(s, s) for s in p.surfaces)
        print(f"\n[{p.id}] {p.label}" + (f"（{surfaces}）" if surfaces else ""))
        print(f"  代理    ： {_fmt(f'{p.proxy[0]}:{p.proxy[1]}' if p.proxy else None)}")
        print(f"  配置来源： {p.source}")
        print(f"  含义    ： {p.detail}")

    if len(routes) >= 2 and pathmod.same_route(routes[0], routes[1]):
        print("\n结论：CLI 和桌面端此刻走同一条路径，出口应当一致。")
    else:
        print("\n结论：CLI 和桌面端读的是两份不同的代理配置，"
              "出口**可以**不一致 —— 跑 `cem probe` 量一下。")

    table = read_scutil_dns()
    hits = {
        h: table[d] for h in (e.host for e in ep.ENDPOINTS)
        for d in table if h == d or h.endswith("." + d)
    }
    if hits:
        print("\n专用解析器（这些域名不走默认 DNS）")
        print("-" * 68)
        for host, ns in sorted(hits.items()):
            print(f"  {host:<44} → {ns}")
        print("  注意：专用解析器常常意味着这些域名的流量也走了对应的隧道，"
              "\n  和其他域名不同路。")
    return 0


# ------------------------------------------------------------------ probe


def _print_sample(sample: Sample, routes: tuple[pathmod.Path, ...]) -> None:
    print("出口（目的地那侧看到的你）")
    print("=" * 78)
    for card in view.surface_cards(sample, routes):
        flag = "  ⚠ 受限地区" if card["restricted"] else ""
        print(f"\n{card['label']}（路径 {card['path_id']}）{flag}")
        print(f"  出口 IP ： {_fmt(card['egress_ip'])}")
        region = card["country_label"]
        if card["country"] and region != card["country"]:
            region = f"{region}（{card['country']}）"
        print(f"  地区    ： {_fmt(region)}")
        print(f"  边缘机房： {_fmt(card['colo'])}")
        print(f"  测于    ： {_fmt(card['measured_on'])}")

    print("\n\n逐域名明细")
    print("=" * 78)
    # 出口 IP 放最后一列：IPv6 地址长达 39 字符，放中间会把整张表撑歪。
    print(f"{'域名':<38}{'路径':<9}{'地区':<5}{'耗时':>8}   出口 IP")
    print("-" * 78)
    for row in view.trace_rows(sample):
        total = row["timing"]["total_ms"]
        print(f"{row['target']:<38}{row['path']:<9}{_fmt(row['country']):<5}"
              f"{_fmt(round(total) if total else None):>8}   "
              f"{_fmt(row['egress_ip'])}")
        if row["error"]:
            print(f"{' ' * 38}└ 失败：{row['error']}")

    resolves = view.resolve_rows(sample)
    if resolves:
        print("\n\n解析对账（本机 vs 公网权威）")
        print("=" * 78)
        for row in resolves:
            if row["kind"] == "real":
                continue
            print(f"\n{row['host']}  [{row['kind']}]")
            print(f"  本机   ： {', '.join(row['system']) or DASH}")
            print(f"  权威   ： {', '.join(row['doh']) or DASH}"
                  f"  ({_fmt(row['doh_source'])})")
            if row["resolver"]:
                print(f"  解析器 ： {row['resolver']}")
            print(f"  说明   ： {row['note']}")

    conns = view.connection_rows(sample)
    if conns:
        print("\n\n此刻的连接")
        print("=" * 78)
        for row in conns:
            asn = row["asn"] or {}
            who = row["host"] or asn.get("org") or DASH
            print(f"  [{row['surface']:<7}] {row['remote']:<24} "
                  f"{row['kind']:<12} {who}")

    if sample.notes:
        print("\n\n结论")
        print("=" * 78)
        for note in sample.notes:
            print(f"  ⚠ {note}")


def cmd_probe(args: argparse.Namespace) -> int:
    cache = _asn_cache(Path(args.cache_dir) if args.cache_dir else None)
    routes = pathmod.discover()
    sample = probe.run_once(
        seq=1,
        routes=routes,
        include_optional=args.all,
        include_telemetry=not args.no_telemetry,
        with_resolve=not args.no_dns,
        with_sockets=not args.no_sockets,
        asn_cache=cache,
        timeout=args.timeout,
    )
    if args.json:
        json.dump(sample.to_json(), sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        _print_sample(sample, routes)
    return 0


# --------------------------------------------------------------- endpoints


def cmd_endpoints(args: argparse.Namespace) -> int:
    if args.json:
        json.dump(view.endpoint_payload(), sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
    print(f"Claude 出网域名清单（CLI 取证版本 {ep.CLI_VERSION_SAMPLED}）")
    print("=" * 78)
    for category, label in view.CATEGORY_LABELS.items():
        group = [e for e in ep.ENDPOINTS if e.category == category]
        if not group:
            continue
        print(f"\n## {label}")
        for e in group:
            surfaces = "/".join(e.surfaces)
            tail = "（可选）" if e.optional else ""
            print(f"\n  {e.host}{tail}")
            print(f"    入口： {surfaces}")
            print(f"    用途： {e.purpose}")
            print(f"    证据： {', '.join(e.evidence)}")
            if e.note:
                print(f"    备注： {e.note}")
    return 0


# ------------------------------------------------------------------- serve


def cmd_serve(args: argparse.Namespace) -> int:
    jsonl = Path(args.persist).expanduser() if args.persist else None
    history = History(jsonl_path=jsonl)
    cache = _asn_cache(Path(args.cache_dir) if args.cache_dir else None)
    sampler = Sampler(
        history,
        config=SamplerConfig(
            interval_s=args.interval,
            include_optional=args.all,
            include_telemetry=not args.no_telemetry,
            with_resolve=not args.no_dns,
            with_sockets=not args.no_sockets,
        ),
        asn_cache=cache,
    )
    httpd, sampler, history, _bus = build_server(
        host=args.host, port=args.port, history=history, sampler=sampler,
    )
    if args.demo:
        from . import demo
        rounds = demo.seed(history, sampler)
        print(f"演示： 已注入 {rounds} 轮**虚构**数据（RFC 5737 文档保留地址），"
              f"界面上会标出来")
    url = f"http://{args.host}:{args.port}/"
    print(f"界面： {url}")
    print(f"监控： {'已自动开启' if args.start else '默认关闭 —— 在界面上按开关启动'}")
    if jsonl:
        print(f"落盘： {jsonl}（含真实 IP，注意别提交进仓库）")
    print("Ctrl-C 结束。")
    if args.start:
        sampler.start()
    if args.open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n收到中断，停止采样并关闭服务……")
    finally:
        sampler.stop()
        httpd.shutdown()
        httpd.server_close()
    return 0


# -------------------------------------------------------------------- 装配


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cem",
        description="Claude 出网出口 / 遥测 / 延迟监控（本机运行，数据不外发）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--all", action="store_true",
                        help="连可选域名（MCP 之类）一起探测")
    common.add_argument("--no-telemetry", action="store_true",
                        help="不探测遥测 intake 域名")
    common.add_argument("--no-dns", action="store_true",
                        help="跳过解析对账")
    common.add_argument("--no-sockets", action="store_true",
                        help="跳过实时连接枚举（不调用 lsof）")
    common.add_argument("--cache-dir", default=None,
                        help="ASN 查询缓存目录，不给则只用内存缓存")

    p_doctor = sub.add_parser("doctor", help="看清本机三个入口各走哪条路")
    p_doctor.set_defaults(func=cmd_doctor)

    p_probe = sub.add_parser("probe", parents=[common],
                             help="立刻采一轮并打印")
    p_probe.add_argument("--json", action="store_true", help="输出 JSON")
    p_probe.add_argument("--timeout", type=float, default=8.0)
    p_probe.set_defaults(func=cmd_probe)

    p_ep = sub.add_parser("endpoints", help="打印出网域名清单")
    p_ep.add_argument("--json", action="store_true")
    p_ep.set_defaults(func=cmd_endpoints)

    p_serve = sub.add_parser("serve", parents=[common], help="启动网页界面")
    p_serve.add_argument("--host", default="127.0.0.1",
                         help="监听地址，默认只听回环，不建议改")
    p_serve.add_argument("--port", type=int, default=8787)
    p_serve.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_S,
                         help=f"采样间隔秒数，默认 {DEFAULT_INTERVAL_S}")
    p_serve.add_argument("--start", action="store_true",
                         help="启动后立刻开始监控（默认关闭，等界面上手动开）")
    p_serve.add_argument("--open", action="store_true", help="顺手打开浏览器")
    p_serve.add_argument("--persist", default=None,
                         help="把每轮采样追加到这个 JSONL 文件")
    p_serve.add_argument("--demo", action="store_true",
                         help="注入几轮虚构数据（文档保留地址），用来看界面 / 出截图，"
                              "一个探测都不发")
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


__all__ = ["build_parser", "main"]
