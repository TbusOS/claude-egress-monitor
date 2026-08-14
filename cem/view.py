"""把采样结果整形成界面要的形状。

放在单独一个模块里，是为了让 server.py 只管 HTTP、不管业务，
也让这一层能被离线测试（喂一个构造好的 Sample，断言输出）。

界面上每一个数字都必须能追到 Sample 里的某个字段。
这一层不做任何计算之外的加工，尤其**不为空值编占位数**：
拿不到就是 None，界面显示破折号。
"""

from __future__ import annotations

from typing import Optional

from . import diagnose as dx
from . import endpoints as ep
from . import paths as pathmod
from . import probe
from .model import Sample
from .store import History, egress_changes, latency_stats

CATEGORY_LABELS = {
    ep.CAT_API: "模型 API / 会话",
    ep.CAT_AUTH: "登录鉴权",
    ep.CAT_CONTROL: "特性开关 / 配置",
    ep.CAT_TELEMETRY: "遥测上报",
    ep.CAT_UPDATE: "版本更新",
    ep.CAT_CONTENT: "文档 / 静态资源",
    ep.CAT_MCP: "MCP 代理",
}

# 国家码 → 中文名。只列监控里真会出现的，不做一张世界表。
COUNTRY_ZH = {
    "US": "美国", "SG": "新加坡", "JP": "日本", "HK": "香港", "TW": "台湾",
    "KR": "韩国", "DE": "德国", "GB": "英国", "NL": "荷兰", "FR": "法国",
    "CA": "加拿大", "AU": "澳大利亚", "IN": "印度", "CN": "中国大陆",
    "MY": "马来西亚", "TH": "泰国", "VN": "越南", "ID": "印尼", "PH": "菲律宾",
    "IE": "爱尔兰", "SE": "瑞典", "FI": "芬兰", "CH": "瑞士", "BR": "巴西",
}

# Claude 的服务条款把这些地区列为受限。出口落在这里是**账号风险**，
# 不是"慢一点"。所以它在界面上是一条红色结论，不是一个普通字段。
RESTRICTED_CC = {
    "CN": "中国大陆", "HK": "香港", "MO": "澳门", "RU": "俄罗斯",
    "KP": "朝鲜", "IR": "伊朗", "SY": "叙利亚", "CU": "古巴",
    "BY": "白俄罗斯", "VE": "委内瑞拉",
}


def country_label(cc: Optional[str]) -> Optional[str]:
    if not cc:
        return None
    return COUNTRY_ZH.get(cc.upper(), cc.upper())


def path_payload(routes: tuple[pathmod.Path, ...]) -> list[dict]:
    return [
        {
            "id": p.id,
            "label": p.label,
            "surfaces": list(p.surfaces),
            "surface_labels": [pathmod.SURFACE_LABELS.get(s, s) for s in p.surfaces],
            "proxy": (f"{p.proxy[0]}:{p.proxy[1]}" if p.proxy else None),
            "source": p.source,
            "detail": p.detail,
        }
        for p in routes
    ]


def endpoint_payload() -> list[dict]:
    return [
        {
            "host": e.host,
            "category": e.category,
            "category_label": CATEGORY_LABELS.get(e.category, e.category),
            "surfaces": list(e.surfaces),
            "purpose": e.purpose,
            "evidence": list(e.evidence),
            "probe": e.probe,
            "optional": e.optional,
            "note": e.note,
        }
        for e in ep.ENDPOINTS
    ]


def _asn_payload(info) -> Optional[dict]:
    if info is None:
        return None
    return {
        "asn": info.asn, "org": info.org, "short_org": info.short_org,
        "country": info.country, "country_label": country_label(info.country),
        "city": info.city, "region": info.region, "where": info.where,
        "timezone": info.timezone, "rdns": info.rdns, "prefix": info.prefix,
        "anycast": info.anycast, "source": info.source,
    }


def _address_payload(a: dx.ExitAddress, asn_by_ip: dict) -> dict:
    info = asn_by_ip.get(a.ip)
    return {
        "ip": a.ip,
        "family": a.family,
        "country": a.country,
        "country_label": country_label(a.country),
        "colo": a.colo,
        "asn": a.asn,
        "org": a.org,
        "hosts": list(a.hosts),
        "host_count": len(a.hosts),
        "city": a.city,
        "kind": a.kind,
        "kind_label": dx.KIND_LABEL.get(a.kind, a.kind),
        "kind_evidence": a.kind_evidence,
        "proxy_flagged": a.proxy_flagged,
        "restricted": bool(a.country and a.country.upper() in RESTRICTED_CC),
        "geo": _asn_payload(info),
    }


def surface_cards(sample: Optional[Sample],
                  routes: tuple[pathmod.Path, ...]) -> list[dict]:
    """三个入口各一张卡。

    比早先多给三样东西，都是"国家相同但地址不同"时唯一能区分出口的信息：
    **归属网络（ASN + 运营商）**、**城市**、以及这条路径的**一致性级别**
    （单一出口 / 同节点双栈 / 同网多址 / 跨网 / 跨国）。
    """
    profiles = dx.egress_profile(sample) if sample else {}
    asn_by_ip = {}
    if sample:
        for t in sample.traces:
            if t.egress_ip and t.egress_asn:
                asn_by_ip[t.egress_ip] = t.egress_asn

    cards: list[dict] = []
    for surface in (pathmod.SURFACE_CLI, pathmod.SURFACE_DESKTOP,
                    pathmod.SURFACE_WEB):
        route = pathmod.path_for_surface(routes, surface)
        prof = profiles.get(route.id) if route else None
        primary = prof.primary if prof else None
        info = asn_by_ip.get(primary.ip) if primary else None
        cc = primary.country if primary else None
        cards.append({
            "surface": surface,
            "label": pathmod.SURFACE_LABELS[surface],
            "path_id": route.id if route else None,
            "route_label": route.label if route else None,
            "proxy": (f"{route.proxy[0]}:{route.proxy[1]}"
                      if route and route.proxy else None),
            "route_detail": route.detail if route else None,
            "egress_ip": primary.ip if primary else None,
            "family": primary.family if primary else None,
            "country": cc,
            "country_label": country_label(cc),
            "colo": primary.colo if primary else None,
            "asn": primary.asn if primary else None,
            "org": primary.org if primary else None,
            "geo": _asn_payload(info),
            "measured_on": (prof.primary.hosts[0] if prof and prof.primary
                            and prof.primary.hosts else None),
            "domains": prof.domains if prof else 0,
            "level": prof.level if prof else None,
            "level_label": dx.LEVEL_LABEL.get(prof.level) if prof else None,
            "level_meaning": dx.LEVEL_MEANING.get(prof.level) if prof else None,
            "kind": primary.kind if primary else None,
            "kind_label": (dx.KIND_LABEL.get(primary.kind) if primary else None),
            "kind_meaning": (dx.KIND_MEANING.get(primary.kind) if primary else None),
            "kind_evidence": primary.kind_evidence if primary else None,
            "proxy_flagged": bool(primary and primary.proxy_flagged),
            "city": primary.city if primary else None,
            "addresses": ([_address_payload(a, asn_by_ip) for a in prof.addresses]
                          if prof else []),
            "countries": list(prof.countries) if prof else [],
            "restricted": bool(prof and prof.restricted),
        })
    return cards


def trace_rows(sample: Optional[Sample]) -> list[dict]:
    if not sample:
        return []
    rows: list[dict] = []
    for t in sample.traces:
        endpoint = ep.classify_host(t.target)
        rows.append({
            "target": t.target,
            "path": t.path,
            "ok": t.ok,
            "egress_ip": t.egress_ip,
            "country": t.country,
            "country_label": country_label(t.country),
            "colo": t.colo,
            "http": t.http,
            "tls": t.tls,
            "peer_ip": t.peer_ip,
            "peer_asn": _asn_payload(t.peer_asn),
            "egress_asn": _asn_payload(t.egress_asn),
            "family": t.family,
            "ipv6": t.is_ipv6,
            "tun_shortcut": t.tun_shortcut,
            "clock_skew_s": t.clock_skew_s,
            "cert": t.tls_info,
            "category": endpoint.category if endpoint else None,
            "category_label": (CATEGORY_LABELS.get(endpoint.category)
                               if endpoint else None),
            "probe": endpoint.probe if endpoint else "tcp",
            "timing": {
                "dns_ms": t.timing.dns_ms,
                "tcp_ms": t.timing.tcp_ms,
                "tls_ms": t.timing.tls_ms,
                "ttfb_ms": t.timing.ttfb_ms,
                "total_ms": t.timing.total_ms,
            },
            "error": t.error,
        })
    return rows


def resolve_rows(sample: Optional[Sample]) -> list[dict]:
    if not sample:
        return []
    return [
        {
            "host": r.host,
            "system": list(r.system),
            "doh": list(r.doh),
            "doh_source": r.doh_source,
            "resolver": r.resolver,
            "kind": r.kind,
            "note": r.note,
        }
        for r in sample.resolves
    ]


def connection_rows(sample: Optional[Sample]) -> list[dict]:
    """把连接按 (入口, 目的地) 合并计数。

    Claude Code 对同一个地址会同时开好几条连接（HTTP/2 之外还有流式请求），
    逐条列出来只是把同一行重复五遍。合并之后一行 = 一个目的地，
    `sockets` 列告诉你有几条。
    """
    if not sample:
        return []
    merged: dict[tuple, dict] = {}
    for c in sample.connections:
        key = (c.surface, c.remote_ip, c.remote_port, c.host)
        prev = merged.get(key)
        if prev is not None:
            merged = {**merged, key: {
                **prev,
                "sockets": prev["sockets"] + 1,
                "pids": prev["pids"] + ((c.pid,) if c.pid not in prev["pids"] else ()),
            }}
            continue
        merged = {**merged, key: {
            "pids": (c.pid,),
            "sockets": 1,
            "command": c.command,
            "surface": c.surface,
            "surface_label": pathmod.SURFACE_LABELS.get(c.surface, c.surface),
            "remote": f"{c.remote_ip}:{c.remote_port}",
            "remote_ip": c.remote_ip,
            "kind": c.kind,
            "host": c.host,
            "service": c.service,
            "service_label": CATEGORY_LABELS.get(c.service or "", None),
            "asn": (
                {
                    "asn": c.asn.asn, "org": c.asn.org,
                    "country": c.asn.country,
                    "country_label": country_label(c.asn.country),
                    "city": c.asn.city, "prefix": c.asn.prefix,
                    "anycast": c.asn.anycast, "source": c.asn.source,
                } if c.asn else None
            ),
        }}
    rows = [{**v, "pids": list(v["pids"])} for v in merged.values()]
    rows.sort(key=lambda r: (r["surface"], -r["sockets"], r["host"] or "~"))
    return rows


SEVERITY_LABEL = {
    dx.SEV_CRITICAL: "必须处理",
    dx.SEV_WARN: "该修",
    dx.SEV_INFO: "知道即可",
    dx.SEV_OK: "检查通过",
}


def check_rows(sample: Optional[Sample]) -> list[dict]:
    if not sample:
        return []
    return [
        {
            "id": c.id, "label": c.label, "ok": c.ok, "value": c.value,
            "detail": c.detail, "severity": c.severity,
            "severity_label": SEVERITY_LABEL.get(c.severity, c.severity),
        }
        for c in sample.checks
    ]


def finding_rows(sample: Optional[Sample],
                 samples: tuple[Sample, ...] = ()) -> list[dict]:
    """诊断条目。每条都带判据、成因、可执行的下一步。"""
    return [
        {
            "id": f.id, "severity": f.severity,
            "severity_label": SEVERITY_LABEL.get(f.severity, f.severity),
            "title": f.title, "evidence": f.evidence,
            "cause": f.cause, "fix": f.fix, "docs": f.docs,
        }
        for f in dx.diagnose(sample, samples)
    ]


def stability_rows(samples: tuple[Sample, ...],
                   routes: tuple[pathmod.Path, ...]) -> list[dict]:
    out = []
    for route in routes:
        st = dx.stability(samples, route.id)
        if not st.rounds:
            continue
        out.append({
            "path": route.id, "path_label": route.label,
            "rounds": st.rounds,
            "ips": list(st.ips), "networks": list(st.networks),
            "countries": [country_label(c) or c for c in st.countries],
            "country_codes": list(st.countries),
            "ip_changes": st.ip_changes,
            "network_changes": st.network_changes,
            "country_changes": st.country_changes,
            "stable": st.stable,
            "drift_rate": st.drift_rate,
        })
    return out


def telemetry_payload() -> dict:
    """遥测字段的静态提取结果。见 cem/telemetry.py 的边界说明。"""
    from . import telemetry as tele
    return tele.to_json(tele.inspect())


def day_payload(store) -> dict:
    """历史看板的目录：有哪些天、各占多大。"""
    if store is None or not store.enabled:
        return {"enabled": False, "days": [], "total_bytes": 0}
    days = []
    total = 0
    for day in store.days():
        summary = store.summary(day) or {}
        size = summary.get("size_bytes", 0)
        total += size
        days.append({
            "day": day,
            "rounds": summary.get("rounds", 0),
            "size_bytes": size,
            "hours_covered": summary.get("hours_covered", 0),
            "changes": summary.get("changes", 0),
            "country_changes": summary.get("country_changes", 0),
            "countries": summary.get("countries", [])[:4],
            "p50": (summary.get("latency") or {}).get("p50"),
            "severity": summary.get("severity", {}),
        })
    return {"enabled": True, "days": days, "total_bytes": total,
            "root": str(store.root) if store.root else None}


def latency_panel(history: History,
                  routes: tuple[pathmod.Path, ...],
                  *,
                  window: int = 120) -> list[dict]:
    """延迟面板：每个主干域名 × 每条路径的 p50 / p95。

    只统计业务主干和遥测，不统计文档站 —— 文档站慢不影响使用。
    """
    samples = history.recent(window)
    wanted = [e for e in ep.ENDPOINTS
              if e.category in (ep.CAT_API, ep.CAT_TELEMETRY, ep.CAT_CONTROL)
              and not e.optional]
    out: list[dict] = []
    for e in wanted:
        for route in routes:
            stats = latency_stats(samples, e.host, route.id)
            if not stats["n"]:
                continue
            out.append({
                "host": e.host,
                "category": e.category,
                "category_label": CATEGORY_LABELS.get(e.category, e.category),
                "path": route.id,
                "path_label": route.label,
                **stats,
            })
    return out


def change_log(history: History, routes: tuple[pathmod.Path, ...],
               *, window: int = 720) -> list[dict]:
    samples = history.recent(window)
    out: list[dict] = []
    for route in routes:
        for evt in egress_changes(samples, route.id):
            out.append({
                "ts": evt["ts"],
                "path": route.id,
                "path_label": route.label,
                "egress_ip": evt["egress_ip"],
                "country": evt["country"],
                "country_label": country_label(evt["country"]),
                "first": evt["first"],
            })
    out.sort(key=lambda r: -r["ts"])
    return out[:40]


def snapshot(history: History, sampler, day_store=None) -> dict:
    """UI 一次拉取要的全部内容。"""
    sample = history.latest()
    routes = sampler.routes
    return {
        "status": sampler.status(),
        "rounds": history.size(),
        "ts": sample.ts if sample else None,
        "paths": path_payload(routes),
        "surfaces": surface_cards(sample, routes),
        "traces": trace_rows(sample),
        "resolves": resolve_rows(sample),
        "connections": connection_rows(sample),
        "latency": latency_panel(history, routes),
        "changes": change_log(history, routes),
        "notes": list(sample.notes) if sample else [],
        "checks": check_rows(sample),
        "findings": finding_rows(sample, history.recent(240)),
        "stability": stability_rows(history.recent(240), routes),
        "severity": dx.summary(dx.diagnose(sample, history.recent(240)))
                    if sample else {},
        "endpoints": endpoint_payload(),
        "history": day_payload(day_store),
        "meta": {
            "cli_sampled": ep.CLI_VERSION_SAMPLED,
            "desktop_sampled": ep.DESKTOP_SAMPLED,
        },
    }


__all__ = [
    "CATEGORY_LABELS",
    "SEVERITY_LABEL",
    "check_rows",
    "day_payload",
    "telemetry_payload",
    "finding_rows",
    "stability_rows",
    "COUNTRY_ZH",
    "RESTRICTED_CC",
    "change_log",
    "connection_rows",
    "country_label",
    "endpoint_payload",
    "latency_panel",
    "path_payload",
    "resolve_rows",
    "snapshot",
    "surface_cards",
    "trace_rows",
]
