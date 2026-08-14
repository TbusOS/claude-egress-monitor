"""RDAP 查询：从 RIR 官方拿一个地址段的注册信息。

## 它是什么

RDAP（RFC 7482/7483）是 WHOIS 的继任者：**同样是注册局的官方数据，
但返回结构化 JSON 而不是自由文本**。五个 RIR（APNIC / ARIN / RIPE /
LACNIC / AFRINIC）都提供，免费、无 key、无速率限制。

## 为什么值得单独查

前面几个源回答的是"这个地址属于谁的网络"（ASN）和"第三方觉得它是什么"
（hosting 标志）。RDAP 补的是**注册时写下的事实**：

| 字段 | 能说明什么 |
|---|---|
| `name` | 网段名。企业专线常带公司名，住宅池常写 `BROADBAND` / `POOL` / `DYNAMIC` |
| `type` | 分配类型。`ALLOCATED NON-PORTABLE` 多是运营商分给客户的段 |
| `remarks` | 注册时的备注，有时直接写用途 |
| `entities` | 联系人角色（abuse / technical），能看出是谁在管这个段 |

这些是**分配时登记的**，比第三方推断硬一档 —— 但仍然不是"确证"：
登记信息可能陈旧，`name` 的命名习惯各家不同，没有统一规范。
所以这里给出的线索只提升到「较可能」，不会声称确证。

## 局限（写在前面）

- **不同 RIR 的字段习惯不一样**，同一个 `type` 值在 APNIC 和 ARIN 下
  含义未必对齐。所以这里只做关键词匹配，不做跨 RIR 的语义归一。
- 查询要按地址所属 RIR 选 endpoint，用 IANA 官方的 bootstrap 表定位。
  **不能靠"挨个试"**：RIR 对不归自己管的段返回的是**占位记录**而不是
  404，看起来完全像一条有效答案。拿 APNIC 查一个美国地址会得到
  `IANA-NETBLOCK-34`，照单全收就等于给出了错误的注册信息。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from .net import timed_get

# IANA 官方的 RDAP bootstrap 表：哪个前缀归哪个 RIR 管，权威且免费。
# 不用它的话只能挨个 RIR 试，而**试错会拿到错误答案** —— 见 _is_placeholder。
BOOTSTRAP_V4 = "https://data.iana.org/rdap/ipv4.json"
BOOTSTRAP_V6 = "https://data.iana.org/rdap/ipv6.json"

# bootstrap 拿不到时的兜底顺序。
RDAP_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("apnic", "https://rdap.apnic.net/ip/{ip}"),
    ("arin", "https://rdap.arin.net/registry/ip/{ip}"),
    ("ripe", "https://rdap.db.ripe.net/ip/{ip}"),
    ("lacnic", "https://rdap.lacnic.net/rdap/ip/{ip}"),
    ("afrinic", "https://rdap.afrinic.net/rdap/ip/{ip}"),
)

# 网段名 / 备注里出现这些词，说明是住宅或动态池。
# 只当**线索**用 —— 命名习惯各家不同，没有统一规范。
HOME_WORDS = ("broadband", "residential", "dynamic", "pool", "dialup",
              "dsl", "adsl", "ftth", "fttx", "cable", "consumer", "home",
              "pppoe", "subscriber")

# 出现这些词说明是机房 / 托管。
DC_WORDS = ("hosting", "datacenter", "data center", "server", "cloud",
            "colocation", "colo", "vps", "dedicated", "idc")


# RIR 对**不归自己管**的段会返回一条占位记录，而不是 404。
# APNIC 查一个美国地址会回 `IANA-NETBLOCK-34` +「This network range is
# not allocated to APNIC」—— 有 name 有 type，看起来完全像一条有效答案。
# 早先按"有 name 就算成功"判定，于是美国地址拿到了 APNIC 的占位数据。
# 一个看起来正常的错误答案比报错糟糕得多。
PLACEHOLDER_NAMES = ("iana-netblock", "erx-netblock", "ianablk",
                     "iana-reserved", "non-arin", "iana-v4")
PLACEHOLDER_REMARKS = ("not allocated to", "not managed by",
                       "early registration addresses",
                       "this range is not", "please query")


def _is_placeholder(info: "RdapInfo") -> bool:
    name = (info.name or "").lower()
    if any(w in name for w in PLACEHOLDER_NAMES):
        return True
    blob = " ".join(info.remarks).lower()
    return any(w in blob for w in PLACEHOLDER_REMARKS)


@dataclass(frozen=True)
class RdapInfo:
    ip: str
    registry: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    country: Optional[str] = None
    handle: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    remarks: tuple[str, ...] = ()
    abuse_contact: Optional[str] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        """有实质内容，且不是"这段不归我管"的占位记录。"""
        if not (self.name or self.type or self.handle):
            return False
        return not _is_placeholder(self)

    @property
    def blob(self) -> str:
        """把可用于关键词匹配的文本拼一起。"""
        return " ".join(filter(None, [self.name, self.type, *self.remarks])).lower()

    @property
    def hint(self) -> Optional[str]:
        """从注册信息里读出的用途线索。判不出来返回 None —— 不猜。"""
        blob = self.blob
        if not blob:
            return None
        if any(w in blob for w in DC_WORDS):
            return "datacenter"
        if any(w in blob for w in HOME_WORDS):
            return "residential-ish"
        return None

    @property
    def hint_evidence(self) -> Optional[str]:
        hit = self.hint
        if not hit:
            return None
        words = DC_WORDS if hit == "datacenter" else HOME_WORDS
        matched = [w for w in words if w in self.blob]
        return (f"RDAP 注册信息（{self.registry or '?'}）里出现 "
                f"{'、'.join(matched[:3])}；网段名 {self.name or '—'}，"
                f"类型 {self.type or '—'}")


def parse_rdap(payload: str, ip: str, registry: str) -> RdapInfo:
    """解析 RDAP 响应。纯函数。

    各 RIR 的字段有出入，所以逐个防御性读取；缺字段降级成 None
    而不是抛异常。
    """
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return RdapInfo(ip=ip, registry=registry, error="返回的不是 JSON")
    if not isinstance(data, dict):
        return RdapInfo(ip=ip, registry=registry, error="返回结构不对")

    remarks: list[str] = []
    for r in (data.get("remarks") or []):
        if isinstance(r, dict):
            for line in (r.get("description") or []):
                if isinstance(line, str) and line.strip():
                    remarks.append(line.strip())

    abuse = None
    for ent in (data.get("entities") or []):
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles") or []
        if "abuse" in roles:
            abuse = ent.get("handle")
            break

    return RdapInfo(
        ip=ip,
        registry=registry,
        name=data.get("name"),
        type=data.get("type"),
        country=data.get("country"),
        handle=data.get("handle"),
        start=data.get("startAddress"),
        end=data.get("endAddress"),
        remarks=tuple(remarks[:6]),
        abuse_contact=abuse,
    )


_IP_OK = re.compile(r"^[0-9a-fA-F:.]{3,45}$")


_bootstrap_cache: dict[int, tuple[tuple[object, str], ...]] = {}


def load_bootstrap(version: int = 4, *, timeout: float = 12.0,
                   proxy: Optional[tuple[str, int]] = None):
    """拉 IANA 的 bootstrap 表：前缀 → 该 RIR 的 RDAP 服务地址。

    进程内缓存。拿不到就返回空，调用方退回"挨个试"。
    """
    import ipaddress
    if version in _bootstrap_cache:
        return _bootstrap_cache[version]
    url = BOOTSTRAP_V4 if version == 4 else BOOTSTRAP_V6
    res = timed_get(url, timeout=timeout, proxy=proxy)
    if not res.ok:
        return ()
    try:
        data = json.loads(res.body)
    except (ValueError, TypeError):
        return ()
    out = []
    for entry in (data.get("services") or []):
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        prefixes, servers = entry[0], entry[1]
        base = next((s for s in servers if str(s).startswith("https")), None)
        if not base:
            continue
        for prefix in prefixes:
            try:
                out.append((ipaddress.ip_network(prefix, strict=False), base))
            except ValueError:
                continue
    got = tuple(out)
    _bootstrap_cache[version] = got
    return got


def endpoint_for(ip: str, *, proxy: Optional[tuple[str, int]] = None
                 ) -> Optional[tuple[str, str]]:
    """用 bootstrap 找该查哪个 RIR。返回 (registry 名, URL 模板)。"""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    table = load_bootstrap(addr.version, proxy=proxy)
    for net, base in table:
        if addr in net:
            # 从 rdap.arin.net / rdap.db.ripe.net 里取出 RIR 名。
            # 直接取第一段会拿到 "rdap"，所以挑第一个像 RIR 名的标签。
            labels = base.split("//", 1)[-1].split("/")[0].split(".")
            known = ("arin", "apnic", "ripe", "lacnic", "afrinic")
            name = next((l for l in labels if l in known),
                        next((l for l in labels if l not in ("rdap", "db",
                                                             "www")), "rir"))
            return (name, base.rstrip("/") + "/ip/{ip}")
    return None


def lookup(ip: str, *, timeout: float = 8.0,
           proxy: Optional[tuple[str, int]] = None) -> RdapInfo:
    """查一个地址的注册信息。

    先用 IANA bootstrap 定位正确的 RIR；拿不到 bootstrap 才挨个试。
    挨个试是有代价的：RIR 对不归自己管的段会返回占位记录而不是 404，
    所以必须配合 _is_placeholder 才不会拿到错误答案。

    IP 先做格式校验：它会被拼进 URL，不校验等于把这个函数变成一个
    任意 URL 请求器。
    """
    if not _IP_OK.match(ip or ""):
        return RdapInfo(ip=ip, error="地址格式不合法")

    candidates = list(RDAP_ENDPOINTS)
    routed = endpoint_for(ip, proxy=proxy)
    if routed:
        candidates = [routed] + [c for c in candidates if c[1] != routed[1]]

    last_error = None
    for registry, template in candidates:
        res = timed_get(template.format(ip=ip), timeout=timeout, proxy=proxy,
                        headers={"accept": "application/rdap+json"})
        if not res.ok:
            last_error = f"{registry}: {res.error or res.status}"
            continue
        info = parse_rdap(res.body, ip, registry)
        if info.ok:
            return info
        last_error = (f"{registry}: "
                      + ("这个段不归它管（占位记录）" if _is_placeholder(info)
                         else (info.error or "没有可用字段")))
    return RdapInfo(ip=ip, error=last_error or "所有 RIR 都没有结果")


def to_json(info: RdapInfo) -> dict:
    return {
        "ip": info.ip, "registry": info.registry, "name": info.name,
        "type": info.type, "country": info.country, "handle": info.handle,
        "range": (f"{info.start} – {info.end}" if info.start else None),
        "remarks": list(info.remarks), "abuse_contact": info.abuse_contact,
        "hint": info.hint, "hint_evidence": info.hint_evidence,
        "error": info.error,
    }


__all__ = [
    "BOOTSTRAP_V4",
    "BOOTSTRAP_V6",
    "DC_WORDS",
    "PLACEHOLDER_NAMES",
    "endpoint_for",
    "load_bootstrap",
    "HOME_WORDS",
    "RDAP_ENDPOINTS",
    "RdapInfo",
    "lookup",
    "parse_rdap",
    "to_json",
]
