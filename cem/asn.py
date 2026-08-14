"""IP 归属查询：ASN、前缀、国家、组织。

数据源按可信度排序，能拿到就不再往下问：

1. **Team Cymru 的 DNS 接口**（`origin.asn.cymru.com`）—— 直接读 BGP 全表，
   不要 key、不限速、答案就是路由现实。它只给 ASN / 前缀 / 注册国，
   不给城市，这对判断"流量走哪个网络"已经够了。
2. **ipinfo.io 免费额度** —— 补城市和 anycast 标记。有速率限制，
   所以只在第一档拿不到、或者明确要城市级信息时才用。

两级都失败就诚实返回空，不编。查过的结果落盘缓存 —— ASN 归属很少变，
每次采样重查一遍纯属浪费，也会很快把免费额度打满。
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import threading
from pathlib import Path as FsPath
from typing import Optional

from .model import AsnInfo
from .net import timed_get
from .resolve import is_fake_ip, is_private

CACHE_TTL_S = 7 * 24 * 3600

# "399358 | 160.79.104.0/23 | US | arin | 2023-09-14"
_CYMRU_ORIGIN = re.compile(
    r'^"?\s*(?P<asn>\d+)\s*\|\s*(?P<prefix>[^|]+?)\s*\|\s*(?P<cc>\w{2})\s*\|'
)
# "399358 | US | arin | 2023-09-20 | ANTHROPIC - Anthropic, PBC, US"
_CYMRU_NAME = re.compile(
    r'^"?\s*(?P<asn>\d+)\s*\|\s*(?P<cc>\w{2})\s*\|\s*\w+\s*\|\s*[\d-]*\s*\|\s*'
    r'(?P<org>.+?)"?\s*$'
)


def _reverse_name(ip: str) -> Optional[str]:
    """把 IP 变成 Cymru 要的反向域名。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _dig_txt(name: str, timeout: int = 4) -> list[str]:
    try:
        proc = subprocess.run(
            ["dig", "+short", f"+time={timeout}", "+tries=1", "TXT", name],
            capture_output=True, text=True, timeout=timeout + 3,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def parse_cymru_origin(lines: list[str]) -> Optional[dict[str, str]]:
    """纯函数：解析 origin.asn.cymru.com 的 TXT。"""
    for line in lines:
        m = _CYMRU_ORIGIN.match(line)
        if m:
            return {
                "asn": "AS" + m.group("asn"),
                "prefix": m.group("prefix"),
                "country": m.group("cc").upper(),
            }
    return None


def parse_cymru_name(lines: list[str]) -> Optional[str]:
    """纯函数：解析 ASxxxx.asn.cymru.com 的 TXT，取组织名。"""
    for line in lines:
        m = _CYMRU_NAME.match(line)
        if m:
            return m.group("org").strip()
    return None


def lookup_cymru(ip: str) -> Optional[AsnInfo]:
    name = _reverse_name(ip)
    if not name:
        return None
    origin = parse_cymru_origin(_dig_txt(name))
    if not origin:
        return None
    org = parse_cymru_name(_dig_txt(f"{origin['asn']}.asn.cymru.com"))
    return AsnInfo(
        ip=ip,
        asn=origin["asn"],
        prefix=origin["prefix"],
        country=origin["country"],
        org=org,
        source="cymru",
    )


def parse_ipinfo(payload: str, ip: str) -> Optional[AsnInfo]:
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("bogon"):
        return None
    org = str(data.get("org") or "")
    asn = None
    if org.startswith("AS"):
        asn, _, rest = org.partition(" ")
        org = rest.strip() or org
    return AsnInfo(
        ip=ip,
        asn=asn,
        country=data.get("country"),
        org=org or None,
        city=data.get("city"),
        anycast=bool(data["anycast"]) if "anycast" in data else None,
        source="ipinfo",
    )


def lookup_ipinfo(ip: str, *, proxy: Optional[tuple[str, int]] = None) -> Optional[AsnInfo]:
    res = timed_get(f"https://ipinfo.io/{ip}/json", proxy=proxy, timeout=6.0)
    if not res.ok:
        return None
    return parse_ipinfo(res.body, ip)


def _merge(base: Optional[AsnInfo], extra: Optional[AsnInfo]) -> Optional[AsnInfo]:
    """用 extra 补 base 缺的字段。不覆盖已有值 —— Cymru 的 ASN 比谁都准。"""
    if base is None:
        return extra
    if extra is None:
        return base
    return AsnInfo(
        ip=base.ip,
        asn=base.asn or extra.asn,
        prefix=base.prefix or extra.prefix,
        country=base.country or extra.country,
        org=base.org or extra.org,
        city=base.city or extra.city,
        anycast=base.anycast if base.anycast is not None else extra.anycast,
        source="+".join(filter(None, [base.source, extra.source])),
    )


class AsnCache:
    """线程安全的磁盘缓存。采样线程和 HTTP 线程会同时查。"""

    def __init__(self, path: Optional[FsPath] = None, *, want_city: bool = True):
        self._path = path
        self._want_city = want_city
        self._lock = threading.Lock()
        self._mem: dict[str, AsnInfo] = {}
        if path and path.exists():
            self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        for ip, rec in (raw.get("entries") or {}).items():
            try:
                self._mem[ip] = AsnInfo(**rec)
            except TypeError:
                continue

    def _save(self) -> None:
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "entries": {ip: vars(info) for ip, info in self._mem.items()},
            }
            self._path.write_text(json.dumps(payload, ensure_ascii=False), "utf-8")
        except OSError:
            pass

    def get(self, ip: str, *, proxy: Optional[tuple[str, int]] = None) -> Optional[AsnInfo]:
        """查一个 IP。私有地址和 fake-ip 直接返回带说明的占位结果。"""
        if is_fake_ip(ip):
            return AsnInfo(ip=ip, org="fake-ip 占位地址（本地分流器分配）",
                           source="local")
        if is_private(ip):
            return AsnInfo(ip=ip, org="本机 / 内网地址", source="local")

        with self._lock:
            hit = self._mem.get(ip)
        if hit:
            return hit

        info = lookup_cymru(ip)
        if self._want_city and (info is None or info.city is None):
            info = _merge(info, lookup_ipinfo(ip, proxy=proxy))
        if info is None:
            return None

        with self._lock:
            self._mem = {**self._mem, ip: info}
        self._save()
        return info


__all__ = [
    "AsnCache",
    "AsnInfo",
    "lookup_cymru",
    "lookup_ipinfo",
    "parse_cymru_name",
    "parse_cymru_origin",
    "parse_ipinfo",
]
