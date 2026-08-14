"""云厂商官方发布的 IP 段 —— 判定「是不是机房」最硬的一个证据源。

## 为什么它比第三方 API 硬

第三方 IP 情报（ip-api、ipinfo 之类）给的是**它们的判断**。
而这里读的是**厂商自己发布的地址清单**：AWS 说 `52.94.x.x` 是它的，
那就是它的——没有比这更权威的来源，也不存在"判断失误"。

所以命中云段的结论是**确证**（confirmed），不是推测（guess）。
这个区别必须在界面上说清楚，否则读者无法判断该不该信。

## 局限（同样要说清楚）

- **命中 = 一定是机房；没命中 ≠ 一定不是机房。** 这里只覆盖几家大厂，
  小机房、国内 IDC、住宅代理服务商都不在名单里。
  所以"没命中"只能降级到别的证据源，不能当成"这是家宽"。
- 清单会更新。缓存 7 天，过期重拉。

## 数据源

全部是厂商官方地址，无需 key、无速率限制：

| 厂商 | 地址 |
|---|---|
| AWS | `ip-ranges.amazonaws.com/ip-ranges.json` |
| Google Cloud | `gstatic.com/ipranges/cloud.json` |
| Cloudflare | `cloudflare.com/ips-v4` · `ips-v6` |
| DigitalOcean | `digitalocean.com/geo/google.csv` |
| Oracle Cloud | `docs.oracle.com/.../public_ip_ranges.json` |

Azure 的清单需要从一个会变的下载页拿，不适合无人值守，暂不收录 ——
宁可少一家，也不要一个随时会静默失效的源。
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .net import MAX_BODY_LARGE, timed_get

# 厂商的清单几天更新一次，但缓存久了读者不知道自己在看多旧的数据。
# 24 小时 + 界面上显示拉取时间 + 可手动刷新 —— 与其猜多久合适，
# 不如把新鲜度摆出来让人自己判断。
CACHE_TTL_S = 24 * 3600
MAX_PREFIXES = 60000        # 防止某个源突然变得巨大把内存吃光

SOURCES: tuple[tuple[str, str, str], ...] = (
    ("aws", "AWS", "https://ip-ranges.amazonaws.com/ip-ranges.json"),
    ("gcp", "Google Cloud", "https://www.gstatic.com/ipranges/cloud.json"),
    ("cloudflare", "Cloudflare", "https://www.cloudflare.com/ips-v4"),
    ("cloudflare6", "Cloudflare", "https://www.cloudflare.com/ips-v6"),
    ("digitalocean", "DigitalOcean", "https://www.digitalocean.com/geo/google.csv"),
    ("oracle", "Oracle Cloud",
     "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"),
)


@dataclass(frozen=True)
class CloudHit:
    provider: str
    prefix: str
    source: str


def parse_aws(payload: str) -> tuple[str, ...]:
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return ()
    out = [p.get("ip_prefix") for p in (data.get("prefixes") or [])]
    out += [p.get("ipv6_prefix") for p in (data.get("ipv6_prefixes") or [])]
    return tuple(p for p in out if p)


def parse_gcp(payload: str) -> tuple[str, ...]:
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return ()
    out = []
    for p in (data.get("prefixes") or []):
        out.append(p.get("ipv4Prefix") or p.get("ipv6Prefix"))
    return tuple(p for p in out if p)


def parse_oracle(payload: str) -> tuple[str, ...]:
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return ()
    out = []
    for region in (data.get("regions") or []):
        for c in (region.get("cidrs") or []):
            if c.get("cidr"):
                out.append(c["cidr"])
    return tuple(out)


def parse_plain_lines(payload: str) -> tuple[str, ...]:
    """Cloudflare 的清单就是一行一个 CIDR。"""
    return tuple(
        ln.strip() for ln in (payload or "").splitlines()
        if ln.strip() and "/" in ln and not ln.startswith("#")
    )


def parse_do_csv(payload: str) -> tuple[str, ...]:
    """DigitalOcean 的 CSV：第一列是 CIDR。"""
    out = []
    for ln in (payload or "").splitlines():
        first = ln.split(",", 1)[0].strip()
        if "/" in first:
            out.append(first)
    return tuple(out)


PARSERS = {
    "aws": parse_aws,
    "gcp": parse_gcp,
    "cloudflare": parse_plain_lines,
    "cloudflare6": parse_plain_lines,
    "digitalocean": parse_do_csv,
    "oracle": parse_oracle,
}


class CloudRanges:
    """厂商官方 IP 段的本地索引。线程安全，落盘缓存。

    **默认不自动拉取。** 第一次用要显式 `refresh()` 或者构造时传
    `auto=True` —— 一个监控工具不该在使用者不知情时下载几 MB 数据。
    """

    def __init__(self, cache_path: Optional[Path] = None, *, auto: bool = False):
        self._path = cache_path
        self._lock = threading.Lock()
        self._nets: tuple[tuple[object, str, str], ...] = ()
        self._fetched_at: float = 0.0
        self._errors: tuple[str, ...] = ()
        if cache_path and cache_path.exists():
            self._load()
        if auto and not self.ready:
            self.refresh()

    @property
    def ready(self) -> bool:
        return bool(self._nets)

    @property
    def fresh(self) -> bool:
        return self.ready and (time.time() - self._fetched_at) < CACHE_TTL_S

    @property
    def size(self) -> int:
        return len(self._nets)

    @property
    def errors(self) -> tuple[str, ...]:
        return self._errors

    # ── 缓存 ────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        self._fetched_at = float(raw.get("fetched_at") or 0)
        self._index(tuple(
            (item["prefix"], item["provider"], item["source"])
            for item in (raw.get("prefixes") or [])
            if item.get("prefix")
        ))

    def _save(self, records: tuple[tuple[str, str, str], ...]) -> None:
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps({
                "version": 1,
                "fetched_at": self._fetched_at,
                "prefixes": [
                    {"prefix": p, "provider": prov, "source": src}
                    for p, prov, src in records
                ],
            }), "utf-8")
        except OSError:
            pass

    def _index(self, records: tuple[tuple[str, str, str], ...]) -> None:
        nets = []
        for prefix, provider, source in records[:MAX_PREFIXES]:
            try:
                nets.append((ipaddress.ip_network(prefix, strict=False),
                             provider, source))
            except ValueError:
                continue
        with self._lock:
            self._nets = tuple(nets)

    # ── 拉取 ────────────────────────────────────────────────────

    def refresh(self, *, timeout: float = 20.0) -> int:
        """拉一遍全部源。返回收录的前缀数。

        单个源失败不影响其余 —— 记进 errors 供界面显示，
        而不是让整次刷新失败。
        """
        records: list[tuple[str, str, str]] = []
        errors: list[str] = []
        for key, provider, url in SOURCES:
            res = timed_get(url, timeout=timeout, max_body=MAX_BODY_LARGE)
            if not res.ok:
                errors.append(f"{provider}({key}): {res.error or res.status}")
                continue
            parser = PARSERS.get(key, parse_plain_lines)
            got = parser(res.body)
            if not got:
                errors.append(f"{provider}({key}): 解析不出前缀")
                continue
            records.extend((p, provider, key) for p in got)

        if records:
            self._fetched_at = time.time()
            self._index(tuple(records))
            self._save(tuple(records))
        self._errors = tuple(errors)
        return len(records)

    # ── 查询 ────────────────────────────────────────────────────

    def lookup(self, ip: str) -> Optional[CloudHit]:
        """命中就返回厂商。**命中 = 确证是机房；没命中不代表不是。**"""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        with self._lock:
            nets = self._nets
        for net, provider, source in nets:
            if addr.version == net.version and addr in net:
                return CloudHit(provider=provider, prefix=str(net), source=source)
        return None


__all__ = [
    "CACHE_TTL_S",
    "CloudHit",
    "CloudRanges",
    "SOURCES",
    "parse_aws",
    "parse_do_csv",
    "parse_gcp",
    "parse_oracle",
    "parse_plain_lines",
]
