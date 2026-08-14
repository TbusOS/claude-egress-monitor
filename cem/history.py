"""长期历史：按天分文件存紧凑记录，支持按天汇总、按天选择、按天删除。

## 为什么不直接存整份 Sample

一轮完整采样序列化出来 8～15KB。30 秒一轮跑满一天是 2880 轮 ≈ **40MB/天**，
一个月就 1.2GB。而看历史看板需要的其实只有每轮的几个结论性数字。

所以落盘的是**紧凑记录**（compact record）：每轮约 400～600 字节，
一天 1～2MB，一年也才几百 MB，而且还能按天删。
全量样本只保留在内存环形缓冲里给当前界面用，重启即弃 —— 那本来就是
"此刻的现场"，不是历史。

## 为什么按天分文件

按天分文件让三件事都变成文件操作，不需要索引也不需要数据库：

- 选哪几天看 → 读哪几个文件
- 删哪几天 → 删哪几个文件（**这是用户真正要的**：一个 append-only 的
  大文件没法删掉中间某一天）
- 汇总缓存失效 → 看文件 mtime

日期用**本机时区**的日历日，因为使用者是按"昨天""上周三"来回忆问题的。
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from . import diagnose as dx
from . import endpoints as ep
from .model import Sample

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RECORD_VERSION = 1


def day_of(ts: float) -> str:
    """时间戳 → 本机时区的 YYYY-MM-DD。"""
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def valid_day(value: object) -> bool:
    """日期串是否合法。

    这个校验同时是**安全边界**：日期串会被拼进文件名，不校验就等于
    把删除接口变成任意路径删除。只允许 YYYY-MM-DD，不允许 `..`、斜杠。
    """
    return isinstance(value, str) and bool(DATE_RE.match(value))


# ─────────────────────────────────────────────────────── 紧凑记录

def compact(sample: Sample) -> dict:
    """把一轮采样压成只保留结论的记录。

    保留什么是有取舍的：**保留能回答"那天出了什么事"的字段**，
    丢掉能重新算出来或者当时才有意义的（每个域名的完整 trace、
    进程 pid、socket 明细）。
    """
    profiles = dx.egress_profile(sample)
    paths: dict[str, dict] = {}
    for path_id, prof in profiles.items():
        primary = prof.primary
        paths[path_id] = {
            "ip": primary.ip if primary else None,
            "cc": primary.country if primary else None,
            "asn": primary.asn if primary else None,
            "org": primary.org if primary else None,
            "colo": primary.colo if primary else None,
            "fam": primary.family if primary else None,
            "level": prof.level,
            "ips": [a.ip for a in prof.addresses],
            "ccs": list(prof.countries),
            "domains": prof.domains,
        }

    # 每个 (域名, 路径) 的总耗时，用来算当天的延迟分位数
    lat: dict[str, float] = {}
    ok = 0
    fail = 0
    for t in sample.traces:
        if t.ok:
            ok += 1
            if t.timing.total_ms is not None:
                lat[f"{t.target}|{t.path}"] = round(t.timing.total_ms, 1)
        else:
            fail += 1

    findings = dx.diagnose(sample, (sample,))
    sev = dx.summary(findings)

    return {
        "v": RECORD_VERSION,
        "ts": round(sample.ts, 3),
        "paths": paths,
        "lat": lat,
        "ok": ok,
        "fail": fail,
        "sev": {k: v for k, v in sev.items() if v},
        "top": [f.title for f in findings
                if f.severity in (dx.SEV_CRITICAL, dx.SEV_WARN)][:3],
    }


# ─────────────────────────────────────────────────────── 存储

class DayStore:
    """按天分文件的紧凑记录存储。线程安全。"""

    def __init__(self, root: Optional[Path]):
        self._root = root
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, dict]] = {}   # day -> (mtime, summary)

    @property
    def enabled(self) -> bool:
        return self._root is not None

    @property
    def root(self) -> Optional[Path]:
        return self._root

    def _path(self, day: str) -> Path:
        return self._root / f"{day}.jsonl"

    # ── 写 ──────────────────────────────────────────────────────

    def append(self, sample: Sample) -> None:
        if self._root is None:
            return
        record = compact(sample)
        day = day_of(sample.ts)
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        try:
            with self._lock:
                self._root.mkdir(parents=True, exist_ok=True)
                with self._path(day).open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                self._cache.pop(day, None)
        except OSError:
            # 落盘失败不该让监控停下来 —— 监控本身比它的日志重要。
            pass

    # ── 读 ──────────────────────────────────────────────────────

    def days(self) -> tuple[str, ...]:
        if self._root is None or not self._root.exists():
            return ()
        out = []
        for p in self._root.glob("*.jsonl"):
            if valid_day(p.stem):
                out.append(p.stem)
        return tuple(sorted(out, reverse=True))

    def records(self, day: str) -> tuple[dict, ...]:
        if self._root is None or not valid_day(day):
            return ()
        path = self._path(day)
        if not path.exists():
            return ()
        out = []
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue        # 单行坏了不该让整天读不出来
        except OSError:
            return ()
        return tuple(out)

    def size_bytes(self, day: str) -> int:
        if self._root is None or not valid_day(day):
            return 0
        path = self._path(day)
        try:
            return path.stat().st_size
        except OSError:
            return 0

    # ── 删 ──────────────────────────────────────────────────────

    def delete(self, days: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """删掉指定的几天，返回 (删成功的, 被拒绝的)。

        非法日期串一律拒绝而不是忽略 —— 删除接口上，"静默忽略"和
        "删错东西"只隔一个 bug。
        """
        done: list[str] = []
        rejected: list[str] = []
        if self._root is None:
            return (), tuple(days)
        with self._lock:
            for day in days:
                if not valid_day(day):
                    rejected.append(str(day))
                    continue
                try:
                    self._path(day).unlink(missing_ok=True)
                    self._cache.pop(day, None)
                    done.append(day)
                except OSError:
                    rejected.append(day)
        return tuple(done), tuple(rejected)

    # ── 汇总 ────────────────────────────────────────────────────

    def summary(self, day: str) -> Optional[dict]:
        """一天的汇总。按文件 mtime 缓存 —— 历史文件不会再变，
        重复扫描纯属浪费。"""
        if self._root is None or not valid_day(day):
            return None
        path = self._path(day)
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        hit = self._cache.get(day)
        if hit and hit[0] == mtime:
            return hit[1]
        built = summarize(day, self.records(day), self.size_bytes(day))
        self._cache[day] = (mtime, built)
        return built

    def summaries(self, days: Optional[Iterable[str]] = None) -> tuple[dict, ...]:
        chosen = tuple(days) if days is not None else self.days()
        out = []
        for day in chosen:
            got = self.summary(day)
            if got:
                out.append(got)
        return tuple(sorted(out, key=lambda s: s["day"], reverse=True))


# ─────────────────────────────────────────────────────── 汇总计算

def _percentile(values: list[float], pct: float) -> Optional[float]:
    data = sorted(values)
    if not data:
        return None
    if len(data) == 1:
        return round(data[0], 1)
    pos = (len(data) - 1) * max(0.0, min(1.0, pct))
    low = int(pos)
    high = min(low + 1, len(data) - 1)
    return round(data[low] * (1 - (pos - low)) + data[high] * (pos - low), 1)


def summarize(day: str, records: tuple[dict, ...], size_bytes: int = 0) -> dict:
    """把一天的紧凑记录聚合成看板要的形状。纯函数，好测。

    输出刻意做成"每一项都能画成一个图":
    - `countries` / `networks` / `addresses` → 构成图（环图 / 横条）
    - `hourly` → 按小时的柱状图
    - `latency` → 分位数
    - `changes` → 变更次数
    """
    if not records:
        return {
            "day": day, "rounds": 0, "size_bytes": size_bytes,
            "paths": {}, "countries": [], "networks": [], "addresses": [],
            "latency": {}, "hourly": [], "severity": {}, "top": [],
            "first_ts": None, "last_ts": None, "uptime_ratio": None,
        }

    records = tuple(sorted(records, key=lambda r: r.get("ts", 0)))
    first_ts = records[0].get("ts")
    last_ts = records[-1].get("ts")

    cc_count: dict[str, int] = {}
    net_count: dict[str, int] = {}
    net_org: dict[str, str] = {}
    addr_count: dict[str, int] = {}
    addr_meta: dict[str, dict] = {}
    path_stats: dict[str, dict] = {}
    lat_values: list[float] = []
    lat_by_key: dict[str, list[float]] = {}
    sev_total: dict[str, int] = {}
    ok_total = 0
    fail_total = 0
    titles: dict[str, int] = {}

    prev_primary: dict[str, str] = {}
    changes: dict[str, int] = {}
    cc_changes: dict[str, int] = {}

    hourly_buckets: dict[int, dict] = {}

    for rec in records:
        ts = rec.get("ts") or 0
        hour = int(time.strftime("%H", time.localtime(ts))) if ts else 0
        bucket = hourly_buckets.setdefault(
            hour, {"hour": hour, "rounds": 0, "lat": [], "changes": 0,
                   "countries": {}}
        )
        bucket["rounds"] += 1

        ok_total += int(rec.get("ok") or 0)
        fail_total += int(rec.get("fail") or 0)
        for k, v in (rec.get("sev") or {}).items():
            sev_total[k] = sev_total.get(k, 0) + int(v)
        for title in rec.get("top") or []:
            titles[title] = titles.get(title, 0) + 1

        for key, value in (rec.get("lat") or {}).items():
            try:
                val = float(value)
            except (TypeError, ValueError):
                continue
            lat_values.append(val)
            lat_by_key.setdefault(key, []).append(val)
            bucket["lat"].append(val)

        for path_id, info in (rec.get("paths") or {}).items():
            stat = path_stats.setdefault(path_id, {
                "path": path_id, "rounds": 0, "ips": {}, "countries": {},
                "networks": {}, "levels": {}, "changes": 0, "cc_changes": 0,
            })
            stat["rounds"] += 1

            ip = info.get("ip")
            cc = info.get("cc")
            asn = info.get("asn")
            org = info.get("org")

            if ip:
                stat["ips"][ip] = stat["ips"].get(ip, 0) + 1
                addr_count[ip] = addr_count.get(ip, 0) + 1
                addr_meta.setdefault(ip, {
                    "ip": ip, "cc": cc, "asn": asn, "org": org,
                    "family": info.get("fam"), "colo": info.get("colo"),
                    "paths": [],
                })
                if path_id not in addr_meta[ip]["paths"]:
                    addr_meta[ip]["paths"].append(path_id)
            if cc:
                stat["countries"][cc] = stat["countries"].get(cc, 0) + 1
                cc_count[cc] = cc_count.get(cc, 0) + 1
                bucket["countries"][cc] = bucket["countries"].get(cc, 0) + 1
            if asn:
                stat["networks"][asn] = stat["networks"].get(asn, 0) + 1
                net_count[asn] = net_count.get(asn, 0) + 1
                if org:
                    net_org[asn] = org
            level = info.get("level")
            if level:
                stat["levels"][level] = stat["levels"].get(level, 0) + 1

            key = f"{path_id}"
            if ip:
                if prev_primary.get(key) and prev_primary[key] != ip:
                    changes[key] = changes.get(key, 0) + 1
                    stat["changes"] += 1
                    bucket["changes"] += 1
                prev_primary[key] = ip
            if cc:
                ck = f"cc:{path_id}"
                if prev_primary.get(ck) and prev_primary[ck] != cc:
                    cc_changes[key] = cc_changes.get(key, 0) + 1
                    stat["cc_changes"] += 1
                prev_primary[ck] = cc

    def rank(counter: dict[str, int]) -> list[dict]:
        total = sum(counter.values()) or 1
        return [
            {"key": k, "count": v, "share": round(v * 100.0 / total, 1)}
            for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
        ]

    hourly = []
    for hour in range(24):
        b = hourly_buckets.get(hour)
        if not b:
            hourly.append({"hour": hour, "rounds": 0, "p50": None,
                           "changes": 0, "top_country": None})
            continue
        top_cc = sorted(b["countries"].items(), key=lambda kv: -kv[1])
        hourly.append({
            "hour": hour,
            "rounds": b["rounds"],
            "p50": _percentile(b["lat"], 0.5),
            "changes": b["changes"],
            "top_country": top_cc[0][0] if top_cc else None,
        })

    # 覆盖率：这一天里有采样的小时数 / 24。回答"我这天是不是一直开着"
    covered = sum(1 for h in hourly if h["rounds"])

    return {
        "day": day,
        "rounds": len(records),
        "size_bytes": size_bytes,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "hours_covered": covered,
        "uptime_ratio": round(covered / 24.0, 3),
        "ok": ok_total,
        "fail": fail_total,
        "success_ratio": (round(ok_total * 100.0 / (ok_total + fail_total), 1)
                          if (ok_total + fail_total) else None),
        "countries": rank(cc_count),
        "networks": [
            {**item, "org": net_org.get(item["key"])} for item in rank(net_count)
        ],
        "addresses": [
            {**addr_meta[ip], "count": c,
             "share": round(c * 100.0 / (sum(addr_count.values()) or 1), 1)}
            for ip, c in sorted(addr_count.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "paths": {
            p: {
                **stat,
                "ips": rank(stat["ips"]),
                "countries": rank(stat["countries"]),
                "networks": rank(stat["networks"]),
                "levels": rank(stat["levels"]),
            }
            for p, stat in path_stats.items()
        },
        "latency": {
            "p50": _percentile(lat_values, 0.5),
            "p95": _percentile(lat_values, 0.95),
            "min": round(min(lat_values), 1) if lat_values else None,
            "max": round(max(lat_values), 1) if lat_values else None,
            "n": len(lat_values),
            "by_target": [
                {"key": k, "p50": _percentile(v, 0.5),
                 "p95": _percentile(v, 0.95), "n": len(v)}
                for k, v in sorted(lat_by_key.items())
            ],
        },
        "hourly": hourly,
        "severity": sev_total,
        "top": [{"title": t, "count": c}
                for t, c in sorted(titles.items(), key=lambda kv: -kv[1])[:5]],
        "changes": sum(changes.values()),
        "country_changes": sum(cc_changes.values()),
    }


def combine(summaries: tuple[dict, ...]) -> dict:
    """把多天的汇总合并成一个区间汇总，给"选了 3 天"这种视图用。"""
    if not summaries:
        return {"days": 0, "rounds": 0, "countries": [], "networks": [],
                "addresses": [], "latency": {}, "changes": 0, "size_bytes": 0}

    cc: dict[str, int] = {}
    net: dict[str, int] = {}
    net_org: dict[str, str] = {}
    addr: dict[str, int] = {}
    addr_meta: dict[str, dict] = {}
    rounds = 0
    changes = 0
    cc_changes = 0
    size = 0
    lat_p50: list[float] = []
    lat_p95: list[float] = []
    sev: dict[str, int] = {}

    for s in summaries:
        rounds += s.get("rounds", 0)
        changes += s.get("changes", 0)
        cc_changes += s.get("country_changes", 0)
        size += s.get("size_bytes", 0)
        for item in s.get("countries", []):
            cc[item["key"]] = cc.get(item["key"], 0) + item["count"]
        for item in s.get("networks", []):
            net[item["key"]] = net.get(item["key"], 0) + item["count"]
            if item.get("org"):
                net_org[item["key"]] = item["org"]
        for item in s.get("addresses", []):
            addr[item["ip"]] = addr.get(item["ip"], 0) + item["count"]
            addr_meta.setdefault(item["ip"], item)
        lat = s.get("latency") or {}
        if lat.get("p50") is not None:
            lat_p50.append(lat["p50"])
        if lat.get("p95") is not None:
            lat_p95.append(lat["p95"])
        for k, v in (s.get("severity") or {}).items():
            sev[k] = sev.get(k, 0) + v

    def rank(counter: dict[str, int], extra=None) -> list[dict]:
        total = sum(counter.values()) or 1
        out = []
        for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
            item = {"key": k, "count": v, "share": round(v * 100.0 / total, 1)}
            if extra and k in extra:
                item["org"] = extra[k]
            out.append(item)
        return out

    return {
        "days": len(summaries),
        "day_list": [s["day"] for s in summaries],
        "rounds": rounds,
        "size_bytes": size,
        "countries": rank(cc),
        "networks": rank(net, net_org),
        "addresses": [
            {**addr_meta[ip], "count": c,
             "share": round(c * 100.0 / (sum(addr.values()) or 1), 1)}
            for ip, c in sorted(addr.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "latency": {
            # 跨天只能用"日分位数的中位数"近似 —— 原始值已经不在了。
            # 标出来是为了避免读者把它当成真正的全区间 p50。
            "p50_of_days": _percentile(lat_p50, 0.5),
            "p95_of_days": _percentile(lat_p95, 0.5),
            "approx": True,
        },
        "changes": changes,
        "country_changes": cc_changes,
        "severity": sev,
    }


__all__ = [
    "DATE_RE",
    "DayStore",
    "combine",
    "compact",
    "day_of",
    "summarize",
    "valid_day",
]
