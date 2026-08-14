"""历史存储：内存环形缓冲 + 可选的 JSONL 落盘。

两件事分开做是有原因的：
- UI 要的是"最近 N 轮"，用来画趋势和算 p50/p95 —— 内存里就够，重启丢了无所谓；
- 排查"上周三凌晨出口跳到别的国家"要的是长期记录 —— 那必须落盘。

落盘**默认关闭**。这个文件的内容就是你的网络画像（出口 IP、代理端口、
内网地址、进程名），默认写盘等于默认给自己留一份敏感文件。
要开就显式开，并且路径在 .gitignore 里已经挡掉了。
"""

from __future__ import annotations

import json
import threading
from collections import deque
from pathlib import Path
from typing import Iterable, Optional

from .model import Sample

DEFAULT_RING = 720          # 30 秒一轮 ≈ 6 小时


class History:
    def __init__(self, *, capacity: int = DEFAULT_RING,
                 jsonl_path: Optional[Path] = None):
        self._ring: deque[Sample] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._jsonl = jsonl_path

    @property
    def persisting(self) -> bool:
        return self._jsonl is not None

    def add(self, sample: Sample) -> None:
        with self._lock:
            self._ring.append(sample)
        if self._jsonl is not None:
            self._append_jsonl(sample)

    def _append_jsonl(self, sample: Sample) -> None:
        try:
            self._jsonl.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(sample.to_json(), ensure_ascii=False)
            with self._jsonl.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            # 落盘失败不该让监控停下来 —— 监控本身比它的日志重要。
            pass

    def size(self) -> int:
        """窗口里现有多少轮。界面上的「已采样轮数」用这个，
        而不是采样器的自增序号 —— 序号会算上已经被环形缓冲挤掉的轮次。"""
        with self._lock:
            return len(self._ring)

    def latest(self) -> Optional[Sample]:
        with self._lock:
            return self._ring[-1] if self._ring else None

    def recent(self, n: int = 60) -> tuple[Sample, ...]:
        with self._lock:
            items = list(self._ring)
        return tuple(items[-max(0, n):])

    def clear(self) -> None:
        with self._lock:
            self._ring.clear()


def percentile(values: Iterable[float], pct: float) -> Optional[float]:
    """最近邻插值的分位数。没有 numpy，也不需要。"""
    data = sorted(v for v in values if v is not None)
    if not data:
        return None
    if len(data) == 1:
        return round(data[0], 2)
    pos = (len(data) - 1) * max(0.0, min(1.0, pct))
    low = int(pos)
    high = min(low + 1, len(data) - 1)
    frac = pos - low
    return round(data[low] * (1 - frac) + data[high] * frac, 2)


def latency_series(
    samples: tuple[Sample, ...],
    target: str,
    path_id: str,
) -> tuple[tuple[float, Optional[float]], ...]:
    """取某个 (域名, 路径) 的总耗时时间序列，给 UI 画趋势。"""
    out: list[tuple[float, Optional[float]]] = []
    for s in samples:
        for t in s.traces:
            if t.target == target and t.path == path_id:
                out.append((s.ts, t.timing.total_ms))
                break
    return tuple(out)


def latency_stats(
    samples: tuple[Sample, ...],
    target: str,
    path_id: str,
) -> dict[str, Optional[float]]:
    values = [v for _ts, v in latency_series(samples, target, path_id) if v is not None]
    return {
        "n": len(values),
        "p50": percentile(values, 0.5),
        "p95": percentile(values, 0.95),
        "min": round(min(values), 2) if values else None,
        "max": round(max(values), 2) if values else None,
    }


def egress_changes(samples: tuple[Sample, ...], path_id: str) -> tuple[dict, ...]:
    """出口变更事件流。

    只在**变了**的时候记一条 —— 每轮都记等于把一屏日志变成噪声，
    而读者关心的只有"什么时候变的"。
    """
    events: list[dict] = []
    last: Optional[tuple[Optional[str], Optional[str]]] = None
    for s in samples:
        current: Optional[tuple[Optional[str], Optional[str]]] = None
        for t in s.traces:
            if t.path == path_id and t.ok and t.egress_ip:
                current = (t.egress_ip, t.country)
                break
        if current is None:
            continue
        if last is None or current != last:
            events.append({
                "ts": s.ts,
                "egress_ip": current[0],
                "country": current[1],
                "first": last is None,
            })
            last = current
    return tuple(events)


__all__ = [
    "DEFAULT_RING",
    "History",
    "egress_changes",
    "latency_series",
    "latency_stats",
    "percentile",
]
