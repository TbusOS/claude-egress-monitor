"""路径质量的自动探测：一个可启停的后台循环，一遍把所有目标测完。

## 为什么单独做一个循环，不挂在主采样器上

主采样一轮几百毫秒，30 秒一次很合理。而 `mtr` 一个目标要跑 5–15 秒，
一遍七八个目标就是一两分钟 —— 把它塞进主循环会让"每 30 秒一轮"变成谎话。
所以它有自己的开关、自己的间隔（分钟级），互不拖累。

## 一个关键优化：按解析地址去重

七个 Claude 域名经常解析到同一个地址（同一套 Anycast 前端）。
对同一个地址跑七遍 mtr 是纯浪费，而且七份几乎相同的结果会让面板
看起来"信息很多"其实什么都没多说。

所以先解析、按地址分组，**一个地址只测一次**，然后把"哪几个域名共用
这个地址"一并显示出来 —— 这本身就是一条有用的信息。

## 默认关闭

和主监控一样。`mtr` 要发 ICMP 探测包，这是这个工具唯一会主动往网络里
打非 HTTP 流量的地方，更不该在没人同意的时候自己跑起来。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Optional

from . import pathtrace

# 分钟级。一遍要跑一两分钟，比这更密就变成连续跑了。
DEFAULT_INTERVAL_S = 300
MIN_INTERVAL_S = 60
MAX_INTERVAL_S = 3600


@dataclass(frozen=True)
class WatchConfig:
    interval_s: int = DEFAULT_INTERVAL_S
    cycles: int = 5

    def with_interval(self, seconds: int) -> "WatchConfig":
        clamped = max(MIN_INTERVAL_S, min(MAX_INTERVAL_S, int(seconds)))
        return replace(self, interval_s=clamped)


@dataclass(frozen=True)
class TargetGroup:
    """一个解析地址，以及共用它的那些域名。"""
    address: Optional[str]
    hosts: tuple[str, ...]

    @property
    def probe_target(self) -> str:
        """实际交给 mtr 的那个字符串。

        有地址就用地址：域名再解析一次可能拿到组里的另一个地址，
        那样"测的是谁"就对不上了。解析不出来才退回域名。
        """
        return self.address or self.hosts[0]


def group_by_address(hosts: tuple[str, ...]) -> tuple[TargetGroup, ...]:
    """把域名按解析地址分组。纯函数之外只依赖一次 DNS 查询。

    解析不出来的域名各自单独一组 —— 不能把它们并成一个 "None" 组，
    那会让面板显示成"这三个域名共用同一个地址"，而事实是三个都没解析出来。
    """
    by_addr: dict[str, list[str]] = {}
    orphans: list[TargetGroup] = []
    for host in hosts:
        addr = pathtrace.resolve_once(host)
        if addr is None:
            orphans.append(TargetGroup(address=None, hosts=(host,)))
            continue
        by_addr.setdefault(addr, []).append(host)
    groups = [TargetGroup(address=addr, hosts=tuple(names))
              for addr, names in by_addr.items()]
    return tuple(groups + orphans)


class PathWatcher:
    """按需 / 定时跑 mtr。线程安全，结果只在内存里。

    结果不落盘：路径里全是本机上游的地址（家里的路由器、运营商的 NAT），
    那是最不该被写进文件的一类数据。想留的人可以自己抄。
    """

    def __init__(self, hosts: Callable[[], tuple[str, ...]],
                 *, config: Optional[WatchConfig] = None):
        self._hosts = hosts
        self._config = config or WatchConfig()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        # 取消信号。一遍要跑一两分钟，中途必须能叫停 ——
        # 一个停不下来的长任务，用户读到的就是"这个界面卡死了"。
        self._cancel = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._sweeping = False
        self._results: dict[str, dict] = {}
        self._last_sweep_ts: Optional[float] = None
        self._last_error: Optional[str] = None
        self._sweeps = 0
        # 进度。一遍要跑一两分钟，界面上没有进度就等于"点了没反应"，
        # 而"点了没反应"会被读成"这个按钮坏了"。
        self._done = 0
        self._total = 0
        self._current: Optional[str] = None

    # ---------------------------------------------------------- 只读

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    def status(self) -> dict:
        with self._lock:
            return {
                "available": pathtrace.available(),
                "running": self._running,
                "sweeping": self._sweeping,
                "interval_s": self._config.interval_s,
                "cycles": self._config.cycles,
                "sweeps": self._sweeps,
                "last_sweep_ts": self._last_sweep_ts,
                "last_error": self._last_error,
                "done": self._done,
                "total": self._total,
                "current": self._current,
            }

    def results(self) -> list[dict]:
        """按终点平均延迟排序 —— 慢的排前面，那是要看的。"""
        with self._lock:
            rows = list(self._results.values())
        rows.sort(key=lambda r: (r.get("final_avg_ms") is None,
                                 r.get("final_avg_ms") or 0.0), reverse=True)
        return rows

    # ---------------------------------------------------------- 控制

    def start(self, *, interval_s: Optional[int] = None) -> dict:
        with self._lock:
            if interval_s is not None:
                self._config = self._config.with_interval(interval_s)
            if self._running:
                return self.status()
            self._running = True
            self._wake.clear()
            self._thread = threading.Thread(
                target=self._loop, name="cem-pathwatch", daemon=True)
            self._thread.start()
        return self.status()

    def stop(self) -> dict:
        """关掉自动探测，并叫停正在跑的那一遍。

        「关掉之后还要再跑一两分钟」在界面上就是「关不掉」。所以这里
        连同在途的那一遍一起取消，最多再等当前这一个目标跑完。
        """
        with self._lock:
            self._running = False
        self._cancel.set()
        self._wake.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2)
        with self._lock:
            self._thread = None
        return self.status()

    def cancel(self) -> dict:
        """只叫停在途的那一遍，不动自动探测的开关。"""
        self._cancel.set()
        return self.status()

    def set_interval(self, seconds: int) -> dict:
        with self._lock:
            self._config = self._config.with_interval(seconds)
        self._wake.set()
        return self.status()

    def sweep_soon(self) -> dict:
        """立刻在后台跑一遍，不阻塞调用方。

        同步跑会让那个 HTTP 请求挂一两分钟 —— 浏览器那侧看起来就是卡死。
        所以这里只是起一个一次性线程，界面靠轮询看进度。
        """
        with self._lock:
            if self._sweeping:
                return self.status()
        self._cancel.clear()
        threading.Thread(target=self._sweep_guarded,
                         name="cem-pathsweep", daemon=True).start()
        return self.status()

    # ---------------------------------------------------------- 内部

    def _sweep_guarded(self) -> None:
        try:
            self._sweep()
        except Exception as exc:                       # noqa: BLE001
            # 后台线程里的异常没人接，静默死掉的话界面会一直显示"探测中"。
            with self._lock:
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._sweeping = False

    def _sweep(self) -> None:
        with self._lock:
            if self._sweeping:
                return
            self._sweeping = True
            cycles = self._config.cycles
        try:
            if not pathtrace.available():
                with self._lock:
                    self._last_error = "未安装 mtr"
                return
            groups = group_by_address(self._hosts())
            with self._lock:
                self._done = 0
                self._total = len(groups)
            fresh: dict[str, dict] = {}
            for group in groups:
                # 每个目标之前检查一次取消。**不再区分"第一遍"** ——
                # 早先的写法是第一遍跑完整、之后才可中断，结果就是
                # 刚打开就关掉的话要再等一两分钟，界面上读作"关不掉"。
                if self._cancel.is_set():
                    break
                with self._lock:
                    self._current = group.probe_target
                report = pathtrace.trace(group.probe_target, cycles=cycles,
                                         cancel=self._cancel)
                row = pathtrace.summarize(report)
                row["hosts"] = list(group.hosts)
                row["shared"] = len(group.hosts) > 1
                row["ts"] = time.time()
                fresh[group.probe_target] = row
                with self._lock:
                    # 边跑边更新结果，界面上就能一条一条冒出来 ——
                    # 等一分半钟再一次性全出，和"点了没反应"是同一种体验。
                    self._results = dict(fresh)
                    self._done += 1
            cancelled = self._cancel.is_set()
            with self._lock:
                self._results = fresh
                self._last_sweep_ts = time.time()
                self._sweeps += 1
                self._last_error = "上一遍被中途停掉了" if cancelled else None
                self._current = None
        finally:
            with self._lock:
                self._sweeping = False
                self._current = None

    def _loop(self) -> None:
        while self.running:
            started = time.monotonic()
            self._cancel.clear()
            self._sweep_guarded()
            if not self.running:
                break
            with self._lock:
                interval = self._config.interval_s
            # 一遍本身可能就跑了一分钟，剩多少等多少，不叠加。
            remaining = interval - (time.monotonic() - started)
            if remaining > 0:
                self._wake.wait(remaining)
            self._wake.clear()


__all__ = [
    "DEFAULT_INTERVAL_S",
    "MAX_INTERVAL_S",
    "MIN_INTERVAL_S",
    "PathWatcher",
    "TargetGroup",
    "WatchConfig",
    "group_by_address",
]
