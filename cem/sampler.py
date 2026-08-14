"""后台采样循环，带开关。

开关是这个工具的一条产品原则，不是一个可选功能：

**默认是关的。** 启动服务器只是把界面端起来，一次网络探测都不发。
按下"开始监控"才开始采样，再按一次就彻底停 —— 停之后进程里
没有任何定时器在跑，不是"降低频率"。

为什么较真：一个监控网络的工具自己在后台悄悄发请求，
是这类工具里最容易失去信任的一点。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from . import paths as pathmod
from . import probe
from .asn import AsnCache
from .model import Sample
from .store import History

MIN_INTERVAL_S = 5
MAX_INTERVAL_S = 3600
DEFAULT_INTERVAL_S = 30


@dataclass(frozen=True)
class SamplerConfig:
    interval_s: int = DEFAULT_INTERVAL_S
    include_optional: bool = False
    include_telemetry: bool = True
    with_resolve: bool = True
    with_sockets: bool = True
    timeout: float = 8.0

    def with_interval(self, seconds: int) -> "SamplerConfig":
        return SamplerConfig(
            interval_s=clamp_interval(seconds),
            include_optional=self.include_optional,
            include_telemetry=self.include_telemetry,
            with_resolve=self.with_resolve,
            with_sockets=self.with_sockets,
            timeout=self.timeout,
        )


def clamp_interval(seconds: object) -> int:
    """把外部传进来的间隔夹到合法范围。

    下限 5 秒不是随便定的：一轮采样本身要跑十几个 TLS 握手，
    比这更密就成了给 Claude 的边缘节点刷请求，而且相邻两轮的
    结果没有信息增量。
    """
    try:
        val = int(seconds)                # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_S
    return max(MIN_INTERVAL_S, min(MAX_INTERVAL_S, val))


class Sampler:
    """一个可启停的采样线程。"""

    def __init__(
        self,
        history: History,
        *,
        config: Optional[SamplerConfig] = None,
        asn_cache: Optional[AsnCache] = None,
        on_sample: Optional[Callable[[Sample], None]] = None,
    ):
        self._history = history
        self._config = config or SamplerConfig()
        self._asn = asn_cache
        self._on_sample = on_sample
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._wake = threading.Event()
        self._running = False
        self._seq = 0
        self._routes: tuple[pathmod.Path, ...] = ()
        self._last_error: Optional[str] = None

    # ---------------------------------------------------------- 状态

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def config(self) -> SamplerConfig:
        with self._lock:
            return self._config

    @property
    def routes(self) -> tuple[pathmod.Path, ...]:
        with self._lock:
            return self._routes or pathmod.discover()

    @property
    def last_error(self) -> Optional[str]:
        with self._lock:
            return self._last_error

    def status(self) -> dict:
        with self._lock:
            return {
                "running": self._running,
                "interval_s": self._config.interval_s,
                "samples": self._seq,
                "persisting": self._history.persisting,
                "last_error": self._last_error,
            }

    # ---------------------------------------------------------- 控制

    def start(self, *, interval_s: Optional[int] = None) -> dict:
        with self._lock:
            if interval_s is not None:
                self._config = self._config.with_interval(interval_s)
            if self._running:
                return self.status()
            self._running = True
            self._routes = pathmod.discover()
            self._wake.clear()
            self._thread = threading.Thread(
                target=self._loop, name="cem-sampler", daemon=True,
            )
            self._thread.start()
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            self._running = False
        self._wake.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=12)
        with self._lock:
            self._thread = None
        return self.status()

    def override_routes(self, routes: tuple[pathmod.Path, ...]) -> None:
        """强制指定探测路径。给演示模式用，正常运行时路径应当是发现出来的。"""
        with self._lock:
            self._routes = routes

    def set_interval(self, seconds: int) -> dict:
        with self._lock:
            self._config = self._config.with_interval(seconds)
        self._wake.set()          # 立刻按新间隔重新排一轮
        return self.status()

    def sample_now(self) -> Sample:
        """手动跑一轮，不需要开监控。"""
        return self._one_round()

    # ---------------------------------------------------------- 内部

    def _one_round(self) -> Sample:
        with self._lock:
            self._seq += 1
            seq = self._seq
            cfg = self._config
            routes = self._routes or pathmod.discover()
        sample = probe.run_once(
            seq=seq,
            routes=routes,
            include_optional=cfg.include_optional,
            include_telemetry=cfg.include_telemetry,
            with_resolve=cfg.with_resolve,
            with_sockets=cfg.with_sockets,
            asn_cache=self._asn,
            timeout=cfg.timeout,
        )
        self._history.add(sample)
        if self._on_sample:
            self._on_sample(sample)
        return sample

    def _loop(self) -> None:
        while self.running:
            started = time.monotonic()
            try:
                self._one_round()
                with self._lock:
                    self._last_error = None
            except Exception as exc:                     # noqa: BLE001
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
            # 扣掉这一轮自己花的时间，间隔才是真的间隔。
            wait = max(1.0, self.config.interval_s - (time.monotonic() - started))
            self._wake.wait(wait)
            self._wake.clear()


__all__ = [
    "DEFAULT_INTERVAL_S",
    "MAX_INTERVAL_S",
    "MIN_INTERVAL_S",
    "Sampler",
    "SamplerConfig",
    "clamp_interval",
]
