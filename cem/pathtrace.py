"""路径质量：跳数、每跳延迟、丢包。需要外部工具 `mtr`，没装就降级。

## 为什么要这一层

前面所有探测回答的都是"终点在哪、多久到"，答不了"**中间哪一跳出了问题**"。
而实际排查里最常见的两个问题恰恰在中间：

- **丢包**：表现为 TLS 握手忽快忽慢（重传），但每一段的"平均值"看起来都正常。
  只有丢包率能直接说明这件事。
- **绕路**：出口在新加坡，但流量先绕到了美国再回来。跳数和每跳的地理位置能看出来。

## 为什么用 mtr 而不是自己实现

自己发 ICMP 需要 raw socket，也就是需要 root。`mtr` 在 macOS 上通过一个
setuid 的辅助程序解决了这个问题，装一次就能以普通用户跑。自己实现等于
要求使用者用 sudo 跑一个监控工具 —— 那个代价比装个 mtr 大得多。

## 没装 mtr 会怎样

**降级，不报错。** `available()` 返回 False，界面上这一块显示"未安装"
并给出一键安装命令。其余功能完全不受影响 —— 一个可选增强不该让主流程失败。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

MTR_BIN_CANDIDATES = ("mtr", "/opt/homebrew/sbin/mtr", "/usr/local/sbin/mtr",
                      "/usr/sbin/mtr", "/usr/bin/mtr")

# 丢包超过这个百分比就值得说。低于它的丢包在公网上很常见，
# 而且**中间跳的丢包经常是假的** —— 见 Hop.loss_is_meaningful。
LOSS_WARN_PCT = 5.0


def which() -> Optional[str]:
    for cand in MTR_BIN_CANDIDATES:
        found = shutil.which(cand) if "/" not in cand else (
            cand if shutil.os.path.exists(cand) else None)
        if found:
            return found
    return None


def available() -> bool:
    return which() is not None


@dataclass(frozen=True)
class Hop:
    index: int
    host: Optional[str]
    loss_pct: float
    sent: int
    avg_ms: Optional[float]
    best_ms: Optional[float]
    worst_ms: Optional[float]
    stdev_ms: Optional[float]

    @property
    def loss_is_meaningful(self) -> bool:
        """这一跳的丢包能不能当真。

        **中间跳的丢包大多是假的**：很多路由器给 ICMP TTL-exceeded 做限速，
        于是显示丢包，但转发流量完全正常。真正有意义的是**最后一跳**
        （终点）的丢包，以及"从某一跳开始到终点全都丢"这种模式。

        不讲这条，读者会看到中间某跳 40% 丢包然后开始换节点 —— 换了也没用。
        """
        return self.loss_pct >= LOSS_WARN_PCT


@dataclass(frozen=True)
class PathReport:
    target: str
    ok: bool
    hops: tuple[Hop, ...] = ()
    error: Optional[str] = None

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    @property
    def final(self) -> Optional[Hop]:
        return self.hops[-1] if self.hops else None

    @property
    def end_to_end_loss(self) -> Optional[float]:
        """终点丢包率 —— 这才是"这条链路丢不丢包"的答案。"""
        return self.final.loss_pct if self.final else None

    @property
    def jitter_ms(self) -> Optional[float]:
        return self.final.stdev_ms if self.final else None


def parse_mtr_json(payload: str) -> tuple[Hop, ...]:
    """解析 `mtr --json` 的输出。纯函数。

    字段名带百分号和大小写混合（`Loss%`、`Avg`），而且不同版本略有差异，
    所以逐个防御性读取，缺字段降级成 None 而不是抛异常。
    """
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return ()
    hubs = (data.get("report") or {}).get("hubs")
    if not isinstance(hubs, list):
        return ()

    def num(row: dict, *names) -> Optional[float]:
        for name in names:
            if name in row:
                try:
                    return float(row[name])
                except (TypeError, ValueError):
                    return None
        return None

    out: list[Hop] = []
    for row in hubs:
        if not isinstance(row, dict):
            continue
        host = row.get("host")
        if host in ("???", "", None):
            host = None
        out.append(Hop(
            index=int(row.get("count") or len(out) + 1),
            host=host,
            loss_pct=num(row, "Loss%", "loss") or 0.0,
            sent=int(num(row, "Snt", "sent") or 0),
            avg_ms=num(row, "Avg", "avg"),
            best_ms=num(row, "Best", "best"),
            worst_ms=num(row, "Wrst", "worst"),
            stdev_ms=num(row, "StDev", "stdev"),
        ))
    return tuple(out)


def trace(target: str, *, cycles: int = 5, timeout: float = 40.0) -> PathReport:
    """跑一次 mtr。

    cycles 默认只有 5 —— 这是一个监控工具的后台任务，不是诊断会话。
    要更准的丢包率，使用者应该手动跑 `mtr -c 100`，那是另一种场合。
    """
    binary = which()
    if not binary:
        return PathReport(target=target, ok=False,
                          error="未安装 mtr；跑 scripts/install-deps.sh 装它")
    # -n 不做反向解析（快很多，而且我们自己有 rDNS 查询）
    args = [binary, "--json", "-n", "-c", str(cycles), "--", target]
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return PathReport(target=target, ok=False, error="mtr 超时")
    except (OSError, subprocess.SubprocessError) as exc:
        return PathReport(target=target, ok=False,
                          error=f"{type(exc).__name__}: {exc}")
    if proc.returncode != 0 and not proc.stdout.strip():
        return PathReport(target=target, ok=False,
                          error=explain_failure(proc.stderr or "",
                                                proc.returncode))
    hops = parse_mtr_json(proc.stdout)
    if not hops:
        return PathReport(target=target, ok=False, error="mtr 没有返回可用的跳信息")
    return PathReport(target=target, ok=True, hops=hops)


# macOS 上装完 mtr 之后最常见的一堵墙。原始报错是
# "Failure to start mtr-packet: Invalid argument"，完全看不出是权限问题 ——
# 直接跑 mtr-packet 才会看到真正的原因 "Failure to open IPv4 sockets"。
# 把这层翻译出来，否则使用者会以为是装坏了。
PERMISSION_HINT = (
    "mtr 需要 root 权限才能发 ICMP 探测包（开 raw socket），"
    "当前以普通用户跑不起来。两种解法：\n"
    "  A. 手动跑时加 sudo：sudo mtr --json -n -c 5 -- claude.ai\n"
    "  B. 给它 setuid，之后普通用户可直接跑（改系统文件权限，自己权衡）：\n"
    "     sudo chown root $(brew --prefix)/sbin/mtr-packet\n"
    "     sudo chmod u+s $(brew --prefix)/sbin/mtr-packet\n"
    "本工具默认按普通用户调用 —— 一个监控工具不该要求你用 sudo 跑它自己。"
)


def explain_failure(stderr: str, returncode: int) -> str:
    """把 mtr 的原始报错翻译成能照着做的说明。纯函数。"""
    blob = (stderr or "").lower()
    if ("failure to start mtr-packet" in blob
            or "failure to open" in blob
            or "operation not permitted" in blob
            or "permission denied" in blob):
        return PERMISSION_HINT
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    return lines[-1] if lines else f"mtr 退出码 {returncode}"


def summarize(report: PathReport) -> dict:
    """整形成界面要的形状。"""
    return {
        "target": report.target,
        "ok": report.ok,
        "error": report.error,
        "hop_count": report.hop_count,
        "end_to_end_loss": report.end_to_end_loss,
        "jitter_ms": report.jitter_ms,
        "final_avg_ms": report.final.avg_ms if report.final else None,
        "hops": [
            {
                "index": h.index, "host": h.host, "loss_pct": h.loss_pct,
                "sent": h.sent, "avg_ms": h.avg_ms, "best_ms": h.best_ms,
                "worst_ms": h.worst_ms, "stdev_ms": h.stdev_ms,
                "meaningful_loss": h.loss_is_meaningful,
                "last": bool(report.final and h.index == report.final.index),
            }
            for h in report.hops
        ],
    }


__all__ = [
    "Hop",
    "LOSS_WARN_PCT",
    "PathReport",
    "PERMISSION_HINT",
    "available",
    "explain_failure",
    "parse_mtr_json",
    "summarize",
    "trace",
    "which",
]
