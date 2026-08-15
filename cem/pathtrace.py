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
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from .resolve import is_fake_ip, is_private

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

    @property
    def answered(self) -> bool:
        """这一跳至少回过一个包。没回过就没有地址，也没有可信的延迟。"""
        return self.host is not None and self.loss_pct < 100.0

    @property
    def is_private(self) -> bool:
        """内网 / 回环 / CGNAT（含 Tailscale 的 100.64/10）。

        路径前几跳是内网地址很正常（家里的路由器）。但如果**中间**突然
        冒出内网地址，说明流量进了一条隧道 —— 从那一跳起量到的就不是
        "到 Claude 的路"了。
        """
        return bool(self.host) and is_private(self.host)


@dataclass(frozen=True)
class PathReport:
    target: str
    ok: bool
    hops: tuple[Hop, ...] = ()
    error: Optional[str] = None
    resolved: Optional[str] = None       # mtr 实际打向的地址

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    @property
    def final(self) -> Optional[Hop]:
        return self.hops[-1] if self.hops else None

    @property
    def endpoint_silent(self) -> bool:
        """终点一个包都没回过。

        **这不等于链路在丢包。** 大量主机在防火墙上直接丢掉 ICMP echo，
        TUN 模式下的 fake-ip 占位地址更是压根不存在于网络上 —— 两种情况
        都会显示"终点 100% 丢包"，而真实的 TCP 流量完全正常。

        把它当成丢包报出去，读者会去换节点、换机场，换完还是 100%。
        所以这一档必须单独存在：**丢包率量不出来**，而不是"丢包 100%"。
        """
        final = self.final
        return bool(final and not final.answered)

    @property
    def end_to_end_loss(self) -> Optional[float]:
        """终点丢包率 —— 这才是"这条链路丢不丢包"的答案。

        终点从没回过包时返回 None（测不出来），而不是 100.0。
        原始的 100% 仍然留在那一跳的 `loss_pct` 上，不隐瞒。
        """
        if self.endpoint_silent:
            return None
        return self.final.loss_pct if self.final else None

    @property
    def jitter_ms(self) -> Optional[float]:
        if self.endpoint_silent:
            return None
        return self.final.stdev_ms if self.final else None

    @property
    def resolved_kind(self) -> str:
        """mtr 打向的那个地址是什么性质。fake-ip 时整份报告都要改读法。"""
        if not self.resolved:
            return "unknown"
        if is_fake_ip(self.resolved):
            return "fake-ip"
        if is_private(self.resolved):
            return "private"
        return "real"

    @property
    def last_answering(self) -> Optional[Hop]:
        """最后一个回过包的跳。终点不吭声时，路径只到这里为止。"""
        for hop in reversed(self.hops):
            if hop.answered:
                return hop
        return None


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


def resolve_once(target: str, timeout: float = 4.0) -> Optional[str]:
    """target 解析到哪个地址。失败返回 None —— 这一项是加分信息，不能拖垮探测。

    单独解析一次而不是从 mtr 输出里读，是因为终点不回包时 mtr 根本不会
    打印目标地址，而"打向的是不是一个 fake-ip 占位地址"恰恰是那种情况下
    最需要知道的一件事。

    **必须带超时。** DNS 卡住时 `getaddrinfo` 会一直等下去，而这个函数
    在一遍探测开始前要对每个目标各调一次 —— 一个卡住的解析会让整遍
    停在"正在解析目标"，界面上读作"卡死了"。
    """
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError):
        return None
    finally:
        socket.setdefaulttimeout(old)
    for info in infos:
        addr = info[4][0]
        if addr:
            return str(addr)
    return None


# 打向 fake-ip 占位地址的路径探测会"成功"，并给出一个 0.4 毫秒、一跳到达
# 的漂亮结果 —— 那是本机分流器自己应答的，和 Claude 一点关系都没有。
#
# 这种假数字比没有数字危险得多：它会让人以为链路好得不得了。
# 所以这里**拒测并说明原因**，而不是测出来再在旁边写一行小字。
FAKE_IP_REFUSAL = (
    "目标解析到 fake-ip 占位地址，这个地址在公网上不存在。"
    "对它做路径探测只会量到本机的分流器，得出一个一跳、零点几毫秒的假结果，"
    "所以这里不测。\n"
    "要量真实路径，三选一：\n"
    "  A. 在分流器里给这个域名配 real-ip（或关掉 fake-ip），让它解析到真实地址\n"
    "  B. 直接对你的代理节点地址跑 mtr —— 那才是本机能看见的那一段\n"
    "  C. 只看「延迟分解」里的 TCP / TLS，那是真实业务流量量出来的，不受 fake-ip 影响"
)


class _Cancelled(Exception):
    """探测被叫停。内部信号，不外泄。"""


def _run_cancellable(args: list, *, timeout: float,
                     cancel=None) -> subprocess.CompletedProcess:
    """跑一个子进程，中途可以叫停。

    为什么不用 `subprocess.run`：它会一直阻塞到进程结束。一次 mtr 要
    五到十几秒，一遍七个目标就是一两分钟 —— 按下"停止"之后还要等当前
    这一个跑完，界面上读作"停不下来"。所以改成 Popen + 轮询，
    收到取消信号就 terminate。

    没给 cancel 时行为和 `subprocess.run(timeout=…)` 完全一样。
    """
    proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + timeout
    while True:
        try:
            out, err = proc.communicate(timeout=0.25)
            return subprocess.CompletedProcess(args, proc.returncode, out, err)
        except subprocess.TimeoutExpired:
            pass
        if cancel is not None and cancel.is_set():
            proc.terminate()
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
            raise _Cancelled()
        if time.monotonic() >= deadline:
            proc.kill()
            proc.communicate()
            raise subprocess.TimeoutExpired(args, timeout)


def trace(target: str, *, cycles: int = 5, timeout: float = 40.0,
          cancel=None) -> PathReport:
    """跑一次 mtr。

    cycles 默认只有 5 —— 这是一个监控工具的后台任务，不是诊断会话。
    要更准的丢包率，使用者应该手动跑 `mtr -c 100`，那是另一种场合。

    `cancel` 是一个 `threading.Event`，置位时立刻掐掉正在跑的 mtr。
    """
    binary = which()
    if not binary:
        return PathReport(target=target, ok=False,
                          error="未安装 mtr；跑 scripts/install-deps.sh 装它")
    resolved = resolve_once(target)
    if resolved and is_fake_ip(resolved):
        return PathReport(target=target, ok=False, resolved=resolved,
                          error=FAKE_IP_REFUSAL)
    # -n 不做反向解析（快很多，而且我们自己有 rDNS 查询）
    args = [binary, "--json", "-n", "-c", str(cycles), "--", target]
    try:
        proc = _run_cancellable(args, timeout=timeout, cancel=cancel)
    except subprocess.TimeoutExpired:
        return PathReport(target=target, ok=False, error="mtr 超时", resolved=resolved)
    except _Cancelled:
        return PathReport(target=target, ok=False, resolved=resolved,
                          error="被中途停掉了")
    except (OSError, subprocess.SubprocessError) as exc:
        return PathReport(target=target, ok=False, resolved=resolved,
                          error=f"{type(exc).__name__}: {exc}")
    if proc.returncode != 0 and not proc.stdout.strip():
        return PathReport(target=target, ok=False, resolved=resolved,
                          error=explain_failure(proc.stderr or "",
                                                proc.returncode))
    hops = parse_mtr_json(proc.stdout)
    if not hops:
        return PathReport(target=target, ok=False, resolved=resolved,
                          error="mtr 没有返回可用的跳信息")
    return PathReport(target=target, ok=True, hops=hops, resolved=resolved)


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
    """整形成界面要的形状。只出事实，读法交给界面（界面是双语的）。"""
    final = report.final
    silent = report.endpoint_silent
    return {
        "target": report.target,
        "ok": report.ok,
        "error": report.error,
        "resolved": report.resolved,
        "resolved_kind": report.resolved_kind,
        "hop_count": report.hop_count,
        "endpoint_silent": silent,
        "end_to_end_loss": report.end_to_end_loss,
        "jitter_ms": report.jitter_ms,
        # 没回过包时 mtr 会填 0.0。原样透出去就成了"往返 0 毫秒"，
        # 那是这个仓最忌讳的那种假数字。
        "final_avg_ms": None if silent else (final.avg_ms if final else None),
        "last_answering_index": (report.last_answering.index
                                 if report.last_answering else None),
        "hops": [
            {
                "index": h.index, "host": h.host, "loss_pct": h.loss_pct,
                "sent": h.sent,
                "avg_ms": h.avg_ms if h.answered else None,
                "best_ms": h.best_ms if h.answered else None,
                "worst_ms": h.worst_ms if h.answered else None,
                "stdev_ms": h.stdev_ms if h.answered else None,
                "answered": h.answered,
                "private": h.is_private,
                "meaningful_loss": h.loss_is_meaningful,
                "last": bool(final and h.index == final.index),
            }
            for h in report.hops
        ],
    }


__all__ = [
    "FAKE_IP_REFUSAL",
    "Hop",
    "LOSS_WARN_PCT",
    "PathReport",
    "PERMISSION_HINT",
    "available",
    "explain_failure",
    "parse_mtr_json",
    "resolve_once",
    "summarize",
    "trace",
    "which",
]
