"""从本机安装的 Claude Code 里静态提取「遥测会上报哪些字段」。

## 为什么这件事不需要解密

Claude Code 发行为单文件 JS bundle，**没有加密、没有混淆到不可读**。
构造上报 payload 的那段代码是明文，字段名、事件名白名单、
甚至几个函数名（`stripPiiFieldsForDatadog`）都直接读得出来。

所以这个模块做的事是「读你自己电脑上的一个文件」：

- 不修改任何文件
- 不注入任何进程
- 不改变程序行为
- 不解密任何流量

这是本仓愿意做的逆向的**全部边界**。

## 它答不了什么

静态提取只能回答「**会**发哪些字段」，不能回答「**某一次具体**发了什么值」。
后者需要解密 TLS —— 那要装一个根 CA，而一个根 CA 的私钥泄露意味着
你机器上所有 HTTPS 都可被解密。这个代价远大于收益，所以本仓不做，
也不提供做这件事的工具。详见 docs/06-toolbox.md。

## 会不会过期

会。字段随版本变。所以这里**不写死任何字段清单**，每次都从当前安装的
二进制里现读 —— 一份写死的清单过两个版本就是错的，而且没人知道它错了。
"""

from __future__ import annotations

import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Claude Code 的安装位置。进程名是版本号，因为它是从这里直接执行的。
VERSIONS_DIR = Path.home() / ".local" / "share" / "claude" / "versions"

# 上报信封的固定字段，这几个是 Datadog 日志格式要求的。
ENVELOPE_KEYS = ("ddsource", "ddtags", "message", "service", "hostname", "env")

# 这些函数名本身就说明了行为，值得单独列出来给读者看。
BEHAVIOUR_MARKERS = {
    "stripPiiFieldsForDatadog": "上报前主动剥离 PII 字段",
    "collapseToolNameForDatadog": "工具名做归一化后再上报",
    "isPeerRateBoundEvent": "部分事件受速率限制",
    "truncateBuildVersionTag": "版本号标签会被截断",
    "droppedSinceLastForward": "超出配额的事件被丢弃并计数",
    "initializeDatadog": "初始化上报通道",
    "shutdownDatadog": "退出时关闭上报通道",
    "trackDatadogEvent": "单个事件的上报入口",
}


@dataclass(frozen=True)
class TelemetryReport:
    binary: Optional[str] = None
    version: Optional[str] = None
    ok: bool = False
    error: Optional[str] = None
    intake_url: Optional[str] = None
    client_token_prefix: Optional[str] = None
    flush_interval_ms: Optional[int] = None
    batch_limit: Optional[int] = None
    envelope: tuple[tuple[str, str], ...] = ()      # (字段, 固定值或说明)
    payload_fields: tuple[str, ...] = ()
    event_names: tuple[str, ...] = ()
    behaviours: tuple[tuple[str, str], ...] = ()
    env_vars: tuple[str, ...] = ()


def latest_binary() -> Optional[Path]:
    """找最新安装的那个版本。"""
    if not VERSIONS_DIR.is_dir():
        return None
    candidates = [p for p in VERSIONS_DIR.iterdir() if p.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def read_strings(binary: Path, timeout: float = 120.0) -> str:
    try:
        proc = subprocess.run(
            ["strings", "-a", str(binary)],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout


def _longest_line_with(blob: str, needle: str) -> str:
    """取包含 needle 的**最长**那一行。

    `strings` 会把压缩后的 JS 切成很多段，同一个串可能出现在好几段里。
    短的那些只是零碎引用，只有最长的那段才带着周围的构造代码 —— 早先
    取第一条匹配，结果拿到一个 55 字节的碎片，什么都提取不出来。
    """
    best = ""
    for line in blob.splitlines():
        if needle in line and len(line) > len(best):
            best = line
    return best


def parse_bundle(blob: str) -> TelemetryReport:
    """从 strings 输出里提取遥测信息。纯函数，可以喂固定样本测试。"""
    line = _longest_line_with(blob, "http-intake.logs")
    if not line:
        return TelemetryReport(
            ok=False,
            error="在这个二进制里没找到 Datadog intake 的代码段 —— "
                  "可能这个版本改了实现，或者遥测被移除了",
        )

    idx = line.find("http-intake.logs")
    ctx = line[max(0, idx - 3500): idx + 3500]

    url = None
    m = re.search(r'https://http-intake\.logs\.[a-z0-9.\-]+/api/v\d+/logs', ctx)
    if m:
        url = m.group(0)

    token = None
    m = re.search(r'"(pub[a-f0-9]{6})[a-f0-9]*"', ctx)
    if m:
        # 只保留前缀。完整 token 是别人的公开凭据，抄进输出里没有意义，
        # 想看的人自己跑 strings 就有。
        token = m.group(1) + "…"

    flush = None
    m = re.search(r'CLAUDE_CODE_DATADOG_FLUSH_INTERVAL_MS\|\|(\w+)', ctx)
    if m:
        var = m.group(1)
        m2 = re.search(re.escape(var) + r'=(\d+)', ctx)
        if m2:
            flush = int(m2.group(1))

    batch = None
    m = re.search(r'=(\d+),\w+=5000,', ctx)
    if m:
        batch = int(m.group(1))

    envelope: list[tuple[str, str]] = []
    for key in ENVELOPE_KEYS:
        m = re.search(re.escape(key) + r':\s*"([^"]{0,40})"', ctx)
        if m:
            envelope.append((key, m.group(1)))
        elif re.search(re.escape(key) + r'\s*:', ctx):
            envelope.append((key, "（运行时计算）"))

    # 业务字段的提取要挑对模式。早先用「任何 `名字:` 」去抓，抓回来的
    # 全是**函数名**（`initializeDatadog:` 之类），因为压缩后的模块导出
    # 也长这样。真正的 payload 字段有两个可靠特征：
    #   1. 通过 `l.<字段> = ...` 往上报对象上写
    #   2. 命名是 snake_case 或短小写词（JS 代码里的函数是 camelCase）
    assigned = set(re.findall(r'\b[a-z]\.([a-z][a-z0-9_]{1,28})\s*=', ctx))
    literal = set(re.findall(r'\b([a-z][a-z0-9]*_[a-z0-9_]{1,24})\s*:', ctx))
    noise = set(ENVELOPE_KEYS) | {
        "https", "http", "headers", "timeout", "length", "push", "then",
        "catch", "map", "filter", "join", "enqueue", "forEach",
    }
    payload = tuple(sorted(
        k for k in (assigned | literal)
        if k not in noise
        and "datadog" not in k.lower()
        and k not in BEHAVIOUR_MARKERS
    ))[:24]

    events = tuple(sorted(set(re.findall(r'"((?:tengu|chrome_bridge)_[a-z0-9_]{2,40})"', line))))

    behaviours = tuple(
        (name, desc) for name, desc in sorted(BEHAVIOUR_MARKERS.items())
        if name in blob
    )

    raw_envs = set(re.findall(
        r'\b(CLAUDE_CODE_[A-Z0-9_]*(?:DATADOG|TELEMETRY|NONESSENTIAL)[A-Z0-9_]*'
        r'|DISABLE_TELEMETRY|DISABLE_ERROR_REPORTING|OTEL_EXPORTER_OTLP_ENDPOINT)\b',
        blob))
    # `strings` 会把紧跟在变量名后面的那个字节也带出来，于是同一个变量
    # 会出现两遍：`..._NONESSENTIAL_TRAFFIC` 和 `..._NONESSENTIAL_TRAFFICP`。
    # 凡是「另一个已知变量 + 恰好一个字符」的，都是这种毛刺，丢掉。
    env_vars = tuple(sorted(
        name for name in raw_envs
        if not any(other != name and name.startswith(other)
                   and len(name) == len(other) + 1
                   for other in raw_envs)
    ))

    return TelemetryReport(
        ok=True,
        intake_url=url,
        client_token_prefix=token,
        flush_interval_ms=flush,
        batch_limit=batch,
        envelope=tuple(envelope),
        payload_fields=payload,
        event_names=events,
        behaviours=behaviours,
        env_vars=env_vars,
    )


def inspect(binary: Optional[Path] = None) -> TelemetryReport:
    target = binary or latest_binary()
    if target is None:
        return TelemetryReport(
            ok=False,
            error=f"没找到 Claude Code 的安装（找的是 {VERSIONS_DIR}）",
        )
    if not os.access(target, os.R_OK):
        return TelemetryReport(binary=str(target), ok=False, error="文件读不了")
    blob = read_strings(target)
    if not blob:
        return TelemetryReport(binary=str(target), ok=False,
                               error="strings 读不出内容")
    report = parse_bundle(blob)
    return TelemetryReport(
        binary=str(target), version=target.name, ok=report.ok,
        error=report.error, intake_url=report.intake_url,
        client_token_prefix=report.client_token_prefix,
        flush_interval_ms=report.flush_interval_ms,
        batch_limit=report.batch_limit, envelope=report.envelope,
        payload_fields=report.payload_fields, event_names=report.event_names,
        behaviours=report.behaviours, env_vars=report.env_vars,
    )


def redact_home(path: Optional[str]) -> Optional[str]:
    """把家目录换成 `~`。

    Claude Code 装在 `/Users/<用户名>/.local/share/claude/versions/…`，
    这个路径**带着用户名**。界面上没渲染它，但接口返回了 —— 而这个接口的
    输出正是人们会贴进 issue 里求助的东西。贴一次就把用户名公开了。

    纯字符串替换，不碰文件系统。
    """
    if not path:
        return path
    home = str(Path.home())
    if home and path.startswith(home):
        return "~" + path[len(home):]
    return path


def to_json(report: TelemetryReport) -> dict:
    return {
        "binary": redact_home(report.binary), "version": report.version,
        "ok": report.ok, "error": report.error,
        "intake_url": report.intake_url,
        "client_token_prefix": report.client_token_prefix,
        "flush_interval_ms": report.flush_interval_ms,
        "batch_limit": report.batch_limit,
        "envelope": [{"key": k, "value": v} for k, v in report.envelope],
        "payload_fields": list(report.payload_fields),
        "event_names": list(report.event_names),
        "behaviours": [{"name": n, "meaning": d} for n, d in report.behaviours],
        "env_vars": list(report.env_vars),
        "limits": "静态提取只能知道会发哪些字段，不能知道某一次具体发了什么值。"
                  "后者需要解密 TLS，本仓不做 —— 见 docs/06-toolbox.md。",
    }


__all__ = [
    "BEHAVIOUR_MARKERS",
    "ENVELOPE_KEYS",
    "TelemetryReport",
    "inspect",
    "latest_binary",
    "parse_bundle",
    "to_json",
]
