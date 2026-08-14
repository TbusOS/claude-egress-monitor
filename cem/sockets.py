"""实时连接枚举：Claude 的进程此刻正连着谁。

用 `lsof` 而不是抓包，理由有三条：
1. 不需要 root，不需要装 BPF / pktap，装了就能跑；
2. **抓包看不到进程归属**，而这个工具的全部价值在于"是 Claude 在连它"；
3. TLS 内容我们不想看也不该看 —— 只需要"连到哪"，不需要"发了什么"。

代价写在下面 `KIND_*` 三种分类里，这是必须讲清楚的一件事：
**走本机 HTTP 代理的进程，`lsof` 看到的目的地是代理自己**，
真实目的地在这里拿不到。桌面端和浏览器正好属于这一类。
补这个缺口的办法是读分流器自己的连接表，见 clash.py。
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Optional

from .model import AsnInfo, Connection
from .paths import SURFACE_CLI, SURFACE_DESKTOP, SURFACE_WEB
from .resolve import is_fake_ip, is_private

KIND_REAL = "real"                # 真实公网目的地，可以查归属
KIND_FAKE = "fake-ip"             # 占位地址，能反查出域名，出口看分流规则
KIND_LOCAL_PROXY = "local-proxy"  # 连的是本机代理，真实目的地不可见
KIND_PRIVATE = "private"          # 内网 / 回环，与出网无关

# 进程匹配。两个实测踩到的坑决定了这里为什么不用 pgrep：
#
# 1. Claude Code 的**进程名是版本号**（例如 `2.1.x`），因为它是从
#    ~/.local/share/claude/versions/<version> 直接执行的单文件可执行。
#    拿 `claude` 去匹配进程名会漏掉它。
# 2. `pgrep -f` 匹配整条命令行，于是任何 cwd 或参数里带 "claude" 字样的
#    进程（**包括本工具自己**，如果仓库放在名字含 claude 的目录下）都会被算进来。
#    而且 macOS 的 pgrep 走 POSIX ERE，`\s` 这类转义不生效。
#
# 改成读 `ps` 再在 Python 里用真正的正则筛，并显式排掉自己和父进程。
SURFACE_MATCHERS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    (SURFACE_CLI, re.compile(r"/\.local/share/claude/versions/[\w.\-]+")),
    (SURFACE_CLI, re.compile(r"(^|/)claude(\s|$)")),
    (SURFACE_DESKTOP, re.compile(r"/Applications/Claude\.app")),
    (SURFACE_WEB, re.compile(
        r"/Applications/(Google Chrome|Safari|Firefox|Arc|"
        r"Microsoft Edge|Brave Browser)\.app"
    )),
)

# 命令行里出现这些就一定不是 Claude 本体 —— 挡掉自我匹配。
SELF_MARKERS: tuple[str, ...] = ("cem", "claude-egress-monitor", "lsof", "pgrep")

# lsof 的 NAME 列：`1.2.3.4:5678->9.10.11.12:443` 或 `[::1]:1->[::2]:443`
_ADDR = re.compile(
    r"^(?P<local>\[[^\]]+\]:\d+|[\d.]+:\d+)->(?P<remote>\[[^\]]+\]:\d+|[\d.]+:\d+)$"
)


def _split_addr(text: str) -> Optional[tuple[str, int]]:
    if text.startswith("["):
        host, _, port = text.rpartition("]:")
        return (host.lstrip("["), int(port)) if port.isdigit() else None
    host, _, port = text.rpartition(":")
    return (host, int(port)) if port.isdigit() else None


def read_ps() -> str:
    """`ps -Ao pid=,args=` 的原始输出。只读，不需要权限。"""
    try:
        proc = subprocess.run(
            ["ps", "-Ao", "pid=,args="], capture_output=True, text=True, timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout


def match_processes(
    ps_output: str,
    *,
    exclude_pids: tuple[int, ...] = (),
) -> dict[int, str]:
    """{pid: surface}。纯函数 —— 喂一段 ps 输出就能测。

    一个 pid 只归一个入口，按 SURFACE_MATCHERS 的顺序先匹配到的赢，
    所以 CLI 的两条规则排在浏览器前面。
    """
    found: dict[int, str] = {}
    for raw in ps_output.splitlines():
        line = raw.strip()
        if not line:
            continue
        pid_str, _, args = line.partition(" ")
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        if pid in exclude_pids:
            continue
        if any(marker in args for marker in SELF_MARKERS):
            continue
        for surface, pattern in SURFACE_MATCHERS:
            if pattern.search(args):
                found = {**found, pid: found.get(pid, surface)}
                break
    return found


def discover_surface_pids() -> dict[int, str]:
    return match_processes(
        read_ps(),
        exclude_pids=(os.getpid(), os.getppid()),
    )


def parse_lsof(text: str, surfaces: dict[int, str]) -> tuple[dict, ...]:
    """解析 `lsof -nP -iTCP -sTCP:ESTABLISHED` 的输出。纯函数。

    返回未经归属enrich的原始记录，enrich 交给 build_connections。
    """
    rows: list[dict] = []
    for line in text.splitlines()[1:]:      # 跳过表头
        cols = line.split()
        if len(cols) < 9:
            continue
        name = cols[-1]
        if name.endswith(")"):
            # 末列可能是 (ESTABLISHED)，地址在它前面
            name = cols[-2]
        m = _ADDR.match(name)
        if not m:
            continue
        try:
            pid = int(cols[1])
        except ValueError:
            continue
        remote = _split_addr(m.group("remote"))
        if not remote:
            continue
        rows.append({
            "pid": pid,
            "command": cols[0],
            "surface": surfaces.get(pid, "other"),
            "local": m.group("local"),
            "remote_ip": remote[0],
            "remote_port": remote[1],
        })
    return tuple(rows)


def run_lsof(pids: tuple[int, ...], timeout: float = 8.0) -> str:
    """只查指定 pid。**空 pid 列表不执行** —— `lsof -p ''` 会列出全机器的
    连接，那是别人的隐私，也会把 UI 灌满噪声。这个坑实测踩过。
    """
    if not pids:
        return ""
    args = ["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-a",
            "-p", ",".join(str(p) for p in sorted(set(pids)))]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout


def classify_remote(ip: str, port: int, proxy: Optional[tuple[str, int]]) -> str:
    if proxy and ip == proxy[0] and port == proxy[1]:
        return KIND_LOCAL_PROXY
    if is_fake_ip(ip):
        return KIND_FAKE
    if is_private(ip):
        # 端口像代理端口的回环连接，即使不在系统代理配置里也按代理算：
        # 用环境变量单独给某个进程配代理时会出现这种情况。
        if ip in ("127.0.0.1", "::1") and port in (7890, 7891, 7897, 8080, 8888,
                                                   1080, 1087, 6152, 9090):
            return KIND_LOCAL_PROXY
        return KIND_PRIVATE
    return KIND_REAL


def build_connections(
    rows: tuple[dict, ...],
    *,
    fake_map: dict[str, str],
    asn_lookup=None,
    proxy: Optional[tuple[str, int]] = None,
    endpoint_lookup=None,
) -> tuple[Connection, ...]:
    """给原始记录补上域名、服务归类、IP 归属。

    asn_lookup / endpoint_lookup 用注入的方式传进来，好处是这个函数
    在测试里可以完全离线跑。
    """
    out: list[Connection] = []
    for row in rows:
        ip, port = row["remote_ip"], row["remote_port"]
        kind = classify_remote(ip, port, proxy)
        host = fake_map.get(ip)
        # 一个 anycast 地址可能对应多个域名，反查表里用 `、` 连接。
        # 归类时取第一个 —— 同一个地址上的域名都属于同一家、通常也同一类。
        first_host = host.split("、")[0] if host else None
        endpoint = endpoint_lookup(first_host) if (first_host and endpoint_lookup) else None
        asn: Optional[AsnInfo] = None
        if kind == KIND_REAL and asn_lookup:
            asn = asn_lookup(ip)
        out.append(Connection(
            pid=row["pid"],
            command=row["command"],
            surface=row["surface"],
            local=row["local"],
            remote_ip=ip,
            remote_port=port,
            kind=kind,
            host=host,
            service=endpoint.category if endpoint else None,
            asn=asn,
        ))
    return tuple(out)


def filter_noise(
    conns: tuple[Connection, ...],
) -> tuple[tuple[Connection, ...], int, int]:
    """去掉与 Claude 无关的浏览器连接，返回 (保留, 丢弃数, 走代理数)。

    为什么必须过滤：浏览器进程同时连着几十个别的站点。把它们全列出来
    有两个问题 —— 界面被噪声灌满，以及**把用户在访问哪些网站写进了
    采样文件**。这个工具没有理由知道那些。

    判据：`web` 入口只保留能归属到 Claude 域名的连接；CLI 和桌面端是
    Claude 自己的进程，它连什么都算相关，全部保留。
    """
    kept: list[Connection] = []
    dropped = 0
    via_proxy = 0
    for c in conns:
        if c.kind == KIND_LOCAL_PROXY:
            via_proxy += 1
            if c.surface == SURFACE_WEB:
                continue
        if c.surface == SURFACE_WEB and not c.host:
            dropped += 1
            continue
        kept.append(c)
    return tuple(kept), dropped, via_proxy


def snapshot(
    *,
    fake_map: dict[str, str],
    asn_lookup=None,
    proxy: Optional[tuple[str, int]] = None,
    endpoint_lookup=None,
) -> tuple[tuple[Connection, ...], int, int]:
    surfaces = discover_surface_pids()
    text = run_lsof(tuple(surfaces))
    rows = parse_lsof(text, surfaces)
    conns = build_connections(
        rows,
        fake_map=fake_map,
        asn_lookup=asn_lookup,
        proxy=proxy,
        endpoint_lookup=endpoint_lookup,
    )
    return filter_noise(conns)


__all__ = [
    "KIND_FAKE",
    "KIND_LOCAL_PROXY",
    "KIND_PRIVATE",
    "KIND_REAL",
    "build_connections",
    "classify_remote",
    "discover_surface_pids",
    "filter_noise",
    "match_processes",
    "parse_lsof",
    "read_ps",
    "run_lsof",
    "snapshot",
]
