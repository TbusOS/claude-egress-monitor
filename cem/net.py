"""带分段计时的 HTTPS 客户端，支持直连与 HTTP CONNECT 代理两条路径。

为什么不用 urllib / requests：
1. 拿不到 DNS / TCP / TLS / TTFB 的分段耗时，而"慢"这个现象的四种原因
   只有分段之后才分得开。
2. 拿不到这条 TCP 实际连到了哪个对端地址 —— 而在 fake-ip 环境里，
   这个地址和 DNS 查出来的完全是两回事。
3. 要能在同一次进程里既走直连、又走系统代理，用来复现"不同入口不同出口"。

只用标准库。
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from .model import Timing

DEFAULT_TIMEOUT = 8.0
DEFAULT_UA = "claude-egress-monitor/0.1 (+https://github.com/)"
MAX_BODY = 64 * 1024
# 探测响应几百字节就够，64KB 是给意外情况留的余量。但有些数据源
# （AWS 的官方 IP 段清单 2.5MB）本来就很大，截断了会静默解析失败 ——
# 症状是"这个源解析不出前缀"，看不出是截断造成的。所以要能按需放开。
MAX_BODY_LARGE = 8 * 1024 * 1024


@dataclass(frozen=True)
class TlsInfo:
    """这次 TLS 握手拿到的证书信息。

    为什么要采：**中间人劫持最直接的证据就在证书里**。正常访问
    claude.ai 拿到的应该是公共 CA（Let's Encrypt / Google Trust 之类）
    签发、SAN 里含 claude.ai 的证书。如果某天颁发者变成了一个企业
    自签根、或者 SAN 对不上，说明有东西在中间拆开了你的 TLS ——
    公司设备管理软件、某些"加速"客户端、以及真正的攻击都会这样。

    只读证书的公开字段，不做任何解密。
    """

    version: Optional[str] = None       # TLSv1.3 …
    cipher: Optional[str] = None
    issuer: Optional[str] = None        # 颁发者组织名
    subject: Optional[str] = None       # 证书主体 CN
    not_after: Optional[str] = None     # 到期时间
    days_left: Optional[int] = None
    san_count: Optional[int] = None
    san_match: Optional[bool] = None    # SAN 里有没有这次访问的域名
    alpn: Optional[str] = None          # 协商出来的应用层协议


@dataclass(frozen=True)
class HttpResult:
    ok: bool
    status: Optional[int] = None
    body: str = ""
    peer_ip: Optional[str] = None
    peer_port: Optional[int] = None
    timing: Timing = Timing()
    error: Optional[str] = None
    # 代理路径下 DNS 由代理服务器完成，本机这一段只解析了代理地址本身。
    dns_by_proxy: bool = False
    tls: Optional[TlsInfo] = None


def _ms(t0: float, t1: float) -> float:
    return round((t1 - t0) * 1000, 2)


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # **只**申报 http/1.1。本模块发的是 HTTP/1.1 请求，一旦申报了 h2
    # 就会和服务端协商出 HTTP/2，然后服务端用 h2 帧回话、这里按 1.1 解析，
    # 整个探测直接失败。加 ALPN 的那一刻这个 bug 就出现了，
    # 现象是所有 trace 全部 ok=False —— 教训：ALPN 要和你真会说的协议一致。
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return ctx


def _name_of(pairs) -> Optional[str]:
    """把 ssl 模块给的 ((('organizationName','X'),), …) 结构压成一个名字。

    优先组织名，没有就退到 CN —— 读者要认的是"谁签的"，
    而 Let's Encrypt 这类只有 CN。
    """
    if not pairs:
        return None
    flat = {}
    for rdn in pairs:
        for key, value in rdn:
            flat.setdefault(key, value)
    return flat.get("organizationName") or flat.get("commonName")


def read_tls_info(sock: "ssl.SSLSocket", host: str) -> TlsInfo:
    """从已完成握手的连接上读证书信息。不发任何额外请求。"""
    try:
        cert = sock.getpeercert() or {}
    except (ValueError, OSError):
        cert = {}
    cipher = None
    try:
        got = sock.cipher()
        cipher = got[0] if got else None
    except (ValueError, OSError):
        pass

    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        try:
            expiry = ssl.cert_time_to_seconds(not_after)
            days_left = int((expiry - time.time()) // 86400)
        except (ValueError, TypeError):
            days_left = None

    alt = cert.get("subjectAltName") or ()
    sans = [v for k, v in alt if k == "DNS"]
    ip_sans = [v for k, v in alt if k == "IP Address"]
    match = None
    # 按 IP 直连时（对照组 1.1.1.1 就是这样），证书里的**域名** SAN 当然
    # 对不上，要比的是 IP SAN。早先只比 DNS SAN，于是每轮都报一次
    # "证书 SAN 对不上"的严重告警 —— 一个假阳性的安全告警比没有告警更糟，
    # 因为它会让人开始忽略这一栏。
    looks_like_ip = host.replace(".", "").isdigit() or ":" in host
    if looks_like_ip:
        match = host in ip_sans if ip_sans else None
    elif sans:
        needle = host.lower()
        match = any(
            needle == s.lower() or
            (s.startswith("*.") and needle.endswith(s[1:].lower()))
            for s in sans
        )

    alpn = None
    try:
        alpn = sock.selected_alpn_protocol()
    except (AttributeError, OSError):
        pass

    return TlsInfo(
        version=getattr(sock, "version", lambda: None)(),
        cipher=cipher,
        issuer=_name_of(cert.get("issuer")),
        subject=_name_of(cert.get("subject")),
        not_after=not_after,
        days_left=days_left,
        san_count=len(sans) or None,
        san_match=match,
        alpn=alpn,
    )


def _read_until_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    """读到 header 结束，返回 (header 块, 已经多读进来的 body 片段)。"""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_BODY:
            break
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _status_of(head: bytes) -> Optional[int]:
    first = head.split(b"\r\n", 1)[0].split()
    if len(first) >= 2 and first[1].isdigit():
        return int(first[1])
    return None


def parse_headers(head: bytes) -> dict[str, str]:
    """响应头 → 小写键的字典。纯函数。"""
    out: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        key, sep, val = line.partition(b":")
        if sep:
            out[key.strip().decode("latin-1").lower()] = \
                val.strip().decode("latin-1")
    return out


def dechunk(body: bytes) -> bytes:
    """解 `Transfer-Encoding: chunked`。

    为什么必须自己解：DoH 的 JSON 接口回的就是 chunked，不解开
    直接 `json.loads` 永远失败 —— 这个 bug 让"解析对账"整块功能
    看起来像"DoH 服务不可用"，实际上是本地解析写漏了。
    纯函数，好测。
    """
    out = bytearray()
    rest = body
    first = True
    while True:
        line, sep, rest = rest.partition(b"\r\n")
        if not sep:
            # 第一段就没有 chunk 头 → 这段根本不是 chunked，原样退回。
            return body if first else bytes(out)
        first = False
        size_token = line.split(b";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            # 不是合法 chunk 头 —— 说明这段其实不是 chunked，原样退回。
            return body
        if size == 0:
            break
        out += rest[:size]
        rest = rest[size:]
        if rest[:2] == b"\r\n":
            rest = rest[2:]
    return bytes(out)


def _connect_via_proxy(
    proxy_host: str,
    proxy_port: int,
    host: str,
    port: int,
    timeout: float,
) -> socket.socket:
    """对代理发 CONNECT，建一条到目标的隧道。

    这条路径复刻的是 Chromium / Electron（也就是 Claude 桌面端和浏览器）
    在设置了系统代理时的行为：DNS 交给代理做，本机只认识代理的地址。
    """
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        req = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: {DEFAULT_UA}\r\n"
            f"Proxy-Connection: keep-alive\r\n\r\n"
        ).encode()
        sock.sendall(req)
        head, _ = _read_until_headers(sock)
        status = _status_of(head)
        if status != 200:
            raise OSError(f"代理拒绝 CONNECT：{status} {head[:120]!r}")
        return sock
    except Exception:
        sock.close()
        raise


def timed_get(
    url: str,
    *,
    proxy: Optional[tuple[str, int]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    family: int = 0,
    headers: Optional[dict[str, str]] = None,
    max_body: int = MAX_BODY,
) -> HttpResult:
    """发一次 GET，返回分段耗时 + 实际对端地址 + 响应体。

    family 传 socket.AF_INET / AF_INET6 可以强制协议族 —— 同一个域名
    走 v4 和走 v6 出口可能落在不同国家，这个参数就是为了把这件事量出来。
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return HttpResult(ok=False, error=f"不支持的协议：{parsed.scheme}")
    host = parsed.hostname or ""
    if not host:
        return HttpResult(ok=False, error="URL 里没有主机名")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    t_start = time.perf_counter()
    timing_dns: Optional[float] = None
    timing_tcp: Optional[float] = None
    timing_tls: Optional[float] = None
    timing_ttfb: Optional[float] = None
    sock: Optional[socket.socket] = None

    try:
        if proxy:
            t0 = time.perf_counter()
            socket.getaddrinfo(proxy[0], proxy[1], family or socket.AF_UNSPEC,
                               socket.SOCK_STREAM)
            timing_dns = _ms(t0, time.perf_counter())
            t0 = time.perf_counter()
            if parsed.scheme == "https":
                sock = _connect_via_proxy(proxy[0], proxy[1], host, port, timeout)
            else:
                sock = socket.create_connection(proxy, timeout=timeout)
                path = url  # 明文 HTTP 走代理要发绝对 URI
            timing_tcp = _ms(t0, time.perf_counter())
        else:
            t0 = time.perf_counter()
            infos = socket.getaddrinfo(host, port, family or socket.AF_UNSPEC,
                                       socket.SOCK_STREAM)
            timing_dns = _ms(t0, time.perf_counter())
            if not infos:
                return HttpResult(ok=False, error="解析不到地址")
            af, stype, proto, _canon, addr = infos[0]
            t0 = time.perf_counter()
            sock = socket.socket(af, stype, proto)
            sock.settimeout(timeout)
            sock.connect(addr)
            timing_tcp = _ms(t0, time.perf_counter())

        peer = sock.getpeername()
        peer_ip, peer_port = str(peer[0]), int(peer[1])

        tls_info: Optional[TlsInfo] = None
        if parsed.scheme == "https":
            t0 = time.perf_counter()
            sock = _tls_context().wrap_socket(sock, server_hostname=host)
            timing_tls = _ms(t0, time.perf_counter())
            tls_info = read_tls_info(sock, host)

        hdrs = {
            "Host": host if port in (80, 443) else f"{host}:{port}",
            "User-Agent": DEFAULT_UA,
            "Accept": "*/*",
            "Connection": "close",
            "Cache-Control": "no-store",
        }
        if headers:
            hdrs = {**hdrs, **headers}
        raw = f"GET {path} HTTP/1.1\r\n" + "".join(
            f"{k}: {v}\r\n" for k, v in hdrs.items()
        ) + "\r\n"

        t0 = time.perf_counter()
        sock.sendall(raw.encode())
        head, rest = _read_until_headers(sock)
        timing_ttfb = _ms(t0, time.perf_counter())
        status = _status_of(head)
        resp_headers = parse_headers(head)

        body = rest
        declared = resp_headers.get("content-length")
        want = None
        if declared and declared.isdigit():
            want = min(int(declared), max_body)
        while len(body) < max_body and (want is None or len(body) < want):
            chunk = sock.recv(8192)
            if not chunk:
                break
            body += chunk
        if resp_headers.get("transfer-encoding", "").lower().find("chunked") >= 0:
            body = dechunk(body)

        return HttpResult(
            ok=status is not None and 200 <= status < 400,
            status=status,
            body=body.decode("utf-8", "replace"),
            peer_ip=peer_ip,
            peer_port=peer_port,
            dns_by_proxy=bool(proxy),
            tls=tls_info,
            timing=Timing(
                dns_ms=timing_dns,
                tcp_ms=timing_tcp,
                tls_ms=timing_tls,
                ttfb_ms=timing_ttfb,
                total_ms=_ms(t_start, time.perf_counter()),
            ),
        )
    except Exception as exc:                     # noqa: BLE001 —— 探测失败本身是结果
        return HttpResult(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            dns_by_proxy=bool(proxy),
            timing=Timing(
                dns_ms=timing_dns,
                tcp_ms=timing_tcp,
                tls_ms=timing_tls,
                ttfb_ms=timing_ttfb,
                total_ms=_ms(t_start, time.perf_counter()),
            ),
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def tcp_probe(
    host: str,
    port: int = 443,
    *,
    proxy: Optional[tuple[str, int]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> HttpResult:
    """只握手不发请求 —— 给没有 trace 端点的域名（遥测 intake）量可达性和延迟。

    故意不发任何 HTTP 请求：往遥测 intake 发数据是污染别人的数据，
    也会让这个监控工具自己变成一个上报源。
    """
    t_start = time.perf_counter()
    sock: Optional[socket.socket] = None
    timing_dns: Optional[float] = None
    timing_tcp: Optional[float] = None
    timing_tls: Optional[float] = None
    try:
        if proxy:
            t0 = time.perf_counter()
            socket.getaddrinfo(proxy[0], proxy[1], socket.AF_UNSPEC, socket.SOCK_STREAM)
            timing_dns = _ms(t0, time.perf_counter())
            t0 = time.perf_counter()
            sock = _connect_via_proxy(proxy[0], proxy[1], host, port, timeout)
            timing_tcp = _ms(t0, time.perf_counter())
        else:
            t0 = time.perf_counter()
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            timing_dns = _ms(t0, time.perf_counter())
            af, stype, proto, _c, addr = infos[0]
            t0 = time.perf_counter()
            sock = socket.socket(af, stype, proto)
            sock.settimeout(timeout)
            sock.connect(addr)
            timing_tcp = _ms(t0, time.perf_counter())

        peer = sock.getpeername()
        t0 = time.perf_counter()
        sock = _tls_context().wrap_socket(sock, server_hostname=host)
        timing_tls = _ms(t0, time.perf_counter())
        return HttpResult(
            ok=True,
            peer_ip=str(peer[0]),
            peer_port=int(peer[1]),
            dns_by_proxy=bool(proxy),
            tls=read_tls_info(sock, host),
            timing=Timing(
                dns_ms=timing_dns, tcp_ms=timing_tcp, tls_ms=timing_tls,
                total_ms=_ms(t_start, time.perf_counter()),
            ),
        )
    except Exception as exc:                     # noqa: BLE001
        return HttpResult(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            dns_by_proxy=bool(proxy),
            timing=Timing(
                dns_ms=timing_dns, tcp_ms=timing_tcp, tls_ms=timing_tls,
                total_ms=_ms(t_start, time.perf_counter()),
            ),
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


__all__ = [
    "DEFAULT_TIMEOUT",
    "TlsInfo",
    "read_tls_info",
    "DEFAULT_UA",
    "HttpResult",
    "dechunk",
    "parse_headers",
    "tcp_probe",
    "timed_get",
]
