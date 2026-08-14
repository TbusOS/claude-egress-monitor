"""本地 HTTP 服务 + SSE 推送。

安全边界（这几条是硬的）：

- **只监听回环地址**。默认 127.0.0.1，界面和接口都不出本机。
  想跨机访问请自己套 SSH 端口转发，不要给这个进程加认证然后开到局域网 ——
  它读得到你所有 Claude 进程的连接表。
- **静态文件只从 web/ 目录读**，路径先规范化再做前缀校验，挡目录穿越。
- **写接口只接受 POST**，参数逐个校验类型和范围，不接受未知字段。
- 不设置任何 CORS 头 —— 别的网页不该能读这个接口。
"""

from __future__ import annotations

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from . import view
from .model import Sample
from .sampler import Sampler, clamp_interval
from .store import History

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
MAX_BODY = 8 * 1024
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".ico": "image/x-icon",
}


class Broadcaster:
    """把新采样推给所有连着的 SSE 客户端。

    每个客户端一个有界队列：慢客户端（切到后台的标签页）会把队列填满，
    这时**丢它自己的旧消息**，而不是拖住采样线程。
    """

    def __init__(self, maxsize: int = 8):
        self._lock = threading.Lock()
        self._subs: tuple[queue.Queue, ...] = ()
        self._maxsize = maxsize

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._subs = self._subs + (q,)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs = tuple(s for s in self._subs if s is not q)

    def publish(self, payload: dict) -> None:
        with self._lock:
            subs = self._subs
        for q in subs:
            try:
                q.put_nowait(payload)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except (queue.Empty, queue.Full):
                    pass

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._subs)


class _Handler(BaseHTTPRequestHandler):
    server_version = "cem"
    protocol_version = "HTTP/1.1"

    # 注入进来的依赖（由 build_server 塞到类属性上）
    history: History
    sampler: Sampler
    bus: Broadcaster
    web_root: Path

    def log_message(self, fmt: str, *args) -> None:      # noqa: A003
        """默认的 stderr 访问日志会把每次 SSE 心跳都刷出来，关掉。"""
        return

    # ---------------------------------------------------------- 工具

    def _send_json(self, obj: object, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json({"error": message}, status=status)

    def _read_json(self) -> Optional[dict]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _serve_static(self, rel: str) -> None:
        target = (self.web_root / rel.lstrip("/")).resolve()
        root = self.web_root.resolve()
        if not str(target).startswith(str(root)) or not target.is_file():
            self._send_error_json(404, "not found")
            return
        ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        try:
            body = target.read_bytes()
        except OSError:
            self._send_error_json(500, "read failed")
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # ---------------------------------------------------------- 路由

    def do_GET(self) -> None:                            # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._serve_static("index.html")
        elif path == "/api/state":
            self._send_json(view.snapshot(self.history, self.sampler))
        elif path == "/api/status":
            self._send_json(self.sampler.status())
        elif path == "/api/stream":
            self._stream()
        elif path.startswith("/assets/") or path in ("/app.js", "/favicon.ico"):
            self._serve_static(path)
        else:
            self._send_error_json(404, "not found")

    def do_POST(self) -> None:                           # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/monitor":
            self._monitor()
        elif path == "/api/sample":
            sample = self.sampler.sample_now()
            self.bus.publish(view.snapshot(self.history, self.sampler))
            self._send_json({"ok": True, "seq": sample.seq})
        else:
            self._send_error_json(404, "not found")

    def _monitor(self) -> None:
        data = self._read_json()
        if data is None:
            self._send_error_json(400, "需要 JSON 请求体")
            return
        unknown = set(data) - {"enabled", "interval_s"}
        if unknown:
            self._send_error_json(400, f"不认识的字段：{', '.join(sorted(unknown))}")
            return
        interval = data.get("interval_s")
        if interval is not None:
            if not isinstance(interval, (int, float)) or isinstance(interval, bool):
                self._send_error_json(400, "interval_s 必须是数字（秒）")
                return
            interval = clamp_interval(interval)
        enabled = data.get("enabled")
        if enabled is None:
            if interval is None:
                self._send_error_json(400, "至少要给 enabled 或 interval_s")
                return
            self._send_json(self.sampler.set_interval(interval))
            return
        if not isinstance(enabled, bool):
            self._send_error_json(400, "enabled 必须是 true / false")
            return
        if enabled:
            status = self.sampler.start(interval_s=interval)
        else:
            status = self.sampler.stop()
        self.bus.publish(view.snapshot(self.history, self.sampler))
        self._send_json(status)

    def _stream(self) -> None:
        q = self.bus.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self._sse_send({"type": "snapshot",
                            "data": view.snapshot(self.history, self.sampler)})
            while True:
                try:
                    payload = q.get(timeout=15)
                except queue.Empty:
                    # 心跳。没有它，反向代理和浏览器会在静默期掐掉连接。
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                self._sse_send({"type": "snapshot", "data": payload})
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.bus.unsubscribe(q)

    def _sse_send(self, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False)
        self.wfile.write(b"data: " + body.encode("utf-8") + b"\n\n")
        self.wfile.flush()


def build_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    history: Optional[History] = None,
    sampler: Optional[Sampler] = None,
    web_root: Path = WEB_ROOT,
) -> tuple[ThreadingHTTPServer, Sampler, History, Broadcaster]:
    hist = history or History()
    bus = Broadcaster()

    def on_sample(_sample: Sample) -> None:
        bus.publish(view.snapshot(hist, smp))

    smp = sampler or Sampler(hist, on_sample=on_sample)
    if sampler is not None:
        smp._on_sample = on_sample          # noqa: SLF001 —— 组装期注入

    handler = type("Handler", (_Handler,), {
        "history": hist, "sampler": smp, "bus": bus, "web_root": web_root,
    })
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd, smp, hist, bus


__all__ = ["Broadcaster", "WEB_ROOT", "build_server"]
