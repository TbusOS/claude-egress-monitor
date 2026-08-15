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

from . import endpoints as ep
from . import history as histmod
from . import view
from .model import Sample
from .pathwatch import MAX_INTERVAL_S, MIN_INTERVAL_S, PathWatcher
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
    day_store: object
    pathwatch: PathWatcher

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

    def _drain_body(self) -> Optional[dict]:
        """把请求体读干净，顺便解析成 JSON。见 do_POST 里的说明。"""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0:
            return None
        if length > MAX_BODY:
            # 超限的体也要读掉再拒绝，否则这条连接就废了。
            # 分块丢弃而不是一次读进内存 —— 别人给多大就吃多大是个 DoS。
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            return None
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _read_json(self) -> Optional[dict]:
        """请求体。已经在 do_POST 里读完了，这里只是取出来。"""
        return getattr(self, "_body", None)

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
            self._send_json(view.snapshot(self.history, self.sampler,
                                          self.day_store))
        elif path == "/api/days":
            self._send_json(view.day_payload(self.day_store))
        elif path == "/api/day":
            self._day_detail()
        elif path == "/api/path":
            # 一遍要跑一两分钟，所以这里只读结果；跑是后台线程干的。
            self._send_json(view.path_panel(self.pathwatch))
        elif path == "/api/telemetry":
            # 这一项要跑 strings 扫一个 300MB 的文件，比较慢，
            # 所以不塞进 /api/state，单独按需拉。
            self._send_json(view.telemetry_payload())
        elif path == "/api/status":
            self._send_json(self.sampler.status())
        elif path == "/api/stream":
            self._stream()
        elif path.startswith("/assets/") or path in ("/app.js", "/favicon.ico"):
            self._serve_static(path)
        else:
            self._send_error_json(404, "not found")

    def do_POST(self) -> None:                           # noqa: N802
        # HTTP/1.1 是 keep-alive 的，所以**请求体必须读完**，哪怕这个路由
        # 根本不需要它。没读完的字节留在 socket 里，会被当成下一个请求的
        # 开头 —— 症状是下一次请求莫名其妙 501
        # `Unsupported method ('{}GET')`，而且只在连接被复用时出现，
        # 单独用 curl 打一次永远复现不了。
        #
        # 所以在这里统一读一次，路由自己不用管这件事 —— 靠每个路由记得读，
        # 迟早会有一个忘掉，而这一类 bug 极难查。
        self._body = self._drain_body()
        path = self.path.split("?", 1)[0]
        if path == "/api/monitor":
            self._monitor()
        elif path == "/api/days/delete":
            self._delete_days()
        elif path == "/api/path/auto":
            self._path_auto()
        elif path == "/api/path/sweep":
            self._send_json(self.pathwatch.sweep_soon())
        elif path == "/api/sample":
            sample = self.sampler.sample_now()
            self.bus.publish(view.snapshot(self.history, self.sampler,
                                           self.day_store))
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
        self.bus.publish(view.snapshot(self.history, self.sampler,
                                       self.day_store))
        self._send_json(status)

    def _path_auto(self) -> None:
        """路径质量的自动探测开关。参数和 /api/monitor 一样的形状。"""
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
            interval = max(MIN_INTERVAL_S, min(MAX_INTERVAL_S, int(interval)))
        enabled = data.get("enabled")
        if enabled is None:
            if interval is None:
                self._send_error_json(400, "至少要给 enabled 或 interval_s")
                return
            self._send_json(self.pathwatch.set_interval(interval))
            return
        if not isinstance(enabled, bool):
            self._send_error_json(400, "enabled 必须是 true / false")
            return
        if enabled:
            self._send_json(self.pathwatch.start(interval_s=interval))
        else:
            self._send_json(self.pathwatch.stop())

    def _day_detail(self) -> None:
        """某一天（或几天）的汇总。参数 ?day=YYYY-MM-DD，可重复。"""
        from urllib.parse import parse_qs, urlparse as _urlparse
        query = parse_qs(_urlparse(self.path).query)
        days = query.get("day") or []
        bad = [d for d in days if not histmod.valid_day(d)]
        if bad:
            self._send_error_json(400, f"日期格式不对：{', '.join(bad)}")
            return
        if not days:
            self._send_error_json(400, "至少要给一个 day 参数")
            return
        store = self.day_store
        if store is None or not store.enabled:
            self._send_error_json(404, "没有开启历史归档")
            return
        summaries = store.summaries(days)
        self._send_json({
            "days": list(summaries),
            "combined": histmod.combine(summaries),
        })

    def _delete_days(self) -> None:
        """删掉指定的几天。历史会越攒越多，删除必须是一等功能。"""
        data = self._read_json()
        if data is None:
            self._send_error_json(400, "需要 JSON 请求体")
            return
        unknown = set(data) - {"days"}
        if unknown:
            self._send_error_json(400, f"不认识的字段：{', '.join(sorted(unknown))}")
            return
        days = data.get("days")
        if not isinstance(days, list) or not days:
            self._send_error_json(400, "days 必须是非空数组")
            return
        if not all(isinstance(d, str) for d in days):
            self._send_error_json(400, "days 里必须都是字符串")
            return
        store = self.day_store
        if store is None or not store.enabled:
            self._send_error_json(404, "没有开启历史归档")
            return
        done, rejected = store.delete(days)
        if rejected:
            self._send_error_json(
                400, f"这些日期不合法或删不掉：{', '.join(rejected)}")
            return
        self._send_json({"deleted": list(done),
                         "remaining": list(store.days())})

    def _stream(self) -> None:
        q = self.bus.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self._sse_send({"type": "snapshot",
                            "data": view.snapshot(self.history, self.sampler,
                                                  self.day_store)})
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
    day_store=None,
    pathwatch: Optional[PathWatcher] = None,
) -> tuple[ThreadingHTTPServer, Sampler, History, Broadcaster]:
    hist = history or History()
    bus = Broadcaster()
    # 路径质量的目标 = Claude 的域名 + 对照组。对照组在这里是有用的：
    # 到 1.1.1.1 的路径正常而到 Claude 的不正常，说明问题在后半段。
    watcher = pathwatch or PathWatcher(
        lambda: ep.claude_egress_hosts() + ("1.1.1.1",))

    def on_sample(_sample: Sample) -> None:
        bus.publish(view.snapshot(hist, smp, day_store))

    smp = sampler or Sampler(hist, on_sample=on_sample)
    if sampler is not None:
        smp._on_sample = on_sample          # noqa: SLF001 —— 组装期注入

    handler = type("Handler", (_Handler,), {
        "history": hist, "sampler": smp, "bus": bus, "web_root": web_root,
        "day_store": day_store, "pathwatch": watcher,
    })
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd, smp, hist, bus


__all__ = ["Broadcaster", "WEB_ROOT", "build_server"]
