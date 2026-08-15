"""本地 HTTP 层的测试。

只打回环地址上的自己，不发任何外部请求 —— 用的路由都不会触发探测。

这里钉的是一类**只在连接复用时出现**的 bug：HTTP/1.1 默认 keep-alive，
POST 的请求体如果没被读完，剩下的字节会被当成下一个请求的开头。
症状是下一次请求回 501 `Unsupported method ('{}GET')`，而单独用 curl
打一次永远复现不了 —— 所以必须有用例。
"""

from __future__ import annotations

import http.client
import threading
import unittest

from cem.server import build_server
from cem.store import History


class _Server:
    """起一个真的服务，端口交给系统分配。"""

    def __enter__(self):
        self.httpd, self.sampler, self.history, self.bus = build_server(
            host="127.0.0.1", port=0, history=History())
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        return False


class TestKeepAliveBodyDrain(unittest.TestCase):
    def test_unread_post_body_does_not_corrupt_the_next_request(self):
        """POST 到一个不读请求体的路由之后，同一条连接上的下一个请求要正常。

        修之前：未读的 `{}` 留在 socket 里 → 下一个请求变成 `{}GET /...`
        → 501。界面上表现为"点了按钮，然后别的地方随机开始报错"。
        """
        with _Server() as srv:
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            # 404 路由，明确不读请求体
            conn.request("POST", "/api/nope", body=b"{}",
                         headers={"Content-Type": "application/json"})
            first = conn.getresponse()
            first.read()
            self.assertEqual(first.status, 404)

            # 同一条连接上的第二个请求
            conn.request("GET", "/api/status")
            second = conn.getresponse()
            body = second.read()
            self.assertEqual(second.status, 200, body[:200])
            conn.close()

    def test_oversized_body_is_rejected_without_breaking_the_connection(self):
        """超限的请求体要读掉再拒绝 —— 直接不读的话这条连接后面全乱。"""
        with _Server() as srv:
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
            conn.request("POST", "/api/monitor", body=b"x" * (9 * 1024),
                         headers={"Content-Type": "application/json"})
            first = conn.getresponse()
            first.read()
            self.assertEqual(first.status, 400)

            conn.request("GET", "/api/status")
            second = conn.getresponse()
            second.read()
            self.assertEqual(second.status, 200)
            conn.close()


class TestPathAutoValidation(unittest.TestCase):
    """写接口的参数校验。这些路由能启动会发 ICMP 的后台任务，
    所以只测被拒绝的那些分支 —— 通过的分支会真的跑 mtr。"""

    def _post(self, srv, path, body):
        conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
        conn.request("POST", path, body=body.encode("utf-8"),
                     headers={"Content-Type": "application/json"})
        res = conn.getresponse()
        payload = res.read()
        conn.close()
        return res.status, payload.decode("utf-8")

    def test_unknown_field_is_rejected(self):
        with _Server() as srv:
            status, body = self._post(srv, "/api/path/auto",
                                      '{"enabled": false, "wat": 1}')
            self.assertEqual(status, 400)
            self.assertIn("wat", body)

    def test_enabled_must_be_boolean(self):
        with _Server() as srv:
            status, _ = self._post(srv, "/api/path/auto", '{"enabled": "yes"}')
            self.assertEqual(status, 400)

    def test_empty_body_is_rejected(self):
        with _Server() as srv:
            status, _ = self._post(srv, "/api/path/auto", "{}")
            self.assertEqual(status, 400)

    def test_turning_it_off_is_always_allowed(self):
        """关闭不该被任何校验挡住 —— 关不掉的开关比没有开关更糟。"""
        with _Server() as srv:
            status, _ = self._post(srv, "/api/path/auto", '{"enabled": false}')
            self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
