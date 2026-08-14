"""解析器的单元测试。

这一层是本仓最该被测试的地方：每个函数都是「一段真实工具的输出 → 结构化数据」，
输入可以照抄真实样本，断言明确，而且**解析错了不会报错、只会静默给出错误结论**
—— 这类 bug 只有测试能拦。

全部离线，不发任何请求。
"""

from __future__ import annotations

import unittest

from cem import asn, clash, net, paths, probe, resolve, sockets


class TestHttpParsing(unittest.TestCase):
    def test_dechunk_joins_chunks(self):
        self.assertEqual(net.dechunk(b"5\r\nhello\r\n0\r\n\r\n"), b"hello")
        self.assertEqual(
            net.dechunk(b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"), b"abcdefg"
        )

    def test_dechunk_honours_chunk_extensions(self):
        self.assertEqual(net.dechunk(b"5;foo=bar\r\nhello\r\n0\r\n\r\n"), b"hello")

    def test_dechunk_passes_through_plain_body(self):
        """不是 chunked 的正文必须原样返回。

        这个用例存在的原因：早先的实现遇到没有 chunk 头的正文会返回空串，
        于是 DoH 的 JSON 永远解析失败，症状表现成「DoH 服务不可用」。
        """
        body = b'{"Status":0}'
        self.assertEqual(net.dechunk(body), body)

    def test_parse_headers_lowercases_keys(self):
        head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Transfer-Encoding: chunked")
        got = net.parse_headers(head)
        self.assertEqual(got["content-type"], "application/json")
        self.assertEqual(got["transfer-encoding"], "chunked")

    def test_parse_trace_reads_key_values(self):
        text = (
            "fl=1244f51\n"
            "h=claude.ai\n"
            "ip=203.0.113.24\n"
            "loc=SG\n"
            "colo=SIN\n"
            "http=http/2\n"
            "tls=TLSv1.3\n"
            "warp=off\n"
        )
        got = probe.parse_trace(text)
        self.assertEqual(got["ip"], "203.0.113.24")
        self.assertEqual(got["loc"], "SG")
        self.assertEqual(got["colo"], "SIN")

    def test_parse_trace_tolerates_junk(self):
        self.assertEqual(probe.parse_trace(""), {})
        self.assertEqual(probe.parse_trace("no equals sign here"), {})


class TestProxyConfigParsing(unittest.TestCase):
    SCUTIL_PROXY = """<dictionary> {
  ExceptionsList : <array> {
    0 : 127.0.0.1
    1 : localhost
  }
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
  ProxyAutoConfigEnable : 0
  SOCKSEnable : 1
  SOCKSPort : 7890
}
"""

    def test_system_proxy_reads_https_pair(self):
        self.assertEqual(paths.system_proxy(self.SCUTIL_PROXY), ("127.0.0.1", 7890))

    def test_system_proxy_none_when_disabled(self):
        text = self.SCUTIL_PROXY.replace("HTTPSEnable : 1", "HTTPSEnable : 0")
        self.assertIsNone(paths.system_proxy(text))

    def test_pac_detected(self):
        text = self.SCUTIL_PROXY.replace(
            "ProxyAutoConfigEnable : 0", "ProxyAutoConfigEnable : 1"
        )
        self.assertTrue(paths.system_proxy_is_pac(text))
        self.assertFalse(paths.system_proxy_is_pac(self.SCUTIL_PROXY))

    def test_parse_scutil_proxy_ignores_array_lines(self):
        got = paths.parse_scutil_proxy(self.SCUTIL_PROXY)
        self.assertIn("HTTPSProxy", got)
        # 数组里的 "0 : 127.0.0.1" 不该被当成配置项
        self.assertNotIn("0", got)


class TestDnsParsing(unittest.TestCase):
    def test_parse_doh_takes_a_and_aaaa(self):
        payload = (
            '{"Status":0,"Answer":['
            '{"name":"x","type":5,"data":"cname.example."},'
            '{"name":"x","type":1,"data":"192.0.2.10"},'
            '{"name":"x","type":28,"data":"2001:db8::1"}]}'
        )
        self.assertEqual(resolve.parse_doh(payload),
                         ("192.0.2.10", "2001:db8::1"))

    def test_parse_doh_bad_input(self):
        self.assertEqual(resolve.parse_doh("not json"), ())
        self.assertEqual(resolve.parse_doh('{"Status":3}'), ())

    SCUTIL_DNS = """DNS configuration

resolver #1
  nameserver[0] : 192.0.2.1
  if_index : 14 (en0)

resolver #2
  domain   : api.anthropic.com
  nameserver[0] : 198.51.100.254

resolver #3
  domain   : anthropic.com
  nameserver[0] : 198.51.100.254
"""

    def test_parse_scutil_dns_maps_domain_to_nameserver(self):
        table = resolve.parse_scutil_dns(self.SCUTIL_DNS)
        self.assertEqual(table["api.anthropic.com"], "198.51.100.254")
        self.assertEqual(table["anthropic.com"], "198.51.100.254")
        # 没有 domain 的解析器不该进表
        self.assertEqual(len(table), 2)

    def test_resolver_for_uses_longest_suffix(self):
        table = {"anthropic.com": "a", "api.anthropic.com": "b"}
        self.assertEqual(resolve.resolver_for("api.anthropic.com", table), "b")
        self.assertEqual(resolve.resolver_for("other.anthropic.com", table), "a")
        self.assertIsNone(resolve.resolver_for("claude.ai", table))

    def test_resolver_for_does_not_match_partial_labels(self):
        """`notanthropic.com` 不该匹配 `anthropic.com`。"""
        table = {"anthropic.com": "a"}
        self.assertIsNone(resolve.resolver_for("notanthropic.com", table))

    def test_fake_ip_detection(self):
        self.assertTrue(resolve.is_fake_ip("198.18.0.140"))
        self.assertTrue(resolve.is_fake_ip("198.19.255.255"))
        self.assertFalse(resolve.is_fake_ip("198.51.100.1"))
        self.assertFalse(resolve.is_fake_ip("not an ip"))

    def test_private_excludes_fake_ip(self):
        """fake-ip 段技术上是保留段，但它**不是**内网地址 —— 分类要分开，
        否则占位地址会被归到「与出网无关」里而被忽略。"""
        self.assertTrue(resolve.is_private("127.0.0.1"))
        self.assertTrue(resolve.is_private("192.168.1.1"))
        self.assertFalse(resolve.is_private("198.18.0.140"))
        self.assertFalse(resolve.is_private("8.8.8.8"))

    def test_documentation_ranges_count_as_private(self):
        """RFC 5737 的文档保留段（192.0.2/24 等）在 IANA 的特殊用途登记里
        就是不可路由的，Python 的 ipaddress 也这么判。记一条用例说明这不是
        意外 —— 这些地址只会出现在演示数据里，不会是任何人的真实出口。"""
        for ip in ("192.0.2.1", "198.51.100.1", "203.0.113.1"):
            self.assertTrue(resolve.is_private(ip))

    def test_classify_covers_each_verdict(self):
        kind, note = resolve.classify(("198.18.0.5",), ("192.0.2.1",), None)
        self.assertEqual(kind, "fake-ip")
        self.assertIn("占位", note)

        kind, _ = resolve.classify(("192.0.2.1",), ("192.0.2.1",), None)
        self.assertEqual(kind, "real")

        kind, note = resolve.classify(("192.0.2.9",), ("192.0.2.1",), "198.51.100.2")
        self.assertEqual(kind, "mismatch")
        self.assertIn("198.51.100.2", note)

        kind, _ = resolve.classify((), (), None)
        self.assertEqual(kind, "error")

        kind, _ = resolve.classify(("192.0.2.1",), (), None)
        self.assertEqual(kind, "unknown")


class TestAsnParsing(unittest.TestCase):
    def test_parse_cymru_origin(self):
        lines = ['"399358 | 192.0.2.0/24 | US | arin | 2023-09-14"']
        got = asn.parse_cymru_origin(lines)
        self.assertEqual(got, {"asn": "AS399358", "prefix": "192.0.2.0/24",
                               "country": "US"})

    def test_parse_cymru_name(self):
        lines = ['"399358 | US | arin | 2023-09-20 | EXAMPLE - Example, Inc., US"']
        self.assertEqual(asn.parse_cymru_name(lines),
                         "EXAMPLE - Example, Inc., US")

    def test_parse_cymru_handles_empty(self):
        self.assertIsNone(asn.parse_cymru_origin([]))
        self.assertIsNone(asn.parse_cymru_name(["garbage"]))

    def test_reverse_name_ipv4(self):
        self.assertEqual(asn._reverse_name("192.0.2.10"),
                         "10.2.0.192.origin.asn.cymru.com")

    def test_reverse_name_ipv6_uses_origin6(self):
        got = asn._reverse_name("2001:db8::1")
        self.assertTrue(got.endswith(".origin6.asn.cymru.com"))
        self.assertTrue(got.startswith("1.0.0.0."))

    def test_reverse_name_rejects_junk(self):
        self.assertIsNone(asn._reverse_name("nope"))

    def test_parse_ipinfo_splits_asn_from_org(self):
        payload = ('{"ip":"192.0.2.10","city":"San Francisco","country":"US",'
                   '"org":"AS399358 Example, Inc.","anycast":true}')
        got = asn.parse_ipinfo(payload, "192.0.2.10")
        self.assertEqual(got.asn, "AS399358")
        self.assertEqual(got.org, "Example, Inc.")
        self.assertEqual(got.city, "San Francisco")
        self.assertTrue(got.anycast)

    def test_parse_ipinfo_rejects_bogon(self):
        self.assertIsNone(asn.parse_ipinfo('{"ip":"10.0.0.1","bogon":true}',
                                           "10.0.0.1"))


class TestLsofParsing(unittest.TestCase):
    LSOF = """COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
2.1.x   14708  demo    7u  IPv4 0x0000000000000000      0t0  TCP 198.18.0.1:51851->198.18.0.140:443 (ESTABLISHED)
2.1.x   14708  demo   17u  IPv4 0x0000000000000000      0t0  TCP 192.0.2.9:50514->192.0.2.40:443 (ESTABLISHED)
Claude     2002  demo   13u  IPv4 0x0000000000000000      0t0  TCP 127.0.0.1:52044->127.0.0.1:7890 (ESTABLISHED)
identitys   663  demo   44u  IPv6 0x0000000000000000      0t0  TCP [fe80::1]:1024->[fe80::2]:1024 (ESTABLISHED)
"""

    def test_parse_lsof_extracts_endpoints(self):
        rows = sockets.parse_lsof(self.LSOF, {14708: "cli", 2002: "desktop"})
        self.assertEqual(len(rows), 4)
        first = rows[0]
        self.assertEqual(first["pid"], 14708)
        self.assertEqual(first["surface"], "cli")
        self.assertEqual(first["remote_ip"], "198.18.0.140")
        self.assertEqual(first["remote_port"], 443)

    def test_parse_lsof_handles_ipv6_brackets(self):
        rows = sockets.parse_lsof(self.LSOF, {})
        v6 = [r for r in rows if r["pid"] == 663][0]
        self.assertEqual(v6["remote_ip"], "fe80::2")
        self.assertEqual(v6["remote_port"], 1024)

    def test_unknown_pid_becomes_other(self):
        rows = sockets.parse_lsof(self.LSOF, {})
        self.assertTrue(all(r["surface"] == "other" for r in rows))

    def test_classify_remote(self):
        proxy = ("127.0.0.1", 7890)
        self.assertEqual(sockets.classify_remote("127.0.0.1", 7890, proxy),
                         sockets.KIND_LOCAL_PROXY)
        self.assertEqual(sockets.classify_remote("198.18.0.140", 443, proxy),
                         sockets.KIND_FAKE)
        self.assertEqual(sockets.classify_remote("8.8.8.8", 443, proxy),
                         sockets.KIND_REAL)
        self.assertEqual(sockets.classify_remote("192.168.1.5", 445, proxy),
                         sockets.KIND_PRIVATE)

    def test_classify_remote_recognises_common_proxy_ports(self):
        """进程用环境变量单独配了代理时，那个端口不在系统代理配置里，
        但它仍然是「连了本机代理」而不是「内网连接」。"""
        self.assertEqual(sockets.classify_remote("127.0.0.1", 7897, None),
                         sockets.KIND_LOCAL_PROXY)


class TestProcessMatching(unittest.TestCase):
    PS = """  501 /Users/x/.local/share/claude/versions/2.1.x --resume abc
  502 /Applications/Claude.app/Contents/MacOS/Claude
  503 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  504 /usr/bin/python3 -m cem serve
  505 /bin/zsh -c cd /Users/x/claude-egress-monitor && ls
  506 /usr/sbin/syslogd
"""

    def test_matches_cli_by_versions_path(self):
        got = sockets.match_processes(self.PS)
        self.assertEqual(got[501], "cli")

    def test_matches_desktop_and_browser(self):
        got = sockets.match_processes(self.PS)
        self.assertEqual(got[502], "desktop")
        self.assertEqual(got[503], "web")

    def test_excludes_self_and_repo_paths(self):
        """本工具自己、以及任何命令行里带仓库名的进程都不该被算成 Claude。

        仓库目录名里含 "claude"，早先用 `pgrep -f claude` 会把自己匹配进去。
        """
        got = sockets.match_processes(self.PS)
        self.assertNotIn(504, got)
        self.assertNotIn(505, got)
        self.assertNotIn(506, got)

    def test_explicit_pid_exclusion(self):
        got = sockets.match_processes(self.PS, exclude_pids=(501,))
        self.assertNotIn(501, got)


class TestClashParsing(unittest.TestCase):
    PAYLOAD = """{"connections":[
      {"id":"a","upload":10,"download":20,
       "metadata":{"host":"api.anthropic.com","destinationIP":"192.0.2.40",
                   "destinationPort":"443","network":"tcp",
                   "processPath":"/Users/x/.local/share/claude/versions/2.1.x"},
       "rule":"DomainSuffix","rulePayload":"anthropic.com",
       "chains":["JP-Tokyo","Proxy"]},
      {"id":"b","metadata":{"host":"example.com"},"chains":[]}
    ]}"""

    def test_parse_connections(self):
        conns = clash.parse_connections(self.PAYLOAD)
        self.assertEqual(len(conns), 2)
        self.assertEqual(conns[0].host, "api.anthropic.com")
        self.assertEqual(conns[0].rule_payload, "anthropic.com")
        self.assertEqual(conns[0].download, 20)

    def test_exit_node_is_first_chain_element(self):
        conns = clash.parse_connections(self.PAYLOAD)
        self.assertEqual(conns[0].exit_node, "JP-Tokyo")
        self.assertIsNone(conns[1].exit_node)

    def test_parse_connections_tolerates_missing_fields(self):
        conns = clash.parse_connections('{"connections":[{"id":"x"}]}')
        self.assertEqual(len(conns), 1)
        self.assertIsNone(conns[0].host)
        self.assertEqual(conns[0].upload, 0)

    def test_parse_connections_bad_input(self):
        self.assertEqual(clash.parse_connections("nope"), ())
        self.assertEqual(clash.parse_connections("{}"), ())

    def test_filter_claude_matches_host_or_process(self):
        conns = clash.parse_connections(self.PAYLOAD)
        kept = clash.filter_claude(conns, ("api.anthropic.com",))
        self.assertEqual([c.id for c in kept], ["a"])

    def test_filter_claude_matches_subdomain(self):
        conns = clash.parse_connections(
            '{"connections":[{"id":"c","metadata":{"host":"a.anthropic.com"}}]}'
        )
        self.assertEqual(len(clash.filter_claude(conns, ("anthropic.com",))), 1)

    def test_exit_summary_counts_by_node(self):
        conns = clash.parse_connections(self.PAYLOAD)
        got = clash.exit_summary(conns)
        self.assertEqual(got["JP-Tokyo"], 1)
        self.assertEqual(got["(直连)"], 1)


if __name__ == "__main__":
    unittest.main()
