"""分析层的单元测试：结论怎么算出来的、连接怎么归属、噪声怎么过滤。

这些函数决定界面上「本轮结论」那张暗卡写什么。算错了不会报错，
只会给出一个自信的错误判断 —— 所以每条结论都要有用例。
"""

from __future__ import annotations

import unittest

from cem import demo, endpoints, probe, sampler, sockets, store, view
from cem.model import AsnInfo, Connection, Sample, Timing, TraceView


def trace(target, path, ip=None, cc=None, ok=True, total=100.0):
    return TraceView(
        target=target, path=path, ok=ok, egress_ip=ip, country=cc,
        timing=Timing(total_ms=total),
    )


class TestDisagreements(unittest.TestCase):
    def test_flags_country_mismatch_between_paths(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG"),
            trace("api.anthropic.com", "desktop", "198.51.100.1", "JP"),
        ))
        notes = probe.disagreements(s)
        self.assertTrue(any("cli → SG" in n and "desktop → JP" in n for n in notes))

    def test_groups_domains_sharing_the_same_mismatch(self):
        """同一个出口组合下的多个域名必须合成**一条**结论。

        逐域名各写一条时，同一个结论会以几乎相同的句子重复六七遍，
        读者会开始跳过整块内容 —— 而这块正是唯一需要动手的地方。
        """
        traces = []
        # 必须用**真实的** Claude 域名：结论计算只认清单里的域名，
        # 对照组和清单外的域名会被过滤掉 —— 这正是修掉假警报的那条规则。
        for host in ("api.anthropic.com", "claude.ai", "code.claude.com"):
            traces.append(trace(host, "cli", "203.0.113.1", "SG"))
            traces.append(trace(host, "desktop", "198.51.100.1", "JP"))
        notes = probe.disagreements(Sample(ts=0, seq=1, traces=tuple(traces)))
        mismatch = [n for n in notes if "不同入口之间不一致" in n]
        self.assertEqual(len(mismatch), 1)
        self.assertIn("3 个域名", mismatch[0])

    def test_quiet_when_paths_agree(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG"),
            trace("api.anthropic.com", "desktop", "203.0.113.1", "SG"),
        ))
        self.assertEqual(probe.disagreements(s), ())

    def test_flags_split_within_one_path(self):
        """同一条路径下不同 Claude 域名落在不同国家 —— 说明有域名没被规则覆盖。"""
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG"),
            trace("claude.ai", "cli", "198.51.100.1", "JP"),
        ))
        notes = probe.disagreements(s)
        self.assertTrue(any("没被规则覆盖" in n for n in notes))

    def test_ignores_failed_probes(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG"),
            trace("api.anthropic.com", "desktop", None, None, ok=False),
        ))
        self.assertEqual(probe.disagreements(s), ())


class TestEgressBySurface(unittest.TestCase):
    def test_uses_only_business_domains(self):
        """遥测域名的探测结果不该被当成业务出口 —— 它们没有出口 IP，
        而且就算有，也不代表模型 API 走哪儿。"""
        s = Sample(ts=0, seq=1, traces=(
            trace("o1158394.ingest.us.sentry.io", "cli", "203.0.113.9", "US"),
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG"),
        ))
        got = probe.egress_by_surface(s)
        self.assertEqual(got["cli"]["egress_ip"], "203.0.113.1")
        self.assertEqual(got["cli"]["country"], "SG")

    def test_records_every_agreeing_target(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG"),
            trace("claude.ai", "cli", "203.0.113.1", "SG"),
        ))
        got = probe.egress_by_surface(s)
        self.assertEqual(len(got["cli"]["targets"]), 2)

    def test_empty_when_nothing_succeeded(self):
        self.assertEqual(probe.egress_by_surface(Sample(ts=0, seq=1)), {})


class TestConnectionBuilding(unittest.TestCase):
    def rows(self):
        return (
            {"pid": 1, "command": "2.1.x", "surface": "cli",
             "local": "198.18.0.1:1", "remote_ip": "198.18.0.140",
             "remote_port": 443},
            {"pid": 1, "command": "2.1.x", "surface": "cli",
             "local": "192.0.2.9:2", "remote_ip": "8.8.8.8",
             "remote_port": 443},
        )

    def test_fake_ip_is_mapped_back_to_a_domain(self):
        """fake-ip 有个副作用刚好有用：每个域名一个独立占位地址，所以能反查。"""
        conns = sockets.build_connections(
            self.rows(),
            fake_map={"198.18.0.140": "http-intake.logs.us5.datadoghq.com"},
            endpoint_lookup=endpoints.classify_host,
        )
        fake = [c for c in conns if c.kind == sockets.KIND_FAKE][0]
        self.assertEqual(fake.host, "http-intake.logs.us5.datadoghq.com")
        self.assertEqual(fake.service, endpoints.CAT_TELEMETRY)

    def test_asn_lookup_only_for_real_addresses(self):
        """占位地址不该去查归属 —— 查了也毫无意义，而且白花一次请求。"""
        asked: list[str] = []

        def lookup(ip):
            asked.append(ip)
            return AsnInfo(ip=ip, asn="AS399358")

        sockets.build_connections(self.rows(), fake_map={}, asn_lookup=lookup)
        self.assertEqual(asked, ["8.8.8.8"])

    def test_unknown_host_is_not_guessed(self):
        conns = sockets.build_connections(self.rows(), fake_map={})
        self.assertTrue(all(c.host is None for c in conns))


class TestNoiseFilter(unittest.TestCase):
    def conn(self, surface, ip, port=443, kind="real", host=None):
        return Connection(
            pid=1, command="x", surface=surface, local="127.0.0.1:1",
            remote_ip=ip, remote_port=port, kind=kind, host=host,
        )

    def test_browser_sockets_without_attribution_are_dropped(self):
        """浏览器同时连着几十个别的站点。列出来既是噪声，
        也等于把使用者在访问哪些网站写进采样文件。"""
        conns = (
            self.conn("web", "8.8.4.4"),
            self.conn("web", "198.18.0.57", kind="fake-ip", host="claude.ai"),
        )
        kept, dropped, _ = sockets.filter_noise(conns)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].host, "claude.ai")
        self.assertEqual(dropped, 1)

    def test_cli_and_desktop_sockets_are_all_kept(self):
        conns = (self.conn("cli", "8.8.4.4"),
                 self.conn("desktop", "8.8.4.5"))
        kept, dropped, _ = sockets.filter_noise(conns)
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, 0)

    def test_proxy_connections_are_counted(self):
        conns = (self.conn("desktop", "127.0.0.1", 7890, kind="local-proxy"),
                 self.conn("web", "127.0.0.1", 7890, kind="local-proxy"))
        kept, _, via_proxy = sockets.filter_noise(conns)
        self.assertEqual(via_proxy, 2)
        # 浏览器那条不列出（无归属），桌面端那条保留
        self.assertEqual(len(kept), 1)


class TestIntervalClamp(unittest.TestCase):
    def test_clamps_into_range(self):
        self.assertEqual(sampler.clamp_interval(1), sampler.MIN_INTERVAL_S)
        self.assertEqual(sampler.clamp_interval(99999), sampler.MAX_INTERVAL_S)
        self.assertEqual(sampler.clamp_interval(30), 30)

    def test_bad_input_falls_back_to_default(self):
        self.assertEqual(sampler.clamp_interval("abc"), sampler.DEFAULT_INTERVAL_S)
        self.assertEqual(sampler.clamp_interval(None), sampler.DEFAULT_INTERVAL_S)


class TestEndpointInventory(unittest.TestCase):
    def test_every_endpoint_has_evidence(self):
        """清单里不许有『网上抄来的域名』—— 每条都要能说出从哪查到的。"""
        for e in endpoints.ALL:
            self.assertTrue(e.evidence, f"{e.host} 没有取证来源")
            self.assertTrue(e.purpose, f"{e.host} 没写用途")

    def test_hosts_are_unique(self):
        hosts = [e.host for e in endpoints.ALL]
        self.assertEqual(len(hosts), len(set(hosts)))

    def test_trace_capable_excludes_tcp_only(self):
        capable = {e.host for e in endpoints.trace_capable()}
        self.assertIn("api.anthropic.com", capable)
        self.assertNotIn("http-intake.logs.us5.datadoghq.com", capable)

    def test_classify_host_does_not_guess(self):
        self.assertIsNone(endpoints.classify_host("evil.example.com"))
        self.assertIsNotNone(endpoints.classify_host("api.anthropic.com"))


class TestDemoData(unittest.TestCase):
    RESERVED_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:",
                         "198.18.", "127.0.0.1")

    def test_all_addresses_are_documentation_ranges(self):
        """演示数据要能公开（进 README 截图），所以地址必须全部落在
        IANA 永久保留给文档的段里 —— 那些地址不可能指向任何真实主机。"""
        s = demo.sample()
        addrs = [t.egress_ip for t in s.traces if t.egress_ip]
        addrs += [t.peer_ip for t in s.traces if t.peer_ip]
        addrs += [c.remote_ip for c in s.connections]
        addrs += [ip for r in s.resolves for ip in r.system + r.doh]
        self.assertTrue(addrs)
        for ip in addrs:
            self.assertTrue(
                ip.startswith(self.RESERVED_PREFIXES),
                f"{ip} 不在文档保留段里，不能进演示数据",
            )

    def test_demo_notice_is_first_note(self):
        self.assertEqual(demo.sample().notes[0], demo.DEMO_NOTICE)

    def test_demo_paths_do_not_expose_a_real_proxy_port(self):
        proxies = [p.proxy for p in demo.paths() if p.proxy]
        self.assertEqual(proxies, [("127.0.0.1", 7890)])

    def test_seed_fills_history_and_overrides_routes(self):
        hist = store.History()
        smp = sampler.Sampler(hist)
        count = demo.seed(hist, smp)
        self.assertEqual(hist.size(), count)
        self.assertEqual([p.id for p in smp.routes], ["cli", "desktop"])

    def test_demo_sample_produces_the_findings_it_advertises(self):
        """演示数据的意义在于展示真实工具会算出什么，
        所以它必须真的能触发结论 —— 不是把结论写死在文案里。"""
        s = demo.sample()
        notes = probe.disagreements(s)
        self.assertTrue(any("不同入口之间不一致" in n for n in notes))
        self.assertTrue(any("没被规则覆盖" in n for n in notes))


class TestViewShaping(unittest.TestCase):
    def test_country_label_falls_back_to_code(self):
        self.assertEqual(view.country_label("SG"), "新加坡")
        self.assertEqual(view.country_label("ZZ"), "ZZ")
        self.assertIsNone(view.country_label(None))

    def test_restricted_region_is_flagged(self):
        from cem import paths as pathmod
        routes = (pathmod.Path(id="cli", label="Claude Code",
                               surfaces=(pathmod.SURFACE_CLI,), proxy=None,
                               source="", detail=""),)
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "HK"),
        ))
        cards = view.surface_cards(s, routes)
        cli = [c for c in cards if c["surface"] == "cli"][0]
        self.assertTrue(cli["restricted"])

    def test_surface_cards_exist_even_without_data(self):
        """没数据时也要给出三张卡（值为 None），界面才能显示破折号
        而不是整块消失。"""
        cards = view.surface_cards(None, ())
        self.assertEqual(len(cards), 3)
        self.assertTrue(all(c["egress_ip"] is None for c in cards))

    def test_connection_rows_merge_by_destination(self):
        conns = tuple(
            Connection(pid=1, command="2.1.x", surface="cli",
                       local=f"192.0.2.9:{i}", remote_ip="192.0.2.40",
                       remote_port=443, kind="real", host="api.anthropic.com")
            for i in range(5)
        )
        rows = view.connection_rows(Sample(ts=0, seq=1, connections=conns))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sockets"], 5)

    def test_connection_rows_keep_distinct_destinations_apart(self):
        conns = (
            Connection(pid=1, command="x", surface="cli", local="a",
                       remote_ip="8.8.8.8", remote_port=443, kind="real"),
            Connection(pid=1, command="x", surface="cli", local="b",
                       remote_ip="8.8.4.4", remote_port=443, kind="real"),
        )
        rows = view.connection_rows(Sample(ts=0, seq=1, connections=conns))
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
