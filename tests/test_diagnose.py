"""诊断层的单元测试：一致性分级、动态/静态判定、出口类型、路径质量、遥测提取。

这一层产出的是**建议**。一条错误的建议会让人去改一份本来没问题的配置，
所以每条规则的判据都要有用例钉住。
"""

from __future__ import annotations

import unittest

from cem import diagnose as dx
from cem import history, pathtrace, telemetry
from cem.model import AsnInfo, Check, Sample, Timing, TraceView


def trace(target, path, ip, cc, asn=None, org=None, city=None,
          hosting=None, mobile=None, total=500.0, ts_ok=True):
    info = None
    if asn or org or city or hosting is not None or mobile is not None:
        info = AsnInfo(ip=ip, asn=asn, org=org, city=city,
                       hosting=hosting, mobile=mobile, country=cc)
    return TraceView(
        target=target, path=path, ok=ts_ok, egress_ip=ip, country=cc,
        egress_asn=info, timing=Timing(total_ms=total),
    )


def addr(ip, family="IPv4", cc="SG", asn="AS1", org=None):
    return dx.ExitAddress(ip=ip, family=family, country=cc, colo=None,
                          asn=asn, org=org, hosts=("api.anthropic.com",))


class TestConsistencyLevel(unittest.TestCase):
    def test_single_address_is_identical(self):
        self.assertEqual(dx.classify_level((addr("1.1.1.1"),)),
                         dx.LEVEL_IDENTICAL)

    def test_v4_v6_same_asn_is_dual_stack(self):
        """同一个节点的双栈地址不该被报成问题 —— 风控看到的是同一个网络。"""
        got = dx.classify_level((
            addr("203.0.113.1", "IPv4", "SG", "AS4817"),
            addr("2001:db8::1", "IPv6", "SG", "AS4817"),
        ))
        self.assertEqual(got, dx.LEVEL_DUAL_STACK)

    def test_three_addresses_same_asn_is_same_network(self):
        got = dx.classify_level(tuple(
            addr(f"203.0.113.{i}", "IPv4", "SG", "AS4817") for i in (1, 2, 3)
        ))
        self.assertEqual(got, dx.LEVEL_SAME_NETWORK)

    def test_same_country_different_asn_is_multi_network(self):
        """**国家相同不等于出口相同。** 这是分级存在的全部理由。"""
        got = dx.classify_level((
            addr("203.0.113.1", "IPv4", "SG", "AS4817"),
            addr("198.51.100.1", "IPv4", "SG", "AS9999"),
        ))
        self.assertEqual(got, dx.LEVEL_MULTI_NETWORK)

    def test_different_country_wins_over_everything(self):
        got = dx.classify_level((
            addr("203.0.113.1", "IPv4", "SG", "AS4817"),
            addr("198.51.100.1", "IPv4", "JP", "AS4817"),
        ))
        self.assertEqual(got, dx.LEVEL_MULTI_COUNTRY)

    def test_missing_asn_falls_back_to_country(self):
        """查不到 ASN 时只能退回国家判断，结论更弱但不能崩。"""
        got = dx.classify_level((
            addr("203.0.113.1", "IPv4", "SG", None),
            addr("203.0.113.2", "IPv4", "SG", None),
        ))
        self.assertEqual(got, dx.LEVEL_SAME_NETWORK)

    def test_every_level_has_a_label_and_meaning(self):
        for level in dx.LEVEL_ORDER:
            self.assertIn(level, dx.LEVEL_LABEL)
            self.assertIn(level, dx.LEVEL_MEANING)


class TestEgressProfile(unittest.TestCase):
    def test_baseline_is_excluded(self):
        """对照组走默认路由是正常的。把它算进来会产生一条假警报，
        而读者会照着那条去改一份本来没问题的规则。"""
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG"),
            trace("1.1.1.1", "cli", "198.51.100.1", "JP"),
        ))
        prof = dx.egress_profile(s)["cli"]
        self.assertEqual(prof.level, dx.LEVEL_IDENTICAL)
        self.assertEqual(prof.countries, ("SG",))

    def test_primary_is_the_widest_covering_address(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG"),
            trace("claude.ai", "cli", "203.0.113.1", "SG"),
            trace("code.claude.com", "cli", "2001:db8::1", "SG"),
        ))
        prof = dx.egress_profile(s)["cli"]
        self.assertEqual(prof.primary.ip, "203.0.113.1")
        self.assertEqual(len(prof.primary.hosts), 2)

    def test_restricted_country_is_surfaced(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "HK"),
        ))
        self.assertEqual(dx.egress_profile(s)["cli"].restricted, ("HK",))

    def test_kind_comes_through_from_asn_info(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG",
                  hosting=True, org="Example Cloud"),
        ))
        self.assertEqual(dx.egress_profile(s)["cli"].primary.kind, "datacenter")


class TestAddressNature(unittest.TestCase):
    def sample_at(self, ts, ip):
        return Sample(ts=ts, seq=1, traces=(
            trace("api.anthropic.com", "cli", ip, "SG", asn="AS4817"),
        ))

    def test_short_window_without_change_is_undecided(self):
        """观测二十分钟就说"是静态 IP"没有依据 —— 动态 IP 常常几小时才换一次。"""
        samples = (self.sample_at(0, "203.0.113.1"),
                   self.sample_at(600, "203.0.113.1"))
        nat = dx.address_nature(samples, "cli")
        self.assertEqual(nat.nature, dx.NATURE_UNKNOWN)
        self.assertIn("小时", nat.detail)

    def test_any_change_means_dynamic(self):
        samples = (self.sample_at(0, "203.0.113.1"),
                   self.sample_at(600, "203.0.113.2"))
        nat = dx.address_nature(samples, "cli")
        self.assertEqual(nat.nature, dx.NATURE_DYNAMIC)
        self.assertEqual(nat.ip_changes, 1)
        self.assertTrue(nat.same_network)

    def test_long_window_without_change_is_steady(self):
        hours = dx.NATURE_MIN_HOURS + 1
        samples = (self.sample_at(0, "203.0.113.1"),
                   self.sample_at(hours * 3600, "203.0.113.1"))
        nat = dx.address_nature(samples, "cli")
        self.assertEqual(nat.nature, dx.NATURE_STEADY)
        # 措辞必须留有余地：观测期内稳定 ≠ 运营商承诺静态
        self.assertIn("不等于", nat.detail)


class TestFindings(unittest.TestCase):
    def two_country_sample(self):
        return Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "SG", asn="AS1"),
            trace("api.anthropic.com", "desktop", "198.51.100.1", "JP", asn="AS2"),
        ))

    def test_cross_surface_country_is_a_warning(self):
        found = dx.diagnose(self.two_country_sample())
        hit = [f for f in found if f.id == "cross-surface-country"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].severity, dx.SEV_WARN)

    def test_every_finding_carries_evidence_cause_and_fix(self):
        """没有判据的建议不值得照做；没有下一步的诊断只是抱怨。"""
        for f in dx.diagnose(self.two_country_sample()):
            self.assertTrue(f.evidence, f"{f.id} 缺判据")
            self.assertTrue(f.cause, f"{f.id} 缺成因")
            self.assertTrue(f.fix, f"{f.id} 缺下一步")

    def test_restricted_region_is_critical(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "CN"),
        ))
        hit = [f for f in dx.diagnose(s) if f.id.startswith("restricted-")]
        self.assertTrue(hit)
        self.assertEqual(hit[0].severity, dx.SEV_CRITICAL)

    def test_findings_are_sorted_most_severe_first(self):
        s = Sample(ts=0, seq=1, traces=(
            trace("api.anthropic.com", "cli", "203.0.113.1", "CN"),
            trace("api.anthropic.com", "desktop", "198.51.100.1", "JP"),
        ))
        order = [dx.SEV_ORDER[f.severity] for f in dx.diagnose(s)]
        self.assertEqual(order, sorted(order))

    def test_empty_sample_gives_no_findings(self):
        self.assertEqual(dx.diagnose(None), ())

    def test_summary_counts_by_severity(self):
        got = dx.summary(dx.diagnose(self.two_country_sample()))
        self.assertEqual(set(got), {dx.SEV_CRITICAL, dx.SEV_WARN,
                                    dx.SEV_INFO, dx.SEV_OK})


class TestIpKind(unittest.TestCase):
    def test_flags_win_over_heuristics(self):
        info = AsnInfo(ip="x", hosting=True, org="Some Telecom Broadband")
        self.assertEqual(info.kind, "datacenter")

    def test_explicit_non_hosting_is_residential(self):
        info = AsnInfo(ip="x", hosting=False, mobile=False)
        self.assertEqual(info.kind, "residential")

    def test_mobile_wins(self):
        self.assertEqual(AsnInfo(ip="x", hosting=True, mobile=True).kind, "mobile")

    def test_heuristic_from_org_name(self):
        self.assertEqual(AsnInfo(ip="x", org="Contabo GmbH").kind, "datacenter")
        self.assertEqual(AsnInfo(ip="x", org="Acme Broadband").kind, "residential")

    def test_unknown_is_not_guessed(self):
        """判不出来就说判不出来。把机房猜成家宽会让人以为风险更低，
        那正好是最危险的方向。"""
        info = AsnInfo(ip="x")
        self.assertEqual(info.kind, "unknown")
        self.assertIn("不猜", info.kind_evidence)

    def test_where_dedupes_city_and_region(self):
        info = AsnInfo(ip="x", city="Singapore", region="Singapore", country="SG")
        self.assertEqual(info.where, "Singapore · SG")

    def test_short_org_strips_suffixes_and_trailing_comma(self):
        self.assertEqual(
            AsnInfo(ip="x", org="ANTHROPIC - Anthropic, PBC, US").short_org,
            "Anthropic")


class TestPathTrace(unittest.TestCase):
    MTR = """{"report":{"mtr":{"src":"a","dst":"claude.ai"},"hubs":[
      {"count":1,"host":"192.0.2.1","Loss%":0.0,"Snt":5,"Best":1.0,"Avg":1.2,"Wrst":2.0,"StDev":0.3},
      {"count":2,"host":"???","Loss%":40.0,"Snt":5,"Best":10.0,"Avg":12.0,"Wrst":14.0,"StDev":1.1},
      {"count":3,"host":"203.0.113.9","Loss%":0.0,"Snt":5,"Best":80.0,"Avg":85.0,"Wrst":95.0,"StDev":4.2}
    ]}}"""

    def test_parse_hops(self):
        hops = pathtrace.parse_mtr_json(self.MTR)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0].host, "192.0.2.1")
        self.assertEqual(hops[2].avg_ms, 85.0)

    def test_unresolved_hop_becomes_none(self):
        hops = pathtrace.parse_mtr_json(self.MTR)
        self.assertIsNone(hops[1].host)

    def test_end_to_end_loss_is_the_last_hop(self):
        """中间跳的丢包大多是 ICMP 限速造成的假象，真正算数的是终点。"""
        report = pathtrace.PathReport(
            target="x", ok=True, hops=pathtrace.parse_mtr_json(self.MTR))
        self.assertEqual(report.end_to_end_loss, 0.0)
        self.assertTrue(report.hops[1].loss_is_meaningful)

    def test_bad_json_is_empty_not_an_exception(self):
        self.assertEqual(pathtrace.parse_mtr_json("nope"), ())
        self.assertEqual(pathtrace.parse_mtr_json('{"report":{}}'), ())

    def test_missing_binary_degrades_gracefully(self):
        """没装 mtr 是降级，不是报错 —— 一个可选增强不该让主流程失败。"""
        report = pathtrace.PathReport(target="x", ok=False, error="未安装 mtr")
        self.assertFalse(report.ok)
        self.assertIsNone(report.end_to_end_loss)


class TestTelemetryExtraction(unittest.TestCase):
    # 一段仿造的 bundle 片段，形状照着真实的来，但内容是编的。
    BUNDLE = (
        'noise\n'
        'let p={ddsource:"nodejs",ddtags:t,message:e,service:"claude-code",'
        'hostname:"claude-code",env:"external"};l.model=m;l.head_sha=h;'
        'l.http_status=s;var X="https://http-intake.logs.us5.datadoghq.com/api/v2/logs",'
        'TOK="pubdeadbeefcafe",FL=15000,B=100,C=5000,'
        'S=new Set(["tengu_api_success","tengu_api_error","chrome_bridge_x"]);'
        'function stripPiiFieldsForDatadog(){}function trackDatadogEvent(){}\n'
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC DISABLE_TELEMETRY\n'
    )

    def report(self):
        return telemetry.parse_bundle(self.BUNDLE)

    def test_finds_intake_and_token_prefix(self):
        r = self.report()
        self.assertTrue(r.ok)
        self.assertIn("us5.datadoghq.com", r.intake_url)
        # 完整 token 不抄进输出 —— 想看的人自己跑 strings 就有
        self.assertTrue(r.client_token_prefix.startswith("pubdea"))
        self.assertNotIn("cafe", r.client_token_prefix)

    def test_envelope_constants(self):
        env = dict(self.report().envelope)
        self.assertEqual(env["service"], "claude-code")
        # hostname 是写死的字符串，不会上报使用者的真实主机名
        self.assertEqual(env["hostname"], "claude-code")

    def test_payload_fields_are_fields_not_function_names(self):
        fields = self.report().payload_fields
        self.assertIn("head_sha", fields)
        self.assertIn("model", fields)
        self.assertNotIn("trackDatadogEvent", fields)

    def test_event_names_extracted(self):
        self.assertIn("tengu_api_success", self.report().event_names)

    def test_behaviour_markers_are_reported(self):
        names = [n for n, _ in self.report().behaviours]
        self.assertIn("stripPiiFieldsForDatadog", names)

    def test_env_vars_extracted(self):
        self.assertIn("DISABLE_TELEMETRY", self.report().env_vars)

    def test_missing_intake_reports_error_not_crash(self):
        r = telemetry.parse_bundle("nothing interesting here")
        self.assertFalse(r.ok)
        self.assertIn("没找到", r.error)

    def test_longest_line_is_used(self):
        """`strings` 会把同一个串切成多段，只有最长那段带着周围的构造代码。
        取第一条匹配会拿到一个碎片，什么都提取不出来。"""
        blob = "http-intake.logs frag\n" + self.BUNDLE
        self.assertTrue(telemetry.parse_bundle(blob).ok)


class TestHistorySummary(unittest.TestCase):
    def records(self):
        base = 1786700000.0
        out = []
        for i in range(6):
            ip = "203.0.113.1" if i < 3 else "198.51.100.2"
            cc = "SG" if i < 3 else "JP"
            asn = "AS4817" if i < 3 else "AS55900"
            out.append({
                "v": 1, "ts": base + i * 600,
                "paths": {"cli": {"ip": ip, "cc": cc, "asn": asn,
                                  "org": "X", "fam": "IPv4",
                                  "level": "identical", "ips": [ip],
                                  "ccs": [cc], "domains": 6}},
                "lat": {"api.anthropic.com|cli": 100.0 + i * 10},
                "ok": 6, "fail": 0, "sev": {"info": 2}, "top": [],
            })
        return tuple(out)

    def test_counts_and_shares(self):
        got = history.summarize("2026-08-15", self.records(), size_bytes=1234)
        self.assertEqual(got["rounds"], 6)
        self.assertEqual(got["size_bytes"], 1234)
        shares = {c["key"]: c["share"] for c in got["countries"]}
        self.assertEqual(shares["SG"], 50.0)
        self.assertEqual(shares["JP"], 50.0)

    def test_change_detection(self):
        got = history.summarize("2026-08-15", self.records())
        self.assertEqual(got["changes"], 1)
        self.assertEqual(got["country_changes"], 1)

    def test_latency_percentiles(self):
        got = history.summarize("2026-08-15", self.records())
        self.assertEqual(got["latency"]["n"], 6)
        self.assertEqual(got["latency"]["min"], 100.0)
        self.assertEqual(got["latency"]["max"], 150.0)

    def test_hourly_has_24_slots(self):
        got = history.summarize("2026-08-15", self.records())
        self.assertEqual(len(got["hourly"]), 24)

    def test_empty_day_is_shaped_the_same(self):
        """空的一天也要有完整形状，否则界面得到处判空。"""
        got = history.summarize("2026-08-15", ())
        self.assertEqual(got["rounds"], 0)
        self.assertEqual(got["countries"], [])
        self.assertIn("hourly", got)

    def test_combine_across_days(self):
        one = history.summarize("2026-08-14", self.records())
        two = history.summarize("2026-08-15", self.records())
        merged = history.combine((one, two))
        self.assertEqual(merged["days"], 2)
        self.assertEqual(merged["rounds"], 12)
        self.assertTrue(merged["latency"]["approx"])

    def test_valid_day_blocks_path_traversal(self):
        """日期串会被拼进文件名。不校验就等于把删除接口变成任意路径删除。"""
        self.assertTrue(history.valid_day("2026-08-15"))
        for bad in ("../etc/passwd", "2026-8-15", "2026-08-15.jsonl",
                    "", None, 20260815):
            self.assertFalse(history.valid_day(bad), bad)


class TestChecksShape(unittest.TestCase):
    def test_check_defaults(self):
        c = Check(id="x", label="y", ok=True)
        self.assertEqual(c.severity, "info")
        self.assertIsNone(c.value)


if __name__ == "__main__":
    unittest.main()
