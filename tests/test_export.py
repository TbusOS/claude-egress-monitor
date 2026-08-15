"""域名发现与导出的测试。全部离线。

这一层的产物是**要发给别人的文件**，所以最重要的用例不是"内容对不对"，
而是"**不该出现的东西有没有出现**" —— 见 TestExportLeaks。
那一组是给未来的改动设的闸：谁往 DomainRow 里加了个带本机信息的字段，
它会当场红。
"""

from __future__ import annotations

import re
import unittest

from cem import discover, export
from cem import endpoints as ep
from cem.model import AsnInfo, Connection, Sample


def conn(host=None, kind="real", ip="192.0.2.10", port=443, surface="cli"):
    return Connection(pid=1, command="0.0.0-demo", surface=surface,
                      local="192.0.2.9:5000", remote_ip=ip, remote_port=port,
                      kind=kind, host=host)


def sample(ts, conns):
    return Sample(ts=ts, seq=1, connections=tuple(conns))


class TestNormalise(unittest.TestCase):
    def test_strips_and_lowercases(self):
        self.assertEqual(discover.normalise("  API.Anthropic.COM. "),
                         "api.anthropic.com")

    def test_rejects_non_domains(self):
        """一个几百 MB 的 bundle 里全是文件名和版本号，不挡住就全是噪声。"""
        for bad in ("", "localhost", "1.2.3.4", "index.js", "styles.css",
                    "a.local", "foo bar.com", "notadomain", "2.1.232"):
            self.assertIsNone(discover.normalise(bad), bad)


class TestClassify(unittest.TestCase):
    def test_known_comes_from_the_inventory(self):
        self.assertEqual(discover.classify("api.anthropic.com"),
                         discover.KIND_KNOWN)

    def test_related_is_a_new_domain_under_a_known_parent(self):
        """这一档就是这个功能存在的理由：Claude 更新加了新域名。"""
        self.assertEqual(discover.classify("preview.claude.ai"),
                         discover.KIND_RELATED)
        self.assertEqual(discover.classify("gcal.mcp.claude.com"),
                         discover.KIND_RELATED)

    def test_unknown_parent_is_its_own_bucket(self):
        """可能是用户自己的 MCP 服务器 —— 默认不能进外发文件。"""
        self.assertEqual(discover.classify("mcp.mycompany.internal.example"),
                         discover.KIND_UNKNOWN)
        self.assertEqual(discover.classify("evil.example.org"),
                         discover.KIND_UNKNOWN)

    def test_parent_matching_is_suffix_not_substring(self):
        """`notanthropic.com` 不该被当成 anthropic.com 的子域。"""
        self.assertIsNone(discover.parent_of("notanthropic.com"))
        self.assertIsNone(discover.parent_of("anthropic.com.evil.example"))


class TestExtractDomains(unittest.TestCase):
    BLOB = ("const A='https://api.anthropic.com/v1';"
            "const B='https://preview.claude.ai/x';"
            "import 'lodash.debounce';require('./styles.css');"
            "// see https://github.com/some/repo and https://npmjs.com/foo\n"
            "track('https://o1158394.ingest.us.sentry.io/1')")

    def test_keeps_only_claude_related_parents(self):
        got = discover.extract_domains(self.BLOB)
        self.assertIn("api.anthropic.com", got)
        self.assertIn("preview.claude.ai", got)
        self.assertIn("o1158394.ingest.us.sentry.io", got)

    def test_drops_unrelated_domains(self):
        """依赖包主页、许可证链接不该进来 —— 那是几千条噪声。"""
        got = discover.extract_domains(self.BLOB)
        self.assertNotIn("github.com", got)
        self.assertNotIn("npmjs.com", got)
        self.assertNotIn("lodash.debounce", got)

    def test_result_is_sorted_and_deduped(self):
        got = discover.extract_domains(self.BLOB * 3)
        self.assertEqual(list(got), sorted(set(got)))


class TestObservedHosts(unittest.TestCase):
    def test_counts_rounds_not_connections(self):
        """一轮里同一个域名开了七条连接，算一轮，不算七次。"""
        s = sample(0, [conn("api.anthropic.com") for _ in range(7)])
        counts, _ = export.observed_hosts([s, s])
        self.assertEqual(counts["api.anthropic.com"], 2)

    def test_splits_multi_host_reverse_entries(self):
        counts, _ = export.observed_hosts(
            [sample(0, [conn("claude.ai、api.anthropic.com")])])
        self.assertEqual(set(counts), {"claude.ai", "api.anthropic.com"})

    def test_local_proxy_is_a_blind_spot_not_an_anomaly(self):
        """走本机代理时目的地本来就看不见，不该算成"归不到"。"""
        _, unattributed = export.observed_hosts(
            [sample(0, [conn(None, kind="local-proxy", ip="127.0.0.1", port=7890)])])
        self.assertEqual(unattributed, 0)

    def test_real_connection_without_a_host_counts_as_unattributed(self):
        _, unattributed = export.observed_hosts([sample(0, [conn(None)])])
        self.assertEqual(unattributed, 1)


class TestBuild(unittest.TestCase):
    def test_baseline_never_enters_the_export(self):
        """1.1.1.1 是对照组，不属于 Claude。写进"Claude 会访问的域名"是错的。"""
        doc = export.build()
        self.assertNotIn("1.1.1.1", [r.host for r in doc.rows])

    def test_discovered_domains_are_merged_not_duplicated(self):
        """同一个域名既在清单里又被扫到，只能出现一行，证据并起来。"""
        doc = export.build(discovered={
            "api.anthropic.com": {"kind": discover.KIND_KNOWN,
                                  "sources": ["scan-cli"], "first": 1.0, "last": 2.0},
        })
        hits = [r for r in doc.rows if r.host == "api.anthropic.com"]
        self.assertEqual(len(hits), 1)
        self.assertIn("scan-cli", hits[0].evidence)
        self.assertIn("cli-strings", hits[0].evidence)   # 清单原有的还在
        self.assertTrue(hits[0].in_inventory)

    def test_new_domain_gets_its_own_row(self):
        doc = export.build(discovered={
            "preview.claude.ai": {"kind": discover.KIND_RELATED,
                                  "sources": ["scan-cli"], "first": 1.0, "last": 2.0},
        })
        row = [r for r in doc.rows if r.host == "preview.claude.ai"][0]
        self.assertFalse(row.in_inventory)
        self.assertEqual(row.category, export.CAT_DISCOVERED)
        self.assertIsNone(row.purpose)          # 没有人工写的用途，不编

    def test_unknown_parent_is_withheld_by_default(self):
        doc = export.build(discovered={
            "mcp.internal.example": {"kind": discover.KIND_UNKNOWN,
                                     "sources": ["observed"]},
        })
        self.assertNotIn("mcp.internal.example", [r.host for r in doc.rows])
        self.assertIn("mcp.internal.example", doc.withheld)

    def test_unknown_parent_can_be_opted_in(self):
        doc = export.build(discovered={
            "mcp.internal.example": {"kind": discover.KIND_UNKNOWN,
                                     "sources": ["observed"]},
        }, include_unknown=True)
        self.assertIn("mcp.internal.example", [r.host for r in doc.rows])

    def test_observed_beats_code_only(self):
        doc = export.build([sample(0, [conn("claude.ai")])])
        row = [r for r in doc.rows if r.host == "claude.ai"][0]
        self.assertTrue(row.observed)
        self.assertEqual(row.confidence, "确证")
        other = [r for r in doc.rows if r.host == "mcp.claude.com"][0]
        self.assertFalse(other.observed)
        self.assertEqual(other.confidence, "代码里写着")

    def test_window_needs_two_samples(self):
        self.assertIsNone(export.build([sample(0, [])]).window_hours)
        doc = export.build([sample(0, []), sample(7200, [])])
        self.assertEqual(doc.window_hours, 2.0)


class TestExportLeaks(unittest.TestCase):
    """**这一组是外发文件的闸。**

    导出的产物是要发给别人的。这里用一份"什么都塞进去了"的采样跑三种格式，
    断言那些本机信息一个都没出现在输出里。

    谁将来往 DomainRow 或者渲染函数里加了带本机信息的字段，这几条会当场红。
    """

    SECRETS = {
        "出口 IP": "203.0.113.24",
        "内网地址": "192.0.2.9",
        "代理端口": "7890",
        "进程名": "0.0.0-demo",
        "ASN 组织": "Example Telecom",
        "城市": "Singapore",
    }

    def loaded_doc(self):
        asn = AsnInfo(ip="203.0.113.24", asn="AS64500", org="Example Telecom",
                      city="Singapore", country="SG")
        conns = (
            Connection(pid=4242, command="0.0.0-demo", surface="cli",
                       local="192.0.2.9:51234", remote_ip="203.0.113.24",
                       remote_port=443, kind="real", host="api.anthropic.com",
                       asn=asn),
            Connection(pid=4242, command="0.0.0-demo", surface="desktop",
                       local="127.0.0.1:52044", remote_ip="127.0.0.1",
                       remote_port=7890, kind="local-proxy"),
        )
        return export.build(
            [Sample(ts=0, seq=1, connections=conns)],
            discovered={"preview.claude.ai": {"kind": discover.KIND_RELATED,
                                              "sources": ["scan-cli"]}},
        )

    def test_no_local_details_in_any_format(self):
        doc = self.loaded_doc()
        for fmt in export.FORMATS:
            text = export.render(doc, fmt)
            for label, needle in self.SECRETS.items():
                self.assertNotIn(needle, text, f"{fmt} 里漏出了{label}")

    def test_no_ip_addresses_at_all(self):
        """更狠一条：输出里根本不该有任何 IPv4 字面量。"""
        doc = self.loaded_doc()
        ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for fmt in export.FORMATS:
            found = ipv4.findall(export.render(doc, fmt))
            self.assertEqual(found, [], f"{fmt} 里出现了 IP：{found}")

    def test_privacy_note_is_actually_printed(self):
        """承诺要写在文件里，读者才知道自己在分享什么。"""
        doc = self.loaded_doc()
        self.assertIn("不含任何本机信息", export.to_markdown(doc))
        self.assertIn("不含任何本机信息", export.to_json(doc))
        self.assertIn("不含任何本机信息", export.to_text(doc))

    def test_reading_caveat_is_printed(self):
        """「代码里写着 ≠ 每次都会连」必须出现，否则这份表会被读成断言。"""
        self.assertIn("不等于", export.to_markdown(self.loaded_doc()))
        self.assertIn("不等于", export.to_text(self.loaded_doc()))


class TestFormats(unittest.TestCase):
    def test_text_is_one_domain_per_line(self):
        doc = export.build()
        lines = [ln for ln in export.to_text(doc).splitlines()
                 if ln and not ln.startswith("#")]
        for ln in lines:
            host = ln.split("#")[0].strip()
            self.assertIsNotNone(discover.normalise(host), ln)

    def test_json_is_valid_and_deduped(self):
        import json
        doc = export.build(discovered={
            "api.anthropic.com": {"kind": discover.KIND_KNOWN,
                                  "sources": ["scan-cli"]},
        })
        data = json.loads(export.to_json(doc))
        hosts = [d["host"] for d in data["domains"]]
        self.assertEqual(len(hosts), len(set(hosts)), "导出里有重复域名")
        self.assertEqual(data["counts"]["total"], len(hosts))

    def test_unknown_format_is_rejected(self):
        with self.assertRaises(ValueError):
            export.render(export.build(), "../../etc/passwd")


if __name__ == "__main__":
    unittest.main()
