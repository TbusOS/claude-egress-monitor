"""历史存储与统计的单元测试。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cem import store
from cem.model import Sample, Timing, TraceView


def sample(seq, ts, total, ip="203.0.113.1", cc="SG"):
    return Sample(ts=ts, seq=seq, traces=(
        TraceView(target="api.anthropic.com", path="cli", ok=True,
                  egress_ip=ip, country=cc, timing=Timing(total_ms=total)),
    ))


class TestPercentile(unittest.TestCase):
    def test_single_value(self):
        self.assertEqual(store.percentile([42.0], 0.5), 42.0)
        self.assertEqual(store.percentile([42.0], 0.95), 42.0)

    def test_median_of_even_count_interpolates(self):
        self.assertEqual(store.percentile([10, 20, 30, 40], 0.5), 25.0)

    def test_p95_near_the_top(self):
        data = list(range(1, 101))
        self.assertAlmostEqual(store.percentile(data, 0.95), 95.05, places=2)

    def test_ignores_none_and_empty(self):
        self.assertEqual(store.percentile([None, 10.0, None], 0.5), 10.0)
        self.assertIsNone(store.percentile([], 0.5))
        self.assertIsNone(store.percentile([None], 0.5))

    def test_clamps_out_of_range_pct(self):
        self.assertEqual(store.percentile([1, 2, 3], -1), 1)
        self.assertEqual(store.percentile([1, 2, 3], 9), 3)


class TestHistory(unittest.TestCase):
    def test_ring_drops_oldest(self):
        hist = store.History(capacity=3)
        for i in range(5):
            hist.add(sample(i, float(i), 100.0))
        self.assertEqual(hist.size(), 3)
        self.assertEqual(hist.latest().seq, 4)
        self.assertEqual([s.seq for s in hist.recent(10)], [2, 3, 4])

    def test_latest_is_none_when_empty(self):
        self.assertIsNone(store.History().latest())
        self.assertEqual(store.History().recent(5), ())

    def test_not_persisting_by_default(self):
        """默认不落盘：这个文件的内容就是使用者的网络画像。"""
        self.assertFalse(store.History().persisting)

    def test_jsonl_append_is_one_object_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "samples.jsonl"
            hist = store.History(jsonl_path=path)
            self.assertTrue(hist.persisting)
            hist.add(sample(1, 1.0, 120.0))
            hist.add(sample(2, 2.0, 130.0))
            lines = path.read_text("utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            first = json.loads(lines[0])
            self.assertEqual(first["seq"], 1)
            self.assertEqual(first["traces"][0]["egress_ip"], "203.0.113.1")

    def test_jsonl_failure_does_not_stop_monitoring(self):
        """落盘失败不该让监控停下来 —— 监控本身比它的日志重要。"""
        hist = store.History(jsonl_path=Path("/proc/definitely/not/writable.jsonl"))
        hist.add(sample(1, 1.0, 100.0))       # 不应抛异常
        self.assertEqual(hist.size(), 1)


class TestLatencyStats(unittest.TestCase):
    def hist(self):
        hist = store.History()
        for i, total in enumerate([100.0, 200.0, 300.0, 400.0]):
            hist.add(sample(i, float(i), total))
        return hist

    def test_series_and_stats(self):
        samples = self.hist().recent(10)
        series = store.latency_series(samples, "api.anthropic.com", "cli")
        self.assertEqual([v for _ts, v in series], [100.0, 200.0, 300.0, 400.0])

        stats = store.latency_stats(samples, "api.anthropic.com", "cli")
        self.assertEqual(stats["n"], 4)
        self.assertEqual(stats["p50"], 250.0)
        self.assertEqual(stats["min"], 100.0)
        self.assertEqual(stats["max"], 400.0)

    def test_unknown_target_gives_zero_samples(self):
        stats = store.latency_stats(self.hist().recent(10), "nope", "cli")
        self.assertEqual(stats["n"], 0)
        self.assertIsNone(stats["p50"])


class TestEgressChanges(unittest.TestCase):
    def test_first_reading_is_marked(self):
        samples = (sample(1, 1.0, 100.0),)
        events = store.egress_changes(samples, "cli")
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]["first"])

    def test_only_logs_on_change(self):
        """每轮都记等于把一屏日志变成噪声，而读者关心的只有『什么时候变的』。"""
        samples = (
            sample(1, 1.0, 100.0, ip="203.0.113.1", cc="SG"),
            sample(2, 2.0, 100.0, ip="203.0.113.1", cc="SG"),
            sample(3, 3.0, 100.0, ip="198.51.100.1", cc="JP"),
            sample(4, 4.0, 100.0, ip="198.51.100.1", cc="JP"),
        )
        events = store.egress_changes(samples, "cli")
        self.assertEqual(len(events), 2)
        self.assertFalse(events[1]["first"])
        self.assertEqual(events[1]["country"], "JP")

    def test_same_country_different_ip_still_counts(self):
        """同一个国家里换了出口 IP 也是变更 —— 换节点会影响风控画像。"""
        samples = (
            sample(1, 1.0, 100.0, ip="203.0.113.1", cc="SG"),
            sample(2, 2.0, 100.0, ip="203.0.113.9", cc="SG"),
        )
        self.assertEqual(len(store.egress_changes(samples, "cli")), 2)

    def test_failed_rounds_are_skipped_not_treated_as_change(self):
        blank = Sample(ts=5.0, seq=5)
        samples = (sample(1, 1.0, 100.0), blank, sample(2, 2.0, 100.0))
        self.assertEqual(len(store.egress_changes(samples, "cli")), 1)


if __name__ == "__main__":
    unittest.main()
