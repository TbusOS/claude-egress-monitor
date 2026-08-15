"""文档生成器的测试。全部离线、纯函数。

这个生成器出错的方式很隐蔽：页面照样生成、照样能打开，只是某一段
内容悄悄错了（代码块里的 `*` 被吃成斜体、内部链接没改后缀、
表格少了一列）。所以这里逐条钉住。
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "build_docs", ROOT / "scripts" / "build_docs.py")
build_docs = importlib.util.module_from_spec(_spec)
sys.modules["build_docs"] = build_docs
_spec.loader.exec_module(build_docs)


class TestInline(unittest.TestCase):
    def test_code_span_is_not_eaten_by_emphasis(self):
        """行内代码必须先抠出来。

        这个仓的文档里到处是 `198.18.0.0/15`、`*.anthropic.com` 这类内容，
        先跑强调规则的话它们会被吃掉一半。
        """
        got = build_docs.render_inline("拦 `*.anthropic.com` 会连控制面一起拦")
        self.assertIn("<code>*.anthropic.com</code>", got)
        self.assertNotIn("<em>", got)

    def test_html_in_text_is_escaped(self):
        got = build_docs.render_inline("值是 <script>alert(1)</script>")
        self.assertNotIn("<script>", got)
        self.assertIn("&lt;script&gt;", got)

    def test_bold_and_em(self):
        got = build_docs.render_inline("**确证** 和 *推测* 不一样")
        self.assertIn("<strong>确证</strong>", got)
        self.assertIn("<em>推测</em>", got)

    def test_internal_md_link_becomes_html(self):
        got = build_docs.render_inline("见 [路由](03-routing.md)")
        self.assertIn('href="03-routing.html"', got)

    def test_anchor_survives_link_rewrite(self):
        got = build_docs.render_inline("见 [这节](03-routing.md#陷阱一)")
        self.assertIn('href="03-routing.html#陷阱一"', got)

    def test_link_escaping_docs_goes_to_github_source(self):
        """Pages 只发布 docs/，`../cem/net.py` 在站点上是 404。

        而在 GitHub 上读 .md 源文件时它是对的 —— 所以只能在生成 HTML 时
        换成绝对的源码地址，两边都通。
        """
        got = build_docs.render_inline("实现在 [`cem/net.py`](../cem/net.py)")
        self.assertIn("github.com/TbusOS/claude-egress-monitor/blob/main/cem/net.py",
                      got)
        self.assertNotIn('href="../cem', got)

    def test_external_link_is_untouched(self):
        got = build_docs.render_inline("[清单](https://example.com/a.md)")
        self.assertIn('href="https://example.com/a.md"', got)

    def test_autolink(self):
        got = build_docs.render_inline("打开 <http://127.0.0.1:8787/>")
        self.assertIn('<a href="http://127.0.0.1:8787/">', got)


class TestBlocks(unittest.TestCase):
    def test_fenced_code_keeps_markdown_characters_literal(self):
        md = "```bash\ncurl -s https://x/ | grep '**'\n```"
        body, _ = build_docs.render_markdown(md)
        self.assertIn("<pre><code class=\"language-bash\">", body)
        self.assertIn("**", body)
        self.assertNotIn("<strong>", body)

    def test_table(self):
        md = "| 来源 | 给什么 |\n|---|---|\n| Cymru | ASN |\n"
        body, _ = build_docs.render_markdown(md)
        self.assertIn("<th>来源</th>", body)
        self.assertIn("<td>Cymru</td>", body)
        # 宽表要能自己横滚，页面本体不许出现横向滚动条
        self.assertIn('class="table-wrap"', body)

    def test_table_separator_row_is_not_rendered(self):
        md = "| a | b |\n|:---|---:|\n| 1 | 2 |\n"
        body, _ = build_docs.render_markdown(md)
        self.assertNotIn("---", body)

    def test_headings_get_anchors_and_are_collected(self):
        md = "# 标题\n\n## 一、原理\n\n正文\n"
        body, heads = build_docs.render_markdown(md)
        self.assertEqual([h.level for h in heads], [1, 2])
        self.assertIn('<h2 id="', body)

    def test_lists(self):
        md = "- 一\n- 二\n\n1. 甲\n2. 乙\n"
        body, _ = build_docs.render_markdown(md)
        self.assertIn("<ul><li>一</li><li>二</li></ul>", body)
        self.assertIn("<ol><li>甲</li><li>乙</li></ol>", body)

    def test_blockquote(self):
        body, _ = build_docs.render_markdown("> 注意这一条\n")
        self.assertIn("anth-quote", body)
        self.assertIn("注意这一条", body)

    def test_paragraph_stops_at_a_table(self):
        """段落吃行时必须在表格开始处停下，否则表格会被并进段落。"""
        md = "前面一段话\n\n| a |\n|---|\n| 1 |\n"
        body, _ = build_docs.render_markdown(md)
        self.assertIn("<p>前面一段话</p>", body)
        self.assertIn("<table", body)


class TestManualNav(unittest.TestCase):
    def test_trailing_nav_line_is_dropped(self):
        """.md 末尾手写的上下章导航是给 GitHub 读者的，生成页自己有一份。"""
        md = "正文\n\n---\n\n[← 工具箱](06-toolbox.md) · [部署 →](08-deploy.md)\n"
        self.assertNotIn("←", build_docs.strip_manual_nav(md))
        self.assertIn("正文", build_docs.strip_manual_nav(md))

    def test_ordinary_ending_is_kept(self):
        md = "正文\n\n---\n\n最后一段话。\n"
        self.assertIn("最后一段话", build_docs.strip_manual_nav(md))


class TestChapterList(unittest.TestCase):
    def test_every_listed_chapter_has_a_source_file(self):
        """导航里列了但文件不存在 → Pages 上是一个 404，本地看不出来。"""
        for slug, _short in build_docs.CHAPTERS:
            self.assertTrue((ROOT / "docs" / f"{slug}.md").exists(), slug)


if __name__ == "__main__":
    unittest.main()
