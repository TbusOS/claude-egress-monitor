#!/usr/bin/env python3
"""把 docs/*.md 渲染成 GitHub Pages 上的 HTML 章节，并生成 demo 展示页。

## 为什么要有这个脚本

文档的**源是 Markdown**，因为改文档的人不该被迫写 HTML。
但 GitHub Pages 要 HTML，而这个仓不想引入构建工具链（Node、Jekyll、
静态站生成器都要装东西，而本仓的卖点之一是 clone 完就能跑）。

所以：纯标准库的生成器，输出**提交进仓库**。改文档的流程是
「改 .md → 跑一次这个脚本 → 把 .md 和 .html 一起提交」，
Pages 不需要任何 CI。

## 它支持 Markdown 的哪个子集

标题、段落、表格、围栏代码块、有序/无序列表、引用块、分隔线，
以及行内的 `代码` / **粗体** / *斜体* / [链接](x) / 自动链接。
**够用就行** —— 这里不是要写一个 CommonMark 实现，是要渲染这个仓自己的
八篇文档。遇到不支持的语法，宁可原样输出也不要猜。

内部 `.md` 链接会被改写成 `.html`，这样站内跳转在 Pages 上是通的，
而在 GitHub 的仓库浏览器里读 `.md` 源文件时链接也是通的。

用法：

    python3 scripts/build_docs.py            # 全量生成
    python3 scripts/build_docs.py --check    # 只检查是否需要重新生成
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
WEB = ROOT / "web"
ASSETS = DOCS / "assets"

SITE_TITLE = "claude-egress-monitor"
REPO_URL = "https://github.com/TbusOS/claude-egress-monitor"

# 章节顺序就是导航顺序。标题从 .md 的第一个 h1 读，这里只定顺序和短名。
CHAPTERS = (
    ("01-endpoints", "出网域名"),
    ("02-telemetry", "遥测"),
    ("03-routing", "出口为什么不同"),
    ("04-latency", "延迟"),
    ("05-privacy", "隐私边界"),
    ("06-toolbox", "工具箱"),
    ("07-datasources", "数据源"),
    ("08-deploy", "安装部署"),
)


# ───────────────────────────────────────────────────────── 行内标记

INLINE_CODE = re.compile(r"`([^`]+)`")
BOLD = re.compile(r"\*\*([^*]+)\*\*")
EM = re.compile(r"(?<![*\w])\*([^*\n]+)\*(?!\*)")
LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)\)")
IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)\)")
AUTOLINK = re.compile(r"<(https?://[^>\s]+)>")


SOURCE_BASE = f"{REPO_URL}/blob/main/"


def rewrite_href(href: str) -> str:
    """站内 .md 链接改写成 .html；跳出 docs/ 的链接改写成 GitHub 源码地址。

    第二条是必须的：GitHub Pages **只发布 docs/ 目录**，所以文档里
    `[cem/net.py](../cem/net.py)` 这种链接在站点上是 404。而在 GitHub 的
    仓库浏览器里读 .md 源文件时它又是对的 —— 两边都要通，就只能在生成
    HTML 的时候把它换成绝对的源码地址。
    """
    if href.startswith(("http://", "https://", "#", "mailto:")):
        return href
    base, _, frag = href.partition("#")
    if base.startswith("../"):
        return SOURCE_BASE + base[3:] + (("#" + frag) if frag else "")
    if base.endswith(".md"):
        base = base[:-3] + ".html"
    return base + (("#" + frag) if frag else "")


def render_inline(text: str) -> str:
    """行内标记 → HTML。

    顺序是刻意的：**先把行内代码抠出来占位**，否则代码里的 `*` 和 `_`
    会被当成强调标记吃掉 —— 而这个仓的文档里全是 `198.18.0.0/15`、
    `**` 这类内容。
    """
    slots: list[str] = []

    def stash(rendered: str) -> str:
        slots.append(rendered)
        return f"\x00{len(slots) - 1}\x00"

    text = INLINE_CODE.sub(
        lambda m: stash(f"<code>{html.escape(m.group(1))}</code>"), text)
    text = IMAGE.sub(
        lambda m: stash('<img src="%s" alt="%s" loading="lazy">'
                        % (html.escape(rewrite_href(m.group(2)), quote=True),
                           html.escape(m.group(1), quote=True))), text)
    text = LINK.sub(
        lambda m: stash('<a href="%s">%s</a>'
                        % (html.escape(rewrite_href(m.group(2)), quote=True),
                           html.escape(m.group(1)))), text)
    text = AUTOLINK.sub(
        lambda m: stash('<a href="%s">%s</a>'
                        % (html.escape(m.group(1), quote=True),
                           html.escape(m.group(1)))), text)

    text = html.escape(text)
    text = BOLD.sub(lambda m: f"<strong>{m.group(1)}</strong>", text)
    text = EM.sub(lambda m: f"<em>{m.group(1)}</em>", text)

    for i, rendered in enumerate(slots):
        text = text.replace(f"\x00{i}\x00", rendered)
    return text


def slugify(text: str) -> str:
    """标题 → 锚点 id。中文直接留着，浏览器和 GitHub 都支持。"""
    clean = re.sub(r"<[^>]+>", "", text)
    clean = re.sub(r"[^\w一-鿿\- ]+", "", clean).strip()
    return re.sub(r"\s+", "-", clean).lower() or "section"


# ───────────────────────────────────────────────────────── 块级结构

class Heading:
    __slots__ = ("level", "text", "anchor")

    def __init__(self, level: int, text: str):
        self.level = level
        self.text = text
        self.anchor = slugify(text)


def _table_rows(lines: list[str], start: int) -> tuple[list[list[str]], int]:
    """从 start 开始吃掉连续的表格行。返回 (行, 下一个未消费的下标)。"""
    rows: list[list[str]] = []
    i = start
    while i < len(lines) and lines[i].lstrip().startswith("|"):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        rows.append(cells)
        i += 1
    return rows, i


def _is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{2,}:?", c) for c in cells)


def render_table(rows: list[list[str]]) -> str:
    if len(rows) >= 2 and _is_separator(rows[1]):
        head, body = rows[0], rows[2:]
    else:
        head, body = [], rows
    out = ['<div class="table-wrap"><table class="anth-table">']
    if head:
        out.append("<thead><tr>"
                   + "".join(f"<th>{render_inline(c)}</th>" for c in head)
                   + "</tr></thead>")
    out.append("<tbody>")
    for row in body:
        out.append("<tr>" + "".join(f"<td>{render_inline(c)}</td>" for c in row)
                   + "</tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out)


BULLET = re.compile(r"^(\s*)[-*] +(.*)$")
ORDERED = re.compile(r"^(\s*)(\d+)\. +(.*)$")


def _list_block(lines: list[str], start: int) -> tuple[str, int]:
    """吃掉一段列表。只支持一层嵌套 —— 文档里没有更深的。"""
    items: list[list[str]] = []
    ordered = bool(ORDERED.match(lines[start]))
    i = start
    while i < len(lines):
        line = lines[i]
        m = ORDERED.match(line) if ordered else BULLET.match(line)
        if m:
            items.append([m.group(3) if ordered else m.group(2)])
            i += 1
            continue
        # 续行：缩进的非空行接到上一个条目上
        if items and line.strip() and line.startswith(("  ", "\t")):
            items[-1].append(line.strip())
            i += 1
            continue
        break
    tag = "ol" if ordered else "ul"
    body = "".join(f"<li>{render_inline(' '.join(chunk))}</li>" for chunk in items)
    return f"<{tag}>{body}</{tag}>", i


def render_markdown(text: str) -> tuple[str, list[Heading]]:
    """Markdown → (HTML 片段, 标题表)。纯函数。"""
    lines = text.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    headings: list[Heading] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("```"):
            lang = stripped[3:].strip()
            body: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1
            cls = f' class="language-{html.escape(lang, quote=True)}"' if lang else ""
            out.append(f"<pre><code{cls}>{html.escape(chr(10).join(body))}</code></pre>")
            continue

        m = re.match(r"^(#{1,4}) +(.*)$", stripped)
        if m:
            level = len(m.group(1))
            head = Heading(level, m.group(2))
            headings.append(head)
            out.append(f'<h{level} id="{html.escape(head.anchor, quote=True)}">'
                       f"{render_inline(head.text)}</h{level}>")
            i += 1
            continue

        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", stripped):
            out.append('<hr class="anth-divider">')
            i += 1
            continue

        if stripped.startswith("|"):
            rows, i = _table_rows(lines, i)
            out.append(render_table(rows))
            continue

        if stripped.startswith(">"):
            quote: list[str] = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip().lstrip(">").strip())
                i += 1
            out.append(f'<blockquote class="anth-quote">'
                       f"{render_inline(' '.join(quote))}</blockquote>")
            continue

        if BULLET.match(line) or ORDERED.match(line):
            block, i = _list_block(lines, i)
            out.append(block)
            continue

        para: list[str] = []
        while i < len(lines) and lines[i].strip() \
                and not lines[i].strip().startswith(("|", ">", "```", "#")) \
                and not BULLET.match(lines[i]) and not ORDERED.match(lines[i]) \
                and not re.fullmatch(r"-{3,}", lines[i].strip()):
            para.append(lines[i].strip())
            i += 1
        if para:
            out.append(f"<p>{render_inline(' '.join(para))}</p>")

    return "\n".join(out), headings


# ───────────────────────────────────────────────────────── 页面外壳

def nav_html(depth_prefix: str = "") -> str:
    links = "".join(
        f'<a href="{depth_prefix}{slug}.html">{html.escape(short)}</a>'
        for slug, short in CHAPTERS)
    return f"""<nav class="anth-nav"><div class="anth-nav-inner">
  <a class="brand" href="{depth_prefix}index.html">{SITE_TITLE}</a>
  <div class="nav-links">{links}</div>
  <div class="nav-side">
    <a href="{depth_prefix}demo.html">Demo</a>
    <a class="anth-button" href="{REPO_URL}" target="_blank" rel="noopener">GitHub</a>
  </div>
</div></nav>"""


def footer_html(depth_prefix: str = "") -> str:
    chapters = "".join(
        f'<a href="{depth_prefix}{slug}.html">{html.escape(short)}</a>'
        for slug, short in CHAPTERS[:4])
    more = "".join(
        f'<a href="{depth_prefix}{slug}.html">{html.escape(short)}</a>'
        for slug, short in CHAPTERS[4:])
    return f"""<footer class="anth-footer">
  <div class="anth-footer-grid">
    <div class="anth-footer-group"><h5>原理</h5>{chapters}</div>
    <div class="anth-footer-group"><h5>动手</h5>{more}</div>
    <div class="anth-footer-group"><h5>仓库</h5>
      <a href="{REPO_URL}" target="_blank" rel="noopener">源码</a>
      <a href="{REPO_URL}/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener">参与维护</a>
      <a href="{REPO_URL}/issues" target="_blank" rel="noopener">Issues</a>
      <a href="{REPO_URL}/blob/main/LICENSE" target="_blank" rel="noopener">MIT 许可</a>
    </div>
    <div class="anth-footer-group"><h5>看一眼</h5>
      <a href="{depth_prefix}demo.html">成品界面</a>
      <a href="{depth_prefix}architecture.html">架构与设计</a>
      <a href="{depth_prefix}index.html">首页</a>
    </div>
  </div>
  <div class="anth-footer-legal">
    全部探测在本机发起 · 采样结果不上传 · 界面只监听回环地址 ·
    文档与截图中的地址取自 RFC 5737 文档保留段
  </div>
</footer>"""


PAGE = """<!doctype html>
<html lang="zh-CN" data-lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — {site}</title>
<meta name="description" content="{desc}">
<link rel="stylesheet" href="assets/fonts.css">
<link rel="stylesheet" href="assets/anthropic.css">
<link rel="stylesheet" href="assets/docs.css">
</head>
<body>
{nav}
<main class="chapter">
  <div class="chapter__inner">
    <aside class="chapter__toc">
      <span class="chapter__toc-label">本页</span>
      {toc}
    </aside>
    <article class="chapter__body">
      <span class="anth-badge">{badge}</span>
      {body}
      <div class="chapter__nav">{prevnext}</div>
    </article>
  </div>
</main>
{footer}
</body>
</html>
"""


def toc_html(headings: Iterable[Heading]) -> str:
    items = [h for h in headings if h.level == 2]
    if not items:
        return '<span class="chapter__toc-empty">（本页没有分节）</span>'
    return "".join(
        f'<a href="#{html.escape(h.anchor, quote=True)}">{render_inline(h.text)}</a>'
        for h in items)


def prevnext_html(index: int) -> str:
    bits = []
    if index > 0:
        slug, short = CHAPTERS[index - 1]
        bits.append(f'<a class="anth-link" href="{slug}.html">← {html.escape(short)}</a>')
    else:
        bits.append('<a class="anth-link" href="index.html">← 首页</a>')
    if index < len(CHAPTERS) - 1:
        slug, short = CHAPTERS[index + 1]
        bits.append(f'<a class="anth-link" href="{slug}.html">{html.escape(short)} →</a>')
    else:
        bits.append('<a class="anth-link" href="demo.html">看成品界面 →</a>')
    return "".join(bits)


MANUAL_NAV = re.compile(r"\n-{3,}\n+\[?←[^\n]*\n*$")


def strip_manual_nav(md: str) -> str:
    """去掉 .md 末尾手写的「← 上一章 · 下一章 →」那一行。

    那行是给在 GitHub 上直接读 .md 的人用的。生成的页面自己有上下章导航，
    留着就会连着出现两遍。
    """
    return MANUAL_NAV.sub("\n", md)


def first_paragraph(md: str) -> str:
    for block in md.split("\n\n"):
        block = block.strip()
        if block and not block.startswith(("#", "|", ">", "-", "```")):
            return re.sub(r"[*`\[\]]|\(.*?\)", "", block).replace("\n", " ")[:150]
    return f"{SITE_TITLE} 文档"


def build_chapter(index: int, slug: str) -> Optional[Path]:
    src = DOCS / f"{slug}.md"
    if not src.exists():
        print(f"  ! 缺少 {src.name}，跳过")
        return None
    md = strip_manual_nav(src.read_text(encoding="utf-8"))
    body, headings = render_markdown(md)
    title = headings[0].text if headings else slug
    # h1 已经在正文里了，徽章放章节编号，避免标题重复两遍
    page = PAGE.format(
        title=html.escape(title), site=SITE_TITLE,
        desc=html.escape(first_paragraph(md), quote=True),
        nav=nav_html(), toc=toc_html(headings),
        badge=f"第 {index + 1} 章 · {html.escape(CHAPTERS[index][1])}",
        body=body, prevnext=prevnext_html(index), footer=footer_html())
    out = DOCS / f"{slug}.html"
    out.write_text(page, encoding="utf-8")
    return out


# ───────────────────────────────────────────────────────── 资源与 demo

SKILL_ASSETS = Path.home() / ".claude" / "skills" / "anthropic-design" / "assets"


def copy_assets() -> None:
    """把界面用到的静态资源收进 docs/assets/。

    Pages 只发布 docs/ 目录，所以 demo 页引用不到 web/assets/ ——
    必须复制一份。这也是这个脚本存在的第二个理由。
    """
    ASSETS.mkdir(parents=True, exist_ok=True)
    for name in ("atelier.css", "atelier.js"):
        shutil.copy2(WEB / "assets" / name, ASSETS / name)
    shutil.copy2(WEB / "app.js", ASSETS / "app.js")
    # atelier 和 anthropic 各自的字体表都叫 fonts.css，改名避免互相覆盖
    shutil.copy2(WEB / "assets" / "fonts.css", ASSETS / "atelier-fonts.css")
    for name in ("anthropic.css", "fonts.css"):
        src = SKILL_ASSETS / name
        if src.exists():
            shutil.copy2(src, ASSETS / name)
        elif not (ASSETS / name).exists():
            print(f"  ! 找不到 {src}，且 docs/assets/{name} 也不存在")


DEMO_SHIM = """<script>
/* 离线 demo：把 app.js 会打的三个接口换成内置的一轮虚构采样。
 * 这样 GitHub Pages 上这一页能点、能切面板、能排序，
 * 但**一个请求都不会发出去** —— 一个讲出网流量的页面，
 * 自己偷偷联网是最没有说服力的事。 */
(function () {
  var STATE = %(state)s;
  var PATH = %(path)s;
  function reply(body) {
    return Promise.resolve({ ok: true, json: function () { return Promise.resolve(body); } });
  }
  window.fetch = function (url) {
    var u = String(url);
    if (u.indexOf('/api/path') === 0) return reply(PATH);
    if (u.indexOf('/api/telemetry') === 0) return reply(STATE.telemetry_fields || { ok: false, error: '演示模式下不做静态提取' });
    if (u.indexOf('/api/day') === 0) return reply(STATE.day_detail || { ok: false });
    if (u.indexOf('/api/state') === 0) return reply(STATE);
    return reply({ ok: false, error: 'demo' });
  };
  /* 开关和「立刻采一轮」在这一页没有服务端可打，禁用掉并说明原因，
     比让它们点了没反应好。 */
  window.EventSource = undefined;
  document.addEventListener('DOMContentLoaded', function () {
    ['monitor-switch', 'sample-now', 'telemetry-load'].forEach(function (name) {
      var node = document.querySelector('[data-cem="' + name + '"]');
      if (node) { node.setAttribute('disabled', 'disabled'); node.style.opacity = '0.5'; }
    });
  });
})();
</script>
"""

# 这段话里"发不发请求"必须说准。这一页的主题就是出网流量，
# 在它自己身上含糊一句，整个工具的可信度都要打折。
DEMO_BANNER = """<div class="demo-banner">
  <strong>这是一份静态演示。</strong>
  数据是一轮完全虚构的采样，地址取自 RFC 5737 文档保留段，不是任何人的真实网络。
  面板可以点、可以切、可以排序，但开关是禁用的 —— 这里<strong>没有服务端</strong>，
  一个探测请求也发不出去。（页面本身会向 Google Fonts 取一次字体，
  那是它唯一的外发请求，被拦掉也照样能读。）
  想看真实数据，<a href="%(repo)s">把仓库 clone 下来</a>跑
  <code>python3 -m cem serve --open</code>。
  <a href="index.html">← 回文档首页</a>
</div>
"""


def demo_payloads() -> tuple[dict, dict]:
    """跑一次仓库自带的演示数据，拿到 /api/state 真实的形状。

    刻意走和 `cem serve --demo` 完全相同的路径（`demo.seed` + `view.snapshot`），
    而不是手写一份 JSON —— 手写的那份会随着 view.py 改动悄悄过期，
    而 demo 页看起来还是好的。
    """
    sys.path.insert(0, str(ROOT))
    from cem import demo, view                      # noqa: E402  延迟导入
    from cem.sampler import Sampler, SamplerConfig  # noqa: E402
    from cem.store import History                   # noqa: E402

    history = History()
    sampler = Sampler(history, config=SamplerConfig(interval_s=30))
    demo.seed(history, sampler)
    state = view.snapshot(history, sampler, day_store=None)

    # 路径质量是按需接口，演示数据单独造一份。刻意造出三种情况各一条：
    # 一条正常但中间跳有假丢包、一条终点不回 ICMP、一条 fake-ip 测不了 ——
    # 这三种恰好是这个面板要教会读者分辨的全部内容。
    good = {
        "target": "203.0.113.24", "ok": True, "error": None,
        "resolved": "203.0.113.24", "resolved_kind": "real",
        "hop_count": 6, "endpoint_silent": False,
        "end_to_end_loss": 0.0, "jitter_ms": 3.4, "final_avg_ms": 172.4,
        "last_answering_index": 6,
        "hosts": ["api.anthropic.com", "claude.ai", "code.claude.com"],
        "shared": True, "ts": 0,
        "hops": [
            {"index": 1, "host": "192.168.1.1", "loss_pct": 0.0, "sent": 5,
             "avg_ms": 2.1, "best_ms": 1.8, "worst_ms": 2.9, "stdev_ms": 0.4,
             "answered": True, "private": True, "meaningful_loss": False,
             "last": False},
            {"index": 2, "host": "100.64.0.1", "loss_pct": 0.0, "sent": 5,
             "avg_ms": 9.7, "best_ms": 8.9, "worst_ms": 11.2, "stdev_ms": 0.9,
             "answered": True, "private": True, "meaningful_loss": False,
             "last": False},
            {"index": 3, "host": None, "loss_pct": 40.0, "sent": 5,
             "avg_ms": None, "best_ms": None, "worst_ms": None,
             "stdev_ms": None, "answered": False, "private": False,
             "meaningful_loss": True, "last": False},
            {"index": 4, "host": "198.51.100.9", "loss_pct": 0.0, "sent": 5,
             "avg_ms": 71.5, "best_ms": 70.1, "worst_ms": 74.0,
             "stdev_ms": 1.5, "answered": True, "private": False,
             "meaningful_loss": False, "last": False},
            {"index": 5, "host": "198.51.100.41", "loss_pct": 0.0, "sent": 5,
             "avg_ms": 168.2, "best_ms": 166.0, "worst_ms": 173.1,
             "stdev_ms": 2.8, "answered": True, "private": False,
             "meaningful_loss": False, "last": False},
            {"index": 6, "host": "203.0.113.24", "loss_pct": 0.0, "sent": 5,
             "avg_ms": 172.4, "best_ms": 169.8, "worst_ms": 179.0,
             "stdev_ms": 3.4, "answered": True, "private": False,
             "meaningful_loss": False, "last": True},
        ],
    }
    silent = {
        "target": "198.51.100.77", "ok": True, "error": None,
        "resolved": "198.51.100.77", "resolved_kind": "real",
        "hop_count": 3, "endpoint_silent": True,
        "end_to_end_loss": None, "jitter_ms": None, "final_avg_ms": None,
        "last_answering_index": 2,
        "hosts": ["www.anthropic.com"], "shared": False, "ts": 0,
        "hops": [
            {"index": 1, "host": "192.168.1.1", "loss_pct": 0.0, "sent": 5,
             "avg_ms": 2.0, "best_ms": 1.7, "worst_ms": 2.6, "stdev_ms": 0.3,
             "answered": True, "private": True, "meaningful_loss": False,
             "last": False},
            {"index": 2, "host": "198.51.100.9", "loss_pct": 0.0, "sent": 5,
             "avg_ms": 68.9, "best_ms": 67.2, "worst_ms": 71.0, "stdev_ms": 1.3,
             "answered": True, "private": False, "meaningful_loss": False,
             "last": False},
            {"index": 3, "host": None, "loss_pct": 100.0, "sent": 5,
             "avg_ms": None, "best_ms": None, "worst_ms": None, "stdev_ms": None,
             "answered": False, "private": False, "meaningful_loss": True,
             "last": True},
        ],
    }
    from cem.pathtrace import FAKE_IP_REFUSAL          # noqa: E402
    fake = {
        "target": "198.18.0.56", "ok": False, "error": FAKE_IP_REFUSAL,
        "resolved": "198.18.0.56", "resolved_kind": "fake-ip",
        "hop_count": 0, "endpoint_silent": False,
        "end_to_end_loss": None, "jitter_ms": None, "final_avg_ms": None,
        "last_answering_index": None,
        "hosts": ["platform.claude.com"], "shared": False, "ts": 0,
        "hops": [],
    }
    path = {
        "status": {
            "available": True, "running": False, "sweeping": False,
            "interval_s": 300, "cycles": 5, "sweeps": 1,
            "last_sweep_ts": None, "last_error": None,
            "done": 3, "total": 3, "current": None,
        },
        "available": True,
        "hint": None,
        "rows": [good, silent, fake],
    }
    return state, path


def build_demo() -> Path:
    """把真实界面复制成一个静态页，接口换成内置数据。

    刻意**不重写一套界面**：demo 页和真实界面共用同一个 index.html 和
    app.js，所以它不会随时间和真实界面走偏 —— 一个和产品长得不一样的
    demo 比没有 demo 更糟。
    """
    state, path = demo_payloads()
    src = (WEB / "index.html").read_text(encoding="utf-8")
    src = src.replace('href="assets/', 'href="assets/') \
             .replace('src="assets/atelier.js"', 'src="assets/atelier.js"') \
             .replace('src="app.js"', 'src="assets/app.js"') \
             .replace('href="assets/fonts.css"', 'href="assets/atelier-fonts.css"')

    shim = DEMO_SHIM % {
        "state": json.dumps(state, ensure_ascii=False),
        "path": json.dumps(path, ensure_ascii=False),
    }
    banner = DEMO_BANNER % {"repo": REPO_URL}
    style = """<style>
  .demo-banner {
    max-width: 1180px; margin: 0 auto var(--space-5); padding: 14px 18px;
    border-radius: var(--radius-md); background: rgba(255,255,255,0.82);
    border: 1px solid rgba(88,62,50,0.16); font-size: 13px; line-height: 1.7;
    color: #4a3a33;
  }
  .demo-banner a { color: #b83370; }
  .demo-banner code { font-family: var(--font-mono); font-size: 12px; }
</style>
"""
    src = src.replace("</head>", style + "</head>")
    src = src.replace('<div class="atl-page atl-page--wide">',
                      banner + '<div class="atl-page atl-page--wide">')
    # shim 必须在 app.js **之前**，否则 app.js 已经拿真 fetch 打过接口了
    src = src.replace('<script src="assets/app.js"></script>',
                      shim + '<script src="assets/app.js"></script>')
    out = DOCS / "demo.html"
    out.write_text(src, encoding="utf-8")
    return out


# ───────────────────────────────────────────────────────── 入口

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="生成 docs/ 下的 HTML")
    parser.add_argument("--check", action="store_true",
                        help="只检查生成结果是否和当前 .md 一致（给 CI 用）")
    args = parser.parse_args(argv)

    if args.check:
        before = {p: p.read_bytes() for p in DOCS.glob("*.html") if p.exists()}

    print("→ 复制静态资源")
    copy_assets()

    print("→ 渲染章节")
    for i, (slug, short) in enumerate(CHAPTERS):
        out = build_chapter(i, slug)
        if out:
            print(f"   {out.name}  ({short})")

    print("→ 生成 demo 页")
    print(f"   {build_demo().name}")

    (DOCS / ".nojekyll").write_text("", encoding="utf-8")

    if args.check:
        changed = [p.name for p, data in before.items()
                   if p.exists() and p.read_bytes() != data]
        if changed:
            print("\n生成结果与提交的不一致：" + ", ".join(changed))
            print("跑 python3 scripts/build_docs.py 然后把改动一起提交。")
            return 1
        print("\n生成结果与提交的一致。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
