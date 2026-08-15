# 文档站样式的来源

这个目录里的文件**不是手写的**，是 `scripts/build_docs.py` 收集进来的。
改它们没用，下次生成会被覆盖。

| 文件 | 从哪来 | 干什么 |
|---|---|---|
| `anthropic.css` · `fonts.css` | **anthropic-design** skill | 文档站（首页 / 章节 / 架构页）的视觉语言：暖米白底、Poppins + Lora、橙色强调、编辑式长文 |
| `docs.css` | 本仓自己写的 | 叠在上面的站内样式（章节版式、目录、卡片、图框） |
| `atelier.css` · `atelier.js` · `atelier-fonts.css` | **atelier-design** skill | `demo.html` 用的应用界面样式，从 `web/assets/` 复制过来 |
| `app.js` | 本仓 `web/app.js` | demo 页复用的就是真实界面的那份渲染逻辑 |

## 为什么要复制而不是引用

GitHub Pages 只发布 `docs/` 目录，所以 `demo.html` 引用不到 `web/assets/`。
复制一份是让 Pages 能独立工作的最简单办法，代价是这几个文件在仓库里有两份。
`build_docs.py` 每次生成都重新复制，两份不会走偏。

`atelier-fonts.css` 是重命名过的 —— 两套 skill 的字体表都叫 `fonts.css`，
不改名会互相覆盖。

## 两套设计语言，两个用途

- **anthropic-design** 画的是文档：长文、表格、代码块、架构图。
- **atelier-design** 画的是应用界面：侧栏路由、KPI 行、图表、开关。

atelier 自己的文档里明确写了"文档站别用我"，所以这里没有混用 ——
文档站是 anthropic，demo 页是 atelier，因为 demo 页本身就是那个应用。

两套视觉语言分别重建自 [Ghani Pradita](https://dribbble.com/ghanipradita)
的仪表盘作品（atelier）和 anthropic.com 的编辑式排版（anthropic）。
**没有照抄任何一稿**，借的是这两套语言的语法。

字体从 Google Fonts 加载。在一个主题是"出网流量"的站点上这件事值得点明：
那是页面唯一的外发请求，被拦掉时会回退到系统字体栈，照样能读。
