# 界面样式的来源

`atelier.css` / `atelier.js` / `fonts.css` 来自 **atelier-design** ——
一套用于生成"暖渐变壁纸 + 整窗磨砂玻璃"应用界面的设计 skill，
不是本仓自己写的样式表。它们被原样复制进来，好处是这个工具
不需要构建步骤、不需要 CDN，`git clone` 完就能跑。

这套视觉语言（暖 mesh 壁纸 / 整窗磨砂 / 珊瑚→玫红渐变圆球 / 灰轨道圆头柱 /
每屏一张暗卡）重建自 [Ghani Pradita](https://dribbble.com/ghanipradita)
（印尼日惹 · Paperpillar）的仪表盘作品。**没有照抄任何一稿** ——
配色、排版、组件、文案全部重写，借的是这套语言的语法。

字体从 Google Fonts 加载（Plus Jakarta Sans / JetBrains Mono / Noto Sans SC）。
在一个主题是"出网流量"的页面上这件事值得点明：那是一个到第三方的请求。
删掉 `index.html` 里 `fonts.css` 那一行即可去掉它，页面用系统字体栈照样可读。

**对 skill 原文件做过一处改动**：`fonts.css` 里 `display=swap` 改成了
`display=optional`。实测 swap 会在字体到达后重排整页，渲染闸量到
CLS 0.21（阈值 0.1）；而这个工具的使用者都在代理后面，Google Fonts
经常被拦，swap 之下那是一次迟到的跳变。改动的理由和代价写在
`fonts.css` 的注释里。除此之外三个文件与 skill 一致。

本仓页面自己的样式写在 `index.html` 的 `<style>` 里，一律用**无前缀** class
（`.surface-card`、`.tele-row` 之类）；`atl-` 前缀的都属于上面那套 skill。
