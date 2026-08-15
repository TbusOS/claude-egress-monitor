# 安装、使用、长期运行

从 `git clone` 到"挂着跑一个月"的完整流程。

---

## 一、依赖

| 项 | 要求 | 说明 |
|---|---|---|
| Python | **3.9+** | 只用标准库，不装任何包 |
| 系统 | macOS | 进程与代理检测依赖 `ps` / `lsof` / `scutil` |
| root | **不需要** | 全程以普通用户运行 |
| 网络 | 出网 | 探测本身就是它的工作 |

Linux 上核心探测（出口 IP、延迟、DNS 对账、遥测字段）可以跑，
但"读系统代理"和"列进程连接"两块依赖 macOS 的命令，会降级。
移植的入口在 `cem/paths.py` 和 `cem/sockets.py`，欢迎提 PR。

---

## 二、装

```bash
git clone https://github.com/TbusOS/claude-egress-monitor.git
cd claude-egress-monitor

python3 -m cem doctor     # 先看清本机三个入口各走哪条路（不发探测）
```

`doctor` 不联网，它只读本机配置。看到三条路径都被识别出来，就说明装好了。

### 可选：装 mtr 拿路径质量

```bash
bash scripts/install-deps.sh
```

这个脚本只做一件事：用 Homebrew 装 `mtr`，然后告诉你怎么给它权限。
它**不会**自己改系统文件权限 —— 那个决定应该由你自己做。

`mtr` 要发 ICMP 探测包，需要 raw socket，也就是需要 root。两种解法：

```bash
# A. 每次手动跑时加 sudo（不改任何系统状态）
sudo mtr --json -n -c 5 -- claude.ai

# B. 给辅助程序 setuid，之后普通用户可直接跑（改了系统文件权限，自己权衡）
sudo chown root $(brew --prefix)/sbin/mtr-packet
sudo chmod u+s $(brew --prefix)/sbin/mtr-packet
```

本工具默认按普通用户调用 —— **一个监控工具不该要求你用 sudo 跑它自己**。
没给权限时路径质量面板显示"未安装/无权限"并给出上面这两条命令，
其余功能完全不受影响。

装好之后，界面「路径质量」那一屏有两个入口：

- **全部测一遍** —— 把所有 Claude 域名加对照组跑一遍，约一到两分钟。
  跑的时候按钮上有 `N/M` 进度，结果一条一条出。
- **自动探测**（默认关闭）—— 打开之后按 1 / 5 / 15 分钟自己跑。
  它有自己的开关和间隔，不跟着主监控走：主采样一轮几百毫秒，
  而一遍 mtr 要一两分钟，混在一起会让"每 30 秒一轮"变成谎话。

两个地方会**拒测并说明原因**，而不是给一个假数字：

- 目标解析到 **fake-ip 占位地址**时。硬测会得到一跳、零点几毫秒的漂亮结果，
  那是本机分流器自己应答的，和 Claude 无关。
- 终点**一个 ICMP 回包都没有**时，报"量不出丢包率"而不是"丢包 100%"。

另外，**解析到同一个地址的域名只测一次**（并列出共用它的那些域名）——
七个域名指向同一套 Anycast 前端时，测七遍不会多出任何信息。

---

## 三、命令

| 命令 | 做什么 | 联网 |
|---|---|---|
| `python3 -m cem doctor` | 看清本机三个入口各走哪条路 | 否 |
| `python3 -m cem probe` | 立刻采一轮，打印在终端 | 是 |
| `python3 -m cem probe --json` | 同上，输出 JSON | 是 |
| `python3 -m cem endpoints` | 打印 Claude 会连的域名清单 + 取证来源 | 否 |
| `python3 -m cem telemetry` | 静态提取遥测字段 | 否 |
| `python3 -m cem serve` | 起网页界面 | 按需 |

常用参数：

```bash
python3 -m cem probe --all            # 把可选项全打开（含厂商 IP 段、RDAP）
python3 -m cem probe --no-telemetry   # 跳过遥测目的地探测
python3 -m cem probe --no-sockets     # 不列本机连接
python3 -m cem probe --path-quality   # 顺带跑 mtr（慢，要装 mtr）
python3 -m cem telemetry --all-events # 打印全部事件名而不是前几十个
```

---

## 四、网页界面

```bash
python3 -m cem serve --open
```

打开 <http://127.0.0.1:8787/>。**监控默认是关的** ——
一个监控网络流量的工具，不该在你没同意之前就开始发请求。
在页面右上角的开关打开它，采样间隔可选 10 秒 / 30 秒 / 5 分钟。

| 参数 | 默认 | 说明 |
|---|---|---|
| `--host` | `127.0.0.1` | **只监听回环地址** |
| `--port` | `8787` | |
| `--interval` | `30` | 采样间隔（秒） |
| `--start` | 关 | 起来就开始采（无人值守时用） |
| `--archive` | `./data/days` | 按天归档目录 |
| `--no-archive` | — | 完全不落盘 |
| `--demo` | 关 | 注入虚构数据，一个探测都不发 |
| `--open` | 关 | 顺手打开浏览器 |

### 不要把它暴露到局域网

界面上有出口 IP、代理端口、本机连接列表和进程名 ——
**这些合起来就是"你的网络长什么样"**。默认只监听回环地址是刻意的。

真要在另一台机器上看，用 SSH 转发，别改 `--host`：

```bash
ssh -N -L 8787:127.0.0.1:8787 你的用户名@那台机器
# 然后在本地浏览器打开 http://127.0.0.1:8787/
```

### 只想看界面长什么样

```bash
python3 -m cem serve --demo --open
```

演示模式注入一轮完全虚构的采样，地址取自 RFC 5737 文档保留段
（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`），
一个探测都不发。界面上会显式标出"演示数据"。

---

## 五、长期挂着跑

### 方式一：tmux（最简单）

```bash
tmux new -s cem
python3 -m cem serve --start --interval 300
# Ctrl-b d 退出，随时 tmux attach -t cem 回来
```

### 方式二：launchd（开机自启，macOS 原生）

写 `~/Library/LaunchAgents/com.local.cem.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>com.local.cem</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>-m</string><string>cem</string>
    <string>serve</string>
    <string>--start</string>
    <string>--interval</string><string>300</string>
  </array>
  <key>WorkingDirectory</key> <string>/绝对路径/claude-egress-monitor</string>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>        <true/>
  <key>StandardOutPath</key>  <string>/tmp/cem.log</string>
  <key>StandardErrorPath</key><string>/tmp/cem.err</string>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.local.cem.plist   # 启用
launchctl unload ~/Library/LaunchAgents/com.local.cem.plist # 停用
```

长期跑请把 `--interval` 调到 300 秒以上。30 秒是给"正在排查"用的，
挂一个月的话它会白发几十万次请求。

---

## 六、数据存在哪、怎么删

```
data/
├── days/2026-08-15.jsonl   ← 按天一个文件，每轮一条精简记录（约 1 KB）
├── asn-cache.json          ← ASN 查询缓存
└── cloud-ranges.json       ← 厂商官方 IP 段缓存（24 小时）
```

一整天 5 分钟一轮 ≈ 288 条 ≈ **300 KB**。

**这些文件全部在 `.gitignore` 里**，因为采样产物就是你的网络长什么样。
提交上去等于把自己的出口、代理端口、内网地址公开。

界面「历史看板」里可以选看哪几天、也可以**删掉哪几天**。
命令行直接删也行：

```bash
rm data/days/2026-08-1*.jsonl     # 删某几天
rm -rf data/                      # 全清（缓存会自己重建）
```

---

## 七、部署这份文档站（GitHub Pages）

`docs/` 目录本身就是 Pages 的站点根。章节 HTML 由 Markdown 生成：

```bash
python3 scripts/build-docs.py      # docs/*.md → docs/*.html，并生成 demo 页
```

生成器只用标准库，没有构建工具链。改文档的正确姿势是**改 `.md`，
然后跑一次这个脚本**，把生成的 `.html` 一起提交 ——
这样 Pages 不需要 CI 就能更新。

在自己的 fork 上开 Pages：仓库 **Settings → Pages → Source: Deploy from a branch
→ Branch: `main` / 目录 `/docs`**。

---

## 八、卸载

```bash
# 停掉 launchd（如果配过）
launchctl unload ~/Library/LaunchAgents/com.local.cem.plist
rm ~/Library/LaunchAgents/com.local.cem.plist

# 删仓库和数据
rm -rf claude-egress-monitor

# 如果给 mtr 加过 setuid，想还原：
sudo chmod u-s $(brew --prefix)/sbin/mtr-packet
sudo chown $(whoami) $(brew --prefix)/sbin/mtr-packet
```

工具不写系统配置、不装 CA 证书、不改网络设置、不注册后台服务
（除非你自己配了 launchd）。删掉目录就干净了。

---

## 九、跑测试

```bash
python3 -m unittest discover -s tests -t . -v
```

全部离线，不发任何请求 —— 解析器都写成了纯函数，喂固定样本。
改代码前先跑一遍，改完再跑一遍。

---

[← 数据源](07-datasources.md) · [回到目录](index.html)
