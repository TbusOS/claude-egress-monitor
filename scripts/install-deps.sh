#!/usr/bin/env bash
# install-deps.sh —— 一键装上「让检测更准」的可选外部工具。
#
# 先说清楚边界：**这些全都是可选的**。不装任何东西，
# `python3 -m cem serve` 也能跑，出口 IP、地区、ASN、延迟分段、
# 解析对账、实时连接、证书检查、历史看板全都工作 —— 因为那些只用
# Python 标准库和 macOS 自带的 dig / lsof / scutil / ps。
#
# 装了之后多出来的是**路径质量**这一个维度：跳数、每跳延迟、丢包。
# 这是目前唯一答不了"TLS 握手忽快忽慢，到底是距离远还是在丢包"的地方。
#
# 不装逆向工具（IDA / Ghidra / Frida）。这个仓库解决的是"流量去哪"，
# 答案在链路和系统状态里，不在二进制里 —— 详见 docs/06-toolbox.md。

set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; OK=$'\033[32m'; WARN=$'\033[33m'; OFF=$'\033[0m'

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
good() { printf '  %s✓%s %s\n' "$OK" "$OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$WARN" "$OFF" "$*"; }
note() { printf '  %s%s%s\n' "$DIM" "$*" "$OFF"; }

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      say "用法：bash scripts/install-deps.sh [--dry-run]"
      say ""
      say "  --dry-run   只检查缺什么，不装任何东西"
      exit 0 ;;
    *) warn "不认识的参数：$arg"; exit 2 ;;
  esac
done

run() {
  if [ "$DRY_RUN" = "1" ]; then
    note "（dry-run，跳过）$*"
  else
    "$@"
  fi
}

# ─────────────────────────────────────────────── 先看必需项

step "必需项（不装这些整个工具跑不了）"

if command -v python3 >/dev/null 2>&1; then
  PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "?")
  case "$PYV" in
    3.9|3.1[0-9]) good "python3 $PYV" ;;
    *) warn "python3 $PYV —— 需要 3.9+，低于这个版本类型注解语法会报错" ;;
  esac
else
  warn "没有 python3。macOS 自带的在 /usr/bin/python3，装了 Xcode 命令行工具就有："
  note "xcode-select --install"
fi

for tool in dig lsof scutil ps; do
  if command -v "$tool" >/dev/null 2>&1; then
    good "$tool"
  else
    warn "缺 $tool —— 这个 macOS 自带，缺了说明 PATH 有问题"
  fi
done

# ─────────────────────────────────────────────── 可选项

step "可选项（装了检测更准）"

MISSING=()

if command -v mtr >/dev/null 2>&1 || [ -x /opt/homebrew/sbin/mtr ] \
   || [ -x /usr/local/sbin/mtr ]; then
  good "mtr —— 路径质量（跳数 / 每跳延迟 / 丢包）可用"
else
  warn "mtr 没装 —— 路径质量这一块会显示「未安装」，其余功能不受影响"
  note "它能回答：TLS 握手忽快忽慢，是距离远还是链路在丢包"
  MISSING+=("mtr")
fi

if command -v jq >/dev/null 2>&1; then
  good "jq —— 方便手工处理 cem probe --json 的输出"
else
  note "jq 没装（纯粹是手工调试时方便，工具本身不用它）"
  MISSING+=("jq")
fi

# ─────────────────────────────────────────────── 安装

if [ ${#MISSING[@]} -eq 0 ]; then
  step "全都齐了，不用装任何东西"
  exit 0
fi

step "准备安装：${MISSING[*]}"

if ! command -v brew >/dev/null 2>&1; then
  warn "没有 Homebrew。这个脚本不替你装 Homebrew —— 那会往系统里写很多东西，"
  warn "应该由你自己决定。装法见 https://brew.sh，然后重跑这个脚本。"
  say ""
  say "或者手工装："
  say "  MacPorts:  sudo port install ${MISSING[*]}"
  exit 1
fi

good "找到 Homebrew：$(command -v brew)"

# mtr 在 macOS 上装完之后，二进制在 sbin 且需要 root 才能发 ICMP。
# Homebrew 的 formula 会提示怎么处理，这里如实转达而不是替用户 sudo。
run brew install "${MISSING[@]}"

if printf '%s\n' "${MISSING[@]}" | grep -qx mtr; then
  step "mtr 装完之后还有一步"
  say "  macOS 上 mtr 需要 root 权限才能发 ICMP 探测包。两种做法："
  say ""
  say "  A. 每次用 sudo（最简单，什么都不用改）："
  say "     sudo mtr --json -n -c 5 -- claude.ai"
  say ""
  say "  B. 给它 setuid，之后普通用户可直接跑（改了系统文件权限，自己权衡）："
  say "     sudo chown root \$(brew --prefix)/sbin/mtr"
  say "     sudo chmod u+s \$(brew --prefix)/sbin/mtr"
  say ""
  note "本工具默认按普通用户调用 mtr。走 A 的话路径质量那块会显示权限不足，"
  note "这是预期行为 —— 一个监控工具不该要求你用 sudo 跑它自己。"
fi

step "完成"
say "  验证：python3 -m cem doctor"
