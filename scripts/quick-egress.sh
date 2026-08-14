#!/usr/bin/env bash
# quick-egress.sh —— 不装任何东西、三十秒看清出口的最小版本。
#
# 只用 curl。做的事和 `python3 -m cem probe` 的第一节一样：
# 拿两条路径（直连 / 系统代理）分别去问几个目的地「你看到的我是谁」。
#
# 想要完整功能（解析对账、实时连接、延迟分段、界面）用 Python 版本。

set -u

TARGETS=(
  "api.anthropic.com"      # 模型 API，Claude Code 的主流量
  "claude.ai"              # 网页端
  "code.claude.com"        # Claude Code 后端服务
  "1.1.1.1"                # 对照组：同样在 Cloudflare 上
)

# 读 macOS 系统代理 —— 桌面端和浏览器用的就是这份配置
read_system_proxy() {
  command -v scutil >/dev/null 2>&1 || return 1
  local out enable host port
  out=$(scutil --proxy 2>/dev/null) || return 1
  enable=$(printf '%s\n' "$out" | awk '/HTTPSEnable/ {print $3}')
  [ "${enable:-0}" = "1" ] || return 1
  host=$(printf '%s\n' "$out" | awk '/HTTPSProxy/ {print $3}')
  port=$(printf '%s\n' "$out" | awk '/HTTPSPort/ {print $3}')
  [ -n "${host:-}" ] && [ -n "${port:-}" ] || return 1
  printf 'http://%s:%s' "$host" "$port"
}

field() { printf '%s\n' "$1" | awk -F= -v k="$2" '$1==k {print $2}'; }

probe() {  # probe <标签> <代理或空>
  local label="$1"
  local proxy="${2:-}"
  local suffix=""
  # 变量名后面紧跟中文字符时**必须**加花括号：`$proxy）` 里那个全角右括号
  # 的首字节会被 bash 当成变量名的一部分，报 "proxy?: unbound variable"。
  # 写成 ${proxy} 就没这个问题。
  if [ -n "$proxy" ]; then
    suffix="（经 ${proxy}）"
  fi
  printf '\n%s\n' "── ${label}${suffix}"
  printf '%-24s %-6s %-6s %s\n' "域名" "地区" "机房" "出口 IP"
  for host in "${TARGETS[@]}"; do
    local body
    if [ -n "$proxy" ]; then
      body=$(curl -s --max-time 12 -x "$proxy" "https://$host/cdn-cgi/trace" 2>/dev/null)
    else
      body=$(curl -s --max-time 12 --noproxy '*' "https://$host/cdn-cgi/trace" 2>/dev/null)
    fi
    if [ -z "$body" ]; then
      printf '%-24s %-6s %-6s %s\n' "$host" "—" "—" "探测失败"
      continue
    fi
    printf '%-24s %-6s %-6s %s\n' "$host" \
      "$(field "$body" loc)" "$(field "$body" colo)" "$(field "$body" ip)"
  done
}

echo "Claude 出口速查 —— 出口 IP 是目的地那侧看到的源地址，不是本机接口地址"

# Claude Code 走的是环境变量里的代理；没设就直连。
CLI_PROXY="${HTTPS_PROXY:-${https_proxy:-}}"
probe "Claude Code（环境变量代理）" "$CLI_PROXY"

# 桌面端 / 浏览器走系统代理。
if SYS_PROXY=$(read_system_proxy); then
  probe "Claude 桌面端 / 浏览器（系统代理）" "$SYS_PROXY"
else
  echo
  echo "── Claude 桌面端 / 浏览器：系统代理未开启，与上面同路"
fi

cat <<'NOTE'

怎么读：
  · 两组的「出口 IP」不同 → 三个入口走了不同的出网路径，看 docs/03-routing.md
  · 同一组里 1.1.1.1 和 claude.ai 的出口不同 → 分流规则按域名逐条命中，
    有 Claude 的域名没被规则覆盖到
  · 地区落在 CN / HK / RU / IR 等受限地区 → 账号风控风险，先去核对官方条款
NOTE
