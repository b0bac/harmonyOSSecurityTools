#!/bin/sh
# =============================================================================
# sandbox_forensics.sh — HarmonyOS PC 应用沙箱取证采集脚本(device-side)
#
# 在 HarmonyOS PC 本地运行。POSIX sh,不依赖 python / sqlite3。
# 功能:
#   scan  探测沙箱,列出 数据库(RDB/sqlite)/ Preferences / 疑似凭据 / 日志 清单
#   pack  把可取证文件打包成 tar.gz,供回传主机分析
#   all   scan + pack
#
# 自适应权限: root 遍历全部应用沙箱; 非_root 仅本应用沙箱(自动降级)。
# 纯只读: 不修改、不删除任何数据。
#
# 路径依据: OpenHarmony 标准系统应用沙箱 /data/app/el2/<userId>/<bundleName>/
#           (EL2 = 解锁后可访问的加密层; EL1 为设备级)。
#           真机路径若不同, scan 会打印实际可达范围, 据此校准 SANDBOX_ROOTS。
#
# 仅用于授权安全测试 / 取证。
# =============================================================================
set -u

VERSION="0.1"
PROG="${0##*/}"
OUTDIR="${FORENSIC_OUT:-/data/local/tmp/harmony_forensics}"

# 颜色(非交互终端自动失效)
if [ -t 1 ]; then
  C_RED='\033[31m'; C_YEL='\033[33m'; C_GRN='\033[32m'; C_DIM='\033[2m'; C_RST='\033[0m'
else
  C_RED=''; C_YEL=''; C_GRN=''; C_DIM=''; C_RST=''
fi
log()  { printf "%b[+]%b %s\n" "$C_GRN" "$C_RST" "$*"; }
warn() { printf "%b[!]%b %s\n" "$C_YEL" "$C_RST" "$*"; }
err()  { printf "%b[x]%b %s\n" "$C_RED" "$C_RST" "$*" >&2; }
dim()  { printf "%b%s%b\n" "$C_DIM" "$*" "$C_RST"; }

# 权限
is_root=0
[ "$(id -u 2>/dev/null)" = "0" ] && is_root=1

# 沙箱根候选
SANDBOX_ROOTS="/data/app/el2 /data/app/el1 /data/service/el2 /data/service/el1"

usage() {
  cat <<EOF
用法: $PROG {scan|pack|all} [--out DIR]
  scan  探测沙箱并列清单(默认)
  pack  打包可取证文件为 tar.gz
  all   scan + pack
环境变量: FORENSIC_OUT=输出目录(默认 /data/local/tmp/harmony_forensics)
EOF
}

# 按类别列文件: scan_category <base> <subdir> <db|pref|cred|log>
scan_category() {
  base="$1"; sub="$2"; cat="$3"
  dir="$base/$sub"
  [ -d "$dir" ] || { echo "    (无 $sub 目录)"; return; }
  case "$cat" in
    db)   pat="\\( -name '*.db' -o -name '*.rdb' -o -name '*.sqlite' -o -name '*.sqlite3' \\)" ;;
    pref) pat="\\( -name '*.xml' -o -name '*.json' \\)" ;;
    cred) pat="\\( -name '*token*' -o -name '*session*' -o -name '*auth*' -o -name '*account*' -o -name '*.kv' \\)" ;;
    log)  pat="-name '*.log'" ;;
    *)    pat="-type f" ;;
  esac
  cnt=0
  # eval 展开 $pat(内部固定串, 安全)
  eval "find \"$dir\" -maxdepth 3 -type f $pat 2>/dev/null" | while read -r f; do
    sz=$(ls -l "$f" 2>/dev/null | awk '{print $5}')
    printf "    %s | %s\n" "$f" "${sz:-?}"
    cnt=$((cnt+1))
  done
}

do_scan() {
  log "HarmonyOS 沙箱取证扫描 v$VERSION"
  if [ "$is_root" = "1" ]; then
    log "权限: root(可遍历全部应用沙箱)"
  else
    warn "权限: 非 root(通常仅本应用沙箱可见; 跨应用需 root)"
  fi
  dim "沙箱根候选: $SANDBOX_ROOTS"

  found=0
  for root in $SANDBOX_ROOTS; do
    [ -d "$root" ] || continue
    for uid in $(ls "$root" 2>/dev/null); do
      case "$uid" in *[!0-9]*) continue ;; esac   # 仅数字 userId
      for bundle in $(ls "$root/$uid" 2>/dev/null); do
        base="$root/$uid/$bundle"
        [ -d "$base" ] || continue
        found=$((found+1))
        printf "\n%b== [%s] %s ==%b\n" "$C_YEL" "$bundle" "$base" "$C_RST"
        printf "  [数据库 RDB/sqlite]\n";  scan_category "$base" databases db
        printf "  [Preferences]\n";        scan_category "$base" preferences pref
        printf "  [files 疑似凭据/会话]\n"; scan_category "$base" files cred
        printf "  [cache 日志]\n";         scan_category "$base" cache log
      done
    done
  done

  echo ""
  if [ "$found" = "0" ]; then
    warn "未发现沙箱目录。可能原因: 权限不足 / 路径与预期不符 / namespace 隔离。"
    dim "排查: ls -la /data/app/ ; ls -la /data/service/  (查看实际结构)"
  else
    log "共发现 $found 个应用沙箱。"
  fi
  dim "提示: 数据库文件用 pack 回传, 再在主机用 analyze_dump.py 解析。"
}

do_pack() {
  mkdir -p "$OUTDIR" 2>/dev/null || { err "无法创建输出目录 $OUTDIR"; return 1; }
  ts=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo dump)
  out="$OUTDIR/forensic_${ts}.tar.gz"
  listf=$(mktemp 2>/dev/null || echo /data/local/tmp/.flist)
  : > "$listf"
  for root in $SANDBOX_ROOTS; do
    [ -d "$root" ] || continue
    for uid in $(ls "$root" 2>/dev/null); do
      case "$uid" in *[!0-9]*) continue ;; esac
      for bundle in $(ls "$root/$uid" 2>/dev/null); do
        b="$root/$uid/$bundle"; [ -d "$b" ] || continue
        for sub in databases preferences files cache; do
          [ -d "$b/$sub" ] && find "$b/$sub" -maxdepth 2 -type f 2>/dev/null >> "$listf"
        done
      done
    done
  done
  if [ -s "$listf" ]; then
    if tar -czf "$out" -T "$listf" 2>/dev/null; then
      n=$(wc -l < "$listf" | tr -d ' ')
      sz=$(ls -l "$out" | awk '{print $5}')
      log "打包完成: $n 个文件, $sz 字节 -> $out"
      dim "回传主机: hdc file recv $out ./  (或你的传输方式)"
    else
      err "tar 失败(设备可能不支持 -T)。改用: tar -czf $out -C / <目录>  手动打包"
    fi
  else
    warn "无可打包文件(检查 scan 输出与权限)"
  fi
  rm -f "$listf"
}

# 解析参数
CMD="scan"
while [ $# -gt 0 ]; do
  case "$1" in
    scan|pack|all) CMD="$1" ;;
    --out) OUTDIR="$2"; shift ;;
    -h|--help|help) usage; exit 0 ;;
    *) warn "忽略未知参数: $1" ;;
  esac
  shift
done

case "$CMD" in
  scan) do_scan ;;
  pack) do_pack ;;
  all)  do_scan; echo ""; do_pack ;;
esac
