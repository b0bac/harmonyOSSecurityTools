#!/system/bin/sh
# data_probe.sh  [T7 / 目标 1 实测探针]
# 用途：在「应用上下文」（normal_hap 域）内一键实测沙箱外文件读写可达性。
#       运行位置：应用沙箱内（测试应用的控制台/eval/任意 shell 入口）。
#       依赖：toybox（系统自带），无 python 依赖。
# 判定矩阵（依据 results_pc_20260815 第 4 轮 policy 层结论）：
#   [期望放行] /data/log/faultlog/faultlogger、/data/log/bbox、/data/log/UserView、
#              /data/log/xpower、/data/service/el1/public/for-all-app
#              —— policy 层三闸过二（挂载✓ SELinux✓），本探针验证最后一闸 DAC
#   [期望拦截] 跨应用数据目录、/data/bms_app_install、/data/ecust —— 阴性对照，
#              结果若放行 = 新发现（比 policy 推断更严重）
#   [独立项]   /proc 可见性（整目录映射进沙箱的 T2 HIGH 项）：
#              其他进程 status/maps 可读性 = 跨进程信息泄露的另一形态
# 输出：PROBE_BEGIN/END 之间的文本即完整报告，可直接回传。
# 授权：仅用于已授权设备的安全测试。

TAG="probe_$$"

log() { echo "[PROBE] $*"; }

section() { echo; echo "===== $* ====="; }

# 尝试类操作统一入口：名字 + 命令；打印结果码
try() {
    name="$1"; shift
    out=$("$@" 2>&1); rc=$?
    # 只回显前 160 字节，防报告爆炸
    out=$(printf '%s' "$out" | head -c 160 | tr '\n' '|')
    log "$name -> rc=$rc ${out:+[$out]}"
}

cleanup() {
    for d in "$@"; do
        for f in "$d/$TAG"* "$d/${TAG}"*; do
            [ -f "$f" ] && rm -f "$f" 2>/dev/null
        done
    done
}

echo PROBE_BEGIN
log "id: $(id 2>&1)"
log "cwd: $(pwd 2>&1)"
log "self-label: $(ls -Zd /proc/self 2>&1 | head -1)"
log "enforce: $(getenforce 2>&1)"

# ---------- 1. 期望放行：/data/log 系（policy 层全绿） ----------
section "1 /data/log 系（期望：可读写）"
for d in /data/log/faultlog/faultlogger /data/log/bbox \
         /data/log/UserView /data/log/xpower /data/log; do
    try "list   $d" ls -l "$d"
    first=$(ls "$d" 2>/dev/null | grep -v "^$TAG" | head -1)
    if [ -n "$first" ]; then
        try "read   $d/$first" head -c 64 "$d/$first"
    else
        log "read   $d -> (no readable entry)"
    fi
    try "create $d/$TAG" sh -c "echo x > '$d/$TAG'"
    if [ -f "$d/$TAG" ]; then
        try "write2 $d/$TAG" sh -c "echo y >> '$d/$TAG'"
        try "unlink $d/$TAG" rm -f "$d/$TAG"
    else
        log "write2/unlink $d/$TAG -> skip(create失败)"
    fi
done

# ---------- 2. 期望放行：el1 for-all-app（宽树标签） ----------
section "2 /data/service/el1/public/for-all-app（期望：可写建）"
FA=/data/service/el1/public/for-all-app
try "list   $FA" ls "$FA"
try "create $FA/$TAG" sh -c "echo x > '$FA/$TAG'"
if [ -f "$FA/$TAG" ]; then
    try "write2 $FA/$TAG" sh -c "echo y >> '$FA/$TAG'"
    try "unlink $FA/$TAG" rm -f "$FA/$TAG"
else
    log "write2/unlink $FA/$TAG -> skip(create失败)"
fi
try "list   /data/storage/el1/bundle/storage_daemon" ls /data/storage/el1/bundle/storage_daemon

# ---------- 3. 阴性对照：policy 层判定拦截的路径 ----------
section "3 阴性对照（期望：拒绝；放行=新发现）"
for d in /data/bms_app_install /data/ecust/system /data/update/sd_package \
         /data/service/el1/public/edm/config /data/system; do
    try "list   $d" ls "$d"
    try "create $d/$TAG" sh -c "echo x > '$d/$TAG'"
    [ -f "$d/$TAG" ] && rm -f "$d/$TAG" 2>/dev/null
done

# ---------- 4. 跨应用数据目录（严格形态目标 1） ----------
section "4 跨应用数据（期望：拒绝）"
try "list /data/app" ls /data/app 2>&1
try "list /data/app/el1" ls /data/app/el1 2>&1
try "list /data/app/el2" ls /data/app/el2 2>&1
# 若能列出其他 bundle 目录，逐一探测读
for b in $(ls /data/app/el2 2>/dev/null | head -3); do
    try "list bundle $b" ls "/data/app/el2/$b" 2>&1
    try "read bundle $b" ls -l "/data/app/el2/$b" 2>&1
done

# ---------- 5. /proc 其他进程可见性（T2 HIGH 项） ----------
section "5 /proc 跨进程（信息泄露形态）"
try "list /proc" sh -c 'ls /proc | grep -E "^[0-9]+$" | head -8'
for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | head -4); do
    [ "$p" = "$$" ] && continue
    try "read /proc/$p/cmdline" head -c 64 "/proc/$p/cmdline"
    try "read /proc/$p/status"  head -c 64 "/proc/$p/status"
    try "read /proc/$p/maps"    head -c 64 "/proc/$p/maps"
done
try "read /proc/net/tcp" head -c 64 /proc/net/tcp

# ---------- 6. 汇总 ----------
section "6 汇总"
echo "判定法：rc=0 且有内容 = 可达；rc 非 0 看 errno（EACCES=拦截确认）"
cleanup /data/log /data/log/faultlog/faultlogger /data/log/bbox \
         /data/log/UserView /data/log/xpower "$FA" 2>/dev/null
echo PROBE_END
