#!/bin/sh
# harmony_pc_test.sh  [sandbox_escape 设备侧一键测试脚本]
# 定位：HarmonyOS PC 本地 hishell 直接运行（纯 POSIX sh，无 python/bash 依赖）
# 授权：仅用于已授权设备的安全测试与攻击面研究
#
# 用法：
#   sh harmony_pc_test.sh              # 基础流程（环境/dump/SA枚举/日志探测/打包）
#   sh harmony_pc_test.sh --canary     # 追加 symlink 投饵探测（默认 30s）
#   sh harmony_pc_test.sh --canary --monitor 60
#
# 产物：结果目录（或 sec_test_results.tar.gz），拷回主机喂给
#   T1 transition_mapper / T2 sandbox_config_analyzer / T3 sa_enumerator

VERSION="1.0"
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
MONITOR_SECONDS=30
RUN_CANARY=0

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }

# ---------- 参数解析 ----------
for arg in "$@"; do
    case "$arg" in
        --canary)  RUN_CANARY=1 ;;
        --monitor) : ;;   # 值由下一循环取，见下
        *)         MONITOR_SECONDS=$(echo "$arg" | grep -q '^[0-9]*$' && echo "$arg" || echo "$MONITOR_SECONDS") ;;
    esac
done

# ---------- 工作目录 ----------
WORKDIR=""
for d in /data/local/tmp/sec_test "$HOME/sec_test" "$SCRIPT_DIR/sec_test"; do
    if mkdir -p "$d" 2>/dev/null && [ -w "$d" ]; then
        WORKDIR="$d"; break
    fi
done
if [ -z "$WORKDIR" ]; then
    warn "找不到可写工作目录（/data/local/tmp、\$HOME、脚本目录均失败）"
    exit 1
fi
RESULTS="$WORKDIR/results"
mkdir -p "$RESULTS"
cd "$WORKDIR" || exit 1
ok "工作目录: $WORKDIR"

# ========== 1. 环境探测 ==========
log "Step1 环境探测 → results/env.txt"
{
    echo "=== harmony_pc_test.sh v$VERSION ==="
    echo "=== date ===";  date 2>/dev/null
    echo "=== uname ==="; uname -a 2>/dev/null
    echo "=== id ===";    id 2>/dev/null
    echo "=== selinux context (self) ==="; cat /proc/self/attr/current 2>/dev/null
    echo "=== python3 ===";  command -v python3 2>/dev/null || echo "无"
    echo "=== hidumper ==="; command -v hidumper 2>/dev/null || echo "无"
    echo "=== hilog ===";    command -v hilog 2>/dev/null || echo "无"
    echo "=== dmesg ===";    command -v dmesg 2>/dev/null || echo "无"
    echo "=== sesearch ==="; command -v sesearch 2>/dev/null || echo "无"
    echo "=== toybox/busybox ==="; command -v toybox 2>/dev/null; command -v busybox 2>/dev/null
} > "$RESULTS/env.txt" 2>&1
cat "$RESULTS/env.txt"

# ========== 2. SELinux 策略 dump（T1 输入） ==========
log "Step2 策略 dump → policy.bin"
POLICY_SRC=""
for p in /sys/fs/selinux/policy \
         /system/etc/selinux/precompiled_sepolicy \
         /vendor/etc/selinux/precompiled_sepolicy; do
    rm -f "$WORKDIR/policy.bin"
    if cat "$p" > "$WORKDIR/policy.bin" 2>/dev/null && [ -s "$WORKDIR/policy.bin" ]; then
        POLICY_SRC="$p"; break
    fi
done
[ -z "$POLICY_SRC" ] && rm -f "$WORKDIR/policy.bin"
if [ -n "$POLICY_SRC" ]; then
    ok "policy.bin 导出成功（源: $POLICY_SRC, $(wc -c < "$WORKDIR/policy.bin") 字节）"
else
    warn "policy.bin 导出失败（无权限或路径不存在）——T1 需要，见文末说明"
fi

# file_contexts（路径标签映射，T1 附属输入）
for p in /system/etc/selinux/file_contexts /vendor/etc/selinux/file_contexts; do
    [ -f "$p" ] && cat "$p" > "$RESULTS/file_contexts.txt" 2>/dev/null
done
[ -s "$RESULTS/file_contexts.txt" ] && ok "file_contexts 已导出" || warn "file_contexts 未导出（非阻塞）"

# ========== 3. 沙箱配置 dump（T2 输入）+ 沙箱侦察 ==========
log "Step3 沙箱配置 dump → appdata-sandbox.json"
SANDBOX_SRC=""
for p in /etc/sandbox/appdata-sandbox.json \
         /system/etc/sandbox/appdata-sandbox.json; do
    if cat "$p" > "$RESULTS/appdata-sandbox.json" 2>/dev/null && [ -s "$RESULTS/appdata-sandbox.json" ]; then
        SANDBOX_SRC="$p"; break
    fi
done
if [ -n "$SANDBOX_SRC" ]; then
    ok "appdata-sandbox.json 导出成功（源: $SANDBOX_SRC）"
else
    warn "appdata-sandbox.json 导出失败——T2 需要"
fi

{
    echo "=== /etc/sandbox 目录 ===";  ls -l /etc/sandbox 2>/dev/null
    echo "=== /system/etc/sandbox 目录 ==="; ls -l /system/etc/sandbox 2>/dev/null
    echo "=== 沙箱相关挂载 ==="
    grep -E 'storage|sandbox|el[0-9]' /proc/mounts 2>/dev/null | head -n 80
    echo "=== /data/storage（shell 视角） ==="; ls -l /data/storage 2>/dev/null || echo "不可见（正常：应用专属挂载视图）"
    echo "=== /data/app/el2 ==="; ls /data/app/el2 2>/dev/null || echo "不可见"
} > "$RESULTS/sandbox_recon.txt" 2>&1
ok "沙箱侦察数据 → results/sandbox_recon.txt"

# ========== 4. SA 枚举（T3 输入） ==========
log "Step4 SA 枚举 → results/sa_list.raw"
if command -v hidumper >/dev/null 2>&1; then
    if hidumper -ls > "$RESULTS/sa_list.raw" 2>&1; then
        SA_COUNT=$(grep -cE '^[[:space:]]*[0-9]+' "$RESULTS/sa_list.raw" 2>/dev/null)
        ok "hidumper -ls 完成，原始输出 $(wc -l < "$RESULTS/sa_list.raw") 行（粗匹配 SA 行 ${SA_COUNT:-0} 条）"
        head -n 5 "$RESULTS/sa_list.raw"
    else
        warn "hidumper -ls 执行失败（权限不足?）——查看 results/sa_list.raw 内的错误信息"
    fi
else
    warn "无 hidumper 命令，跳过"
fi

# ========== 5. AVC 日志通道探测（T5 前置） ==========
log "Step5 AVC 日志通道探测 → results/avc_probe.txt"
{
    echo "=== hilog 通道 ==="
    hilog -x 2>/dev/null | grep -i avc | head -n 20
    echo "=== dmesg 通道 ==="
    dmesg 2>/dev/null | grep -i avc | head -n 20
} > "$RESULTS/avc_probe.txt" 2>&1
AVC_LINES=$(grep -c 'avc' "$RESULTS/avc_probe.txt" 2>/dev/null)
if [ "$AVC_LINES" -gt 0 ]; then
    ok "AVC 日志通道可用（${AVC_LINES} 条样本）——T5 可在该设备运行"
else
    warn "未取到 AVC 日志（通道受限或无 deny 记录）——T5 信号采集可能受限"
fi

# ========== 6. symlink 投饵探测（可选，T5 shell 版） ==========
if [ "$RUN_CANARY" = "1" ]; then
    log "Step6 symlink 投饵探测（${MONITOR_SECONDS}s）"
    CANARY_DIR=""
    for d in /data/storage/el2/base/files/.canary "$WORKDIR/canary"; do
        if mkdir -p "$d" 2>/dev/null && [ -w "$d" ]; then CANARY_DIR="$d"; break; fi
    done
    if [ -z "$CANARY_DIR" ]; then
        warn "无可用投饵目录，跳过（shell 进程无应用沙箱视图属正常现象）"
    else
        TARGET="/data/system/.nonexistent_canary_target"
        LINK="$CANARY_DIR/canary_probe"
        rm -f "$LINK" 2>/dev/null
        ln -s "$TARGET" "$LINK" 2>/dev/null
        if [ -L "$LINK" ]; then
            ok "投饵: $LINK -> $TARGET"
            log "监测 ${MONITOR_SECONDS}s（hilog + dmesg 双通道）..."
            DEADLINE=$(( $(date +%s) + MONITOR_SECONDS ))
            : > "$RESULTS/canary_hits.txt"
            while [ "$(date +%s)" -lt "$DEADLINE" ]; do
                (hilog -x 2>/dev/null; dmesg 2>/dev/null) | grep "$TARGET" >> "$RESULTS/canary_hits.txt"
                sleep 5
            done
            sort -u "$RESULTS/canary_hits.txt" -o "$RESULTS/canary_hits.txt" 2>/dev/null
            HITS=$(grep -c . "$RESULTS/canary_hits.txt" 2>/dev/null)
            if [ "$HITS" -gt 0 ]; then
                warn "命中 $HITS 条——存在服务跟随沙箱外 symlink（候选缺陷）:"
                head -n 10 "$RESULTS/canary_hits.txt"
            else
                ok "监测期内无服务跟随"
            fi
            rm -rf "$CANARY_DIR"
            ok "投饵已回收"
        else
            warn "投饵创建失败（目录不可写），跳过"
        fi
    fi
fi

# ========== 7. 打包 ==========
log "Step7 打包结果"
MANIFEST="$RESULTS/MANIFEST.txt"
{
    echo "harmony_pc_test.sh v$VERSION 产物清单（$(date)）"
    echo "policy.bin           T1 输入: SELinux 策略（源: ${POLICY_SRC:-未导出}）"
    echo "appdata-sandbox.json T2 输入: 沙箱映射配置（源: ${SANDBOX_SRC:-未导出}）"
    echo "sa_list.raw          T3 输入: hidumper -ls 原始输出"
    echo "avc_probe.txt        T5 前置: AVC 日志通道样本"
    echo "env.txt / sandbox_recon.txt / file_contexts.txt: 环境与侦察数据"
    [ -f "$RESULTS/canary_hits.txt" ] && echo "canary_hits.txt      T5 结果: 投饵命中记录"
} > "$MANIFEST"
# policy.bin 放工作目录（体积大），其余在 results/
if tar czf "$WORKDIR/sec_test_results.tar.gz" -C "$WORKDIR" results policy.bin 2>/dev/null; then
    ok "打包完成: $WORKDIR/sec_test_results.tar.gz ($(wc -c < "$WORKDIR/sec_test_results.tar.gz") 字节)"
    ok "拷回主机: T1/T2/T3 直接以此数据离线分析"
else
    warn "tar 不可用，直接拷整个目录: $WORKDIR/"
fi

echo "---------------------------------------------------------------"
echo " 测试流程结束。结果位置: $WORKDIR"
echo " 主机侧后续（Mac 上执行）:"
echo "   T1: 先用 setools4 从 policy.bin 导出 rules.txt → transition_mapper.py --rules-file"
echo "   T2: sandbox_config_analyzer.py appdata-sandbox.json --bundle <包名>"
echo "   T3: sa_enumerator.py 的解析适配可直接读 sa_list.raw"
echo "---------------------------------------------------------------"
exit 0
