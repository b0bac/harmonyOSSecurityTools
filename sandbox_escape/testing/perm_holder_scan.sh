#!/system/bin/sh
# perm_holder_scan.sh  [T10 / 设备侧权限持有者排查]
# 用途：确定「权限制挂载闸」的现役钥匙持有者——谁持有权限，谁的沙箱里就有对应挂载。
#       固化第 8 轮排查流程（全进程 mountinfo 扫描 + 预装 hap 权限申请扫描）。
# 判定逻辑（三闸模型的挂载闸侧）：
#   权限 → appdata-sandbox.json permission 段 → 挂载点进沙箱
#   挂载关键词: faultlog/bbox/UserView/xpower/hilog（DFX 类权限制路径）
#   持有者=0 ⇒ 该路径在本机构建上对所有应用关闭（SELinux 链再通也无现实靶）
# 输出：PHS_BEGIN/END 之间的文本即报告。
# 授权：仅用于已授权设备；全程只读。

log() { echo "[PHS] $*"; }

echo PHS_BEGIN
log "身份: $(id 2>&1)"

# ---------- 1. 全进程 mountinfo 扫描（在跑进程=现役持有者）----------
echo "===== 1 全进程挂载扫描 ====="
hits=0
for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    m=$(grep -l -E 'faultlog|/bbox|UserView|xpower|/hilog' "/proc/$p/mountinfo" 2>/dev/null)
    if [ -n "$m" ]; then
        hits=$((hits + 1))
        log "命中 PID=$p $(grep -E 'faultlog|/bbox|UserView|xpower|/hilog' "/proc/$p/mountinfo" | head -2)"
    fi
done
log "在跑进程挂载命中: ${hits}"

# ---------- 2. 预装 hap 权限申请扫描 ----------
echo "===== 2 预装 hap requestPermissions ====="
for h in /system/app/*/*.hap; do
    [ -f "$h" ] || continue
    perms=$(unzip -p "$h" module.json 2>/dev/null | grep -oE '"ohos\.permission\.[A-Z_]+"' | sort -u)
    log "$h:"
    if [ -n "$perms" ]; then
        echo "$perms" | sed 's/^/    /'
    else
        log "    (无申请或不可读)"
    fi
done

# ---------- 3. DFX 关键权限定向复核 ----------
echo "===== 3 关键权限定向 ====="
for kw in ACCESS_HIVIEWX READ_DFX_XPOWER ACCESS_BBOX_DIR ACCESS_ANALYTICS; do
    found=$(unzip -p /system/app/*/*.hap module.json 2>/dev/null | grep -c "$kw" 2>/dev/null)
    log "$kw : 预装命中 ${found:-?}"
done

# ---------- 4. 可观测边界探测（阴性对照，确认本域能看到什么）----------
echo "===== 4 本域可观测边界 ====="
for t in /system/profile /data/service/el1 /data/bundles; do
    if ls "$t" >/dev/null 2>&1; then log "可读: $t"; else log "不可读/不存在: $t"; fi
done

echo "判定法：第1节命中>0 ⇒ 找到现役持有者（其 PID 即 T7/T8 的执行上下文线索）；"
echo "        命中=0 且第2节无申请 ⇒ 挂载闸无钥匙，DFX 路径在本机构建对全部应用关闭。"
echo "残余不确定性：未在跑的用户安装应用（DFX 权限典型持有者必为系统预装，风险低）。"
echo PHS_END
