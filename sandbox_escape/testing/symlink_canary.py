#!/usr/bin/env python3
# symlink_canary.py  [T5 / 路径 A1-c]
# 功能：在授权设备应用沙箱内投饵符号链接，探测哪些高权限系统服务会跟随它
#       越出沙箱访问（symlink 代理缺陷发现）
# 定位：sandbox_escape / testing / A1-c 服务缺陷审计（设备侧主动测试）
# 授权：仅用于已授权设备；投饵文件须可识别、会话结束自动回收
#
# 修正项（对应技术文档 v1.1 勘误编号）：
#   E3  日志通道修正——AVC deny 记录不在 /sys/fs/selinux/avc（那是统计节点），
#       也不在 /dev/__properties__；正确通道是内核日志（dmesg / hilog）里的 avc 行，
#       本工具将其做成可配置数据源
#
# 双运行形态：工具直接拷在设备上本地跑（推荐），或主机经 hdc 跑
#
# 用法（在设备上，应用沙箱上下文或可写沙箱目录的环境中）：
#   python3 symlink_canary.py --label sys_probe --monitor 30
#   python3 symlink_canary.py --target /data/system/.canary_probe --log-source hilog
#   python3 symlink_canary.py --cleanup   # 手动回收残留投饵

import argparse
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "common"))
from hdc_client import Executor, ExecutorError  # noqa: E402

# 投饵目录：应用沙箱内 files 子目录（应用自身可写，服务可读）
CANARY_DIR = "/data/storage/el2/base/files/.canary"
# 默认投饵目标：沙箱外、不存在的系统路径——服务跟随 symlink 尝试访问时
# 会在内核/AVC 日志留下针对该路径的记录（E3 的检测信号）
DEFAULT_TARGET = "/data/system/.nonexistent_canary_target"

# AVC deny 行（E3：来自 dmesg/hilog 内核日志，形如：
#   avc: denied { read } for comm="xxx" ... path="/data/system/.nonexistent_..."
AVC_LINE_RE = re.compile(
    r"avc:\s*denied\s*\{[^}]*\}\s*for\s+comm=\"(?P<comm>[^\"]+)\""
    r".*?(?:path=|name=)\"?(?P<path>[^\"]\S*)", re.S
)

LOG_SOURCES = {
    # 数据源名 → 取日志命令（经 Executor，hdc/本地两模式通用）
    "hilog": "hilog -x 2>/dev/null | grep -i avc",
    "dmesg": "dmesg 2>/dev/null | grep -i avc",
    "kmsg":  "cat /proc/kmsg 2>/dev/null | grep -i avc",  # 通常需 root
}


def plant_canary(ex: Executor, label: str, canary_dir: str,
                 target: str) -> dict:
    """投饵：在沙箱内创建指向沙箱外的 symlink（幂等，覆盖旧投饵）"""
    link_path = os.path.join(canary_dir, f"canary_{label}")
    ex.shell(f"mkdir -p '{canary_dir}'")
    ex.shell_ok(f"rm -f '{link_path}'")  # lexists 等价：rm -f 幂等
    ex.shell(f"ln -s '{target}' '{link_path}'")
    ok, out = ex.shell_ok(f"ls -l '{link_path}'")
    return {"label": label, "link": link_path, "target": target,
            "planted_at": int(time.time()), "verify": out.strip() if ok else ""}


def collect_hits(ex: Executor, target: str, log_source: str,
                 monitor_seconds: int) -> list:
    """
    监测期：轮询日志通道，收集针对 target 的访问记录。
    返回命中列表 [{comm, path, raw, at}]
    """
    if log_source not in LOG_SOURCES:
        raise ValueError(f"未知日志通道 {log_source}，可选: {list(LOG_SOURCES)}")
    cmd = LOG_SOURCES[log_source]
    hits, seen_raw = [], set()
    deadline = time.time() + monitor_seconds
    while time.time() < deadline:
        ok, out = ex.shell_ok(cmd, timeout=max(10, monitor_seconds))
        if ok:
            for line in out.splitlines():
                if target not in line:
                    continue
                if line in seen_raw:
                    continue
                seen_raw.add(line)
                m = AVC_LINE_RE.search(line)
                hits.append({
                    "comm": m.group("comm") if m else "?",
                    "path": m.group("path") if m else "?",
                    "raw": line.strip(),
                    "at": int(time.time()),
                })
        time.sleep(min(5, max(1, deadline - time.time())))
    return hits


def cleanup(ex: Executor, canary_dir: str) -> int:
    """回收投饵目录（会话收尾 / --cleanup）"""
    ok, _ = ex.shell_ok(f"rm -rf '{canary_dir}'")
    return 0 if ok else 1


def run_session(ex: Executor, label: str, target: str, canary_dir: str,
                log_source: str, monitor_seconds: int, report_path: str) -> dict:
    """一次完整投饵会话：投饵 → 监测 → 回收 → 落盘"""
    canary = plant_canary(ex, label, canary_dir, target)
    print(f"[+] 投饵完成: {canary['link']} -> {target}")
    if canary["verify"]:
        print(f"    {canary['verify']}")

    print(f"[*] 监测 {monitor_seconds}s（日志通道: {log_source}）...")
    try:
        hits = collect_hits(ex, target, log_source, monitor_seconds)
    finally:
        cleanup(ex, canary_dir)
        print(f"[+] 投饵已回收: {canary_dir}")

    result = dict(canary)
    result.update({"log_source": log_source, "monitor_seconds": monitor_seconds,
                   "followed": bool(hits), "hits": hits})
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    if hits:
        print(f"[!] 命中 {len(hits)} 条——以下服务跟随了沙箱外 symlink（候选缺陷）:")
        for h in hits:
            print(f"    comm={h['comm']}  {h['raw'][:160]}")
    else:
        print("[-] 监测期内无服务跟随（未观测到缺陷信号）")
    print(f"[+] 会话报告已写入 {report_path}")
    return result


def main():
    ap = argparse.ArgumentParser(description="A1-c symlink 代理缺陷探测器")
    ap.add_argument("--label", default="probe", help="投饵标签（进文件名）")
    ap.add_argument("--target", default=DEFAULT_TARGET,
                    help="投饵指向的沙箱外目标路径")
    ap.add_argument("--canary-dir", default=CANARY_DIR, help="沙箱内投饵目录")
    ap.add_argument("--monitor", type=int, default=60, help="监测时长（秒）")
    ap.add_argument("--log-source", default="hilog", choices=list(LOG_SOURCES),
                    help="AVC 日志通道（E3，默认 hilog）")
    ap.add_argument("--report", default="canary_report.json", help="报告输出路径")
    ap.add_argument("--cleanup", action="store_true",
                    help="仅回收残留投饵目录后退出")
    args = ap.parse_args()

    ex = Executor()
    print(f"[*] 执行模式: {ex.mode}")
    if args.cleanup:
        rc = cleanup(ex, args.canary_dir)
        print(f"[+] 清理{'完成' if rc == 0 else '失败'}: {args.canary_dir}")
        return rc
    try:
        run_session(ex, args.label, args.target, args.canary_dir,
                    args.log_source, args.monitor, args.report)
    except ExecutorError as e:
        print(f"[!] 执行失败: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
