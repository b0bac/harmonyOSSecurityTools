#!/usr/bin/env python3
# sa_enumerator.py  [T3 / 路径 C1 前置]
# 功能：枚举目标设备的 System Ability 清单，摸清 SA 攻击面（供 T4/T5 消费）
# 定位：sandbox_escape / analysis / C1 接口面映射
# 授权：仅用于已授权设备（hidumper 通常需开发者/调试权限，符合授权前提）
#
# 修正项（对应技术文档 v1.1 勘误编号）：
#   E2  SA 枚举主通道为 `hidumper -ls`（列出已注册 SA），`samgr -l` 非标准入口；
#       `/system/profile`、`/vendor/profile` 下的 *_profile.json 扫描作为离线补充
#
# 双运行形态（经 common/hdc_client.py 统一封装）：
#   - 主机 + hdc 连设备：hdc shell hidumper -ls
#   - 工具直接拷在设备上：本地直接执行 hidumper -ls
#
# 用法：
#   python3 sa_enumerator.py -o sa_list            # 生成 sa_list.json / sa_list.raw
#   python3 sa_enumerator.py --dump-all            # 逐个 hidumper -s <id>（慢，深度摸底）
#   HARMONY_EXEC=local python3 sa_enumerator.py    # 强制设备本地模式

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "common"))
from hdc_client import Executor, ExecutorError  # noqa: E402

SA_PROFILE_DIRS = (
    "/system/profile",
    "/vendor/profile",
    "/chip_prod/profile",
)

# hidumper -ls 输出中的 SA 行，兼容几种常见格式（E2：按 hidumper 实际输出解析，
# 而非原文的 samgr SA[..] 正则）：
#   2401 : ai_service
#   2401 - ai_service
#   SystemAbility[2401] name=ai_service
SA_LINE_RE = re.compile(
    r"^\s*(?:SystemAbility\s*\[?)?\b(\d{2,5})\b\]?"
    r"\s*[:|\-]?\s*(?:name\s*=\s*)?([A-Za-z_][\w.]*)\s*$"
)


def dump_sa_list(ex: Executor) -> tuple:
    """主通道：hidumper -ls 枚举已注册 SA。返回 (sa_list, raw_output)"""
    out = ex.shell("hidumper -ls", timeout=60)
    sa_list = []
    for line in out.splitlines():
        m = SA_LINE_RE.match(line)
        if m:
            sa_list.append({"id": m.group(1), "name": m.group(2)})
    return sa_list, out


def dump_sa_detail(ex: Executor, sa_id: str) -> str:
    """深挖单个 SA：hidumper -s <saId>（含接口/能力信息，依 SA 实现而定）"""
    return ex.shell(f"hidumper -s {sa_id}", timeout=60)


def scan_sa_profiles(ex: Executor) -> list:
    """补充通道：扫描 profile 目录获取 SA 及其配置文件清单"""
    profiles = []
    for d in SA_PROFILE_DIRS:
        if not ex.path_exists(d):
            continue
        for entry in ex.list_dir(d):
            entry = entry.strip()
            if entry.endswith((".json", ".xml")) and "profile" in entry:
                profiles.append({"profile": f"{d}/{entry}"})
    return profiles


def merge(sa_list: list, profiles: list) -> list:
    """合并两通道结果：hidumper 实时注册表为主，profile 目录补缺"""
    by_id = {sa["id"]: dict(sa) for sa in sa_list}
    return list(by_id.values()) + [p for p in profiles]


def main():
    ap = argparse.ArgumentParser(description="C1 SA 攻击面枚举器")
    ap.add_argument("-o", "--output", default="sa_list",
                    help="输出前缀（默认 sa_list → sa_list.json / sa_list.raw）")
    ap.add_argument("--dump-all", action="store_true",
                    help="逐个 hidumper -s <id> 深挖（慢）")
    args = ap.parse_args()

    ex = Executor()
    print(f"[*] 执行模式: {ex.mode}")

    try:
        sa_list, raw = dump_sa_list(ex)
    except ExecutorError as e:
        print(f"[!] hidumper 枚举失败: {e}")
        print("[!] 回退到 profile 目录扫描")
        sa_list, raw = [], ""

    profiles = scan_sa_profiles(ex)
    result = merge(sa_list, profiles)
    print(f"[+] 枚举完成：hidumper 通道 {len(sa_list)} 个 SA，"
          f"profile 通道 {len(profiles)} 个配置，合并 {len(result)} 条")

    with open(args.output + ".json", "w", encoding="utf-8") as f:
        json.dump({"mode": ex.mode, "sa_list": result}, f,
                  indent=2, ensure_ascii=False)
    with open(args.output + ".raw", "w", encoding="utf-8") as f:
        f.write(raw)
    print(f"[+] 清单已写入 {args.output}.json / {args.output}.raw")

    if args.dump-all and sa_list:
        os.makedirs(args.output + "_details", exist_ok=True)
        for sa in sa_list:
            try:
                detail = dump_sa_detail(ex, sa["id"])
                path = os.path.join(args.output + "_details", f"{sa['id']}.txt")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(detail)
                print(f"    [+] {sa['id']} {sa.get('name', '')} -> {path}")
            except ExecutorError as e:
                print(f"    [!] {sa['id']} dump 失败: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
