#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sandbox_forensics.py — HarmonyOS PC 应用沙箱取证(设备端 / Python 主力)

设备具备 Python3 时优先用本脚本(比 .sh 更强: 能就地解析 sqlite 内容,
无需回传主机即可看到库内表/列/疑似敏感数据)。

  scan  探测沙箱 + 就地解析数据库 + 列 Preferences/疑似凭据/日志清单(默认)
  pack  打包可取证文件为 tar.gz 供回传深度分析

纯标准库; 数据库只读打开(mode=ro), 不修改原始文件。自适应 root/非root。
路径依据 OpenHarmony 标准沙箱 /data/app/el2/<userId>/<bundleName>/。

用法:
    python3 sandbox_forensics.py scan
    python3 sandbox_forensics.py scan --root /data/app/el2   # 指定沙箱根(校准/测试)
    python3 sandbox_forensics.py scan --json                 # 机器可读
    python3 sandbox_forensics.py pack --out /data/local/tmp

仅用于授权安全测试 / 取证。
"""
import os
import sys
import json
import sqlite3
import tarfile
import time
import argparse

VERSION = "0.1"
DEFAULT_ROOTS = ["/data/storage/el2/auth_groups",   # PC 版: 认证组(扁平 com.xxx bundle)
                 "/data/storage/el1/bundle",        # PC 版: 应用包
                 "/data/app/el2", "/data/app/el1",  # 标准版兜底
                 "/data/service/el2", "/data/service/el1"]
SUBDIRS = ["databases", "preferences", "files", "cache"]
SENS = ("token", "session", "auth", "account", "password",
        "secret", "key", "cookie", "credential")
LOG_EXT = (".log",)


def is_sqlite(p):
    try:
        with open(p, "rb") as f:
            return f.read(16)[:15] == b"SQLite format 3"
    except Exception:
        return False


def _size(p):
    try:
        return os.path.getsize(p)
    except Exception:
        return -1


def _preview(p, n=120):
    try:
        return open(p, "rb").read(n).decode("utf-8", "replace")
    except Exception:
        return "(读取失败)"


def walk_files(path, maxdepth=2):
    """yield 目录下文件, 限制深度(避免遍历过大)"""
    if not os.path.isdir(path):
        return
    for dp, dn, fn in os.walk(path):
        rel = dp[len(path):].lstrip(os.sep)
        depth = 0 if rel == "" else rel.count(os.sep) + 1
        if depth > maxdepth:
            dn[:] = []      # 剪枝: 不再深入
            continue
        for f in fn:
            yield os.path.join(dp, f)


def dump_db(path):
    """只读解析单个 sqlite 库 -> (文本行列表, 结构化表信息)"""
    lines, tables = [], []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except Exception as e:
        return [f"      [打不开] {e}"], []
    cur = con.cursor()
    try:
        tabs = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    except Exception as e:
        con.close()
        return [f"      [查询失败] {e}"], []
    lines.append(f"      表({len(tabs)}): {', '.join(tabs) if tabs else '(空)'}")
    for t in tabs:
        # t 来自 sqlite_master(库内表名), 非外部输入; 取证/只读场景风险可控
        try:
            cnt = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            cols = [d[1] for d in cur.execute(f'PRAGMA table_info("{t}")').fetchall()]
            lines.append(f"        - {t}({cnt}行) 列: {', '.join(cols)}")
            tbl = {"name": t, "count": cnt, "columns": cols,
                   "sensitive": [], "samples": []}
            sens = [c for c in cols if any(k in c.lower() for k in SENS)]
            if sens:
                lines.append(f"          ⚠ 疑似敏感列: {', '.join(sens)}")
                tbl["sensitive"] = sens
                for row in cur.execute(f'SELECT * FROM "{t}" LIMIT 3'):
                    sample = dict(zip(cols, row))
                    tbl["samples"].append(sample)
                    lines.append(f"          样本: {sample}")
            tables.append(tbl)
        except Exception as e:
            lines.append(f"        - {t}: 读取失败 {e}")
    con.close()
    return lines, tables


def classify_and_collect(path, sub, binfo):
    """对单个文件分类并写入沙箱信息结构, 返回要打印的行"""
    name = os.path.basename(path).lower()
    if is_sqlite(path):
        lines, tables = dump_db(path)
        binfo["databases"].append({"file": path, "size": _size(path),
                                   "tables": tables})
        return [f"    [DB] {path} ({_size(path)}B)"] + lines
    if any(k in name for k in SENS):
        binfo["creds"].append({"file": path, "size": _size(path),
                               "preview": _preview(path)})
        return [f"    [疑似凭据] {path} ({_size(path)}B) 预览: {_preview(path)}"]
    if sub == "preferences":
        binfo["prefs"].append({"file": path, "size": _size(path)})
        return [f"    [Preferences] {path} ({_size(path)}B)"]
    if name.endswith(LOG_EXT):
        binfo["logs"].append({"file": path, "size": _size(path)})
        return [f"    [日志] {path} ({_size(path)}B)"]
    return []


def iter_sandboxes(roots):
    """yield (bundle, base) 对所有可达沙箱(去重)。
    兼容两种布局:
      标准: <root>/<userId(数字)>/<bundle>/   (如 /data/app/el2/100/com.x)
      PC 版: <root>/<bundle>/                 (如 /data/storage/el2/auth_groups/com.x)
    """
    seen = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            entries = os.listdir(root)
        except OSError:
            continue
        uid_dirs = [e for e in entries
                    if e.isdigit() and os.path.isdir(os.path.join(root, e))]
        if uid_dirs:
            # 标准模式: root/<userId>/<bundle>
            for uid in uid_dirs:
                try:
                    bundles = os.listdir(os.path.join(root, uid))
                except OSError:
                    continue
                for b in bundles:
                    base = os.path.join(root, uid, b)
                    if os.path.isdir(base) and base not in seen:
                        seen.add(base)
                        yield b, base
        else:
            # 扁平模式(PC 版): root/<bundle>
            for b in entries:
                base = os.path.join(root, b)
                if os.path.isdir(base) and base not in seen:
                    seen.add(base)
                    yield b, base


def cmd_scan(args):
    roots = args.root.split(":") if args.root else DEFAULT_ROOTS
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    # --json 时: 人类信息走 stderr, stdout 只留纯 JSON(便于 jq / 管道)
    out = sys.stderr if args.json else sys.stdout
    print(f"[+] HarmonyOS 沙箱取证扫描 v{VERSION}", file=out)
    print(f"[+] 权限: {'root(全部应用沙箱)' if is_root else '非root(可能仅本应用沙箱)'}", file=out)
    print(f"[+] 沙箱根: {' '.join(roots)}", file=out)

    found = 0
    all_info = []
    for bundle, base in iter_sandboxes(roots):
        found += 1
        print(f"\n== [{bundle}] {base} ==", file=out)
        binfo = {"bundle": bundle, "path": base,
                 "databases": [], "prefs": [], "creds": [], "logs": []}
        collected_any = False
        for sub in SUBDIRS:
            d = os.path.join(base, sub)
            if not os.path.isdir(d):
                continue
            for f in walk_files(d, maxdepth=2):
                for line in classify_and_collect(f, sub, binfo):
                    print(line, file=out)
                    collected_any = True
        if not collected_any:
            # 兜底: 非标准结构(如 PC 版 auth_groups/<bundle>), 直接扫 base 下文件
            for f in walk_files(base, maxdepth=3):
                for line in classify_and_collect(f, "", binfo):
                    print(line, file=out)
        all_info.append(binfo)

    print(file=out)
    if found == 0:
        print("[!] 未发现沙箱目录。可能: 权限不足 / 路径不符 / namespace 隔离。", file=out)
        print("    排查: ls -la /data/app/ ; ls -la /data/service/", file=out)
    else:
        ndb = sum(len(b["databases"]) for b in all_info)
        ncr = sum(len(b["creds"]) for b in all_info)
        print(f"[+] 共 {found} 个沙箱 | 数据库 {ndb} | 疑似凭据 {ncr}", file=out)
    print("    提示: 深度分析可用 pack 回传后跑 analyze_dump.py", file=out)

    if args.json:
        print(json.dumps({"version": VERSION, "is_root": is_root,
                          "sandboxes": all_info}, ensure_ascii=False, indent=2))


def cmd_pack(args):
    outdir = args.out
    try:
        os.makedirs(outdir, exist_ok=True)
    except OSError as e:
        print(f"[x] 无法创建输出目录 {outdir}: {e}", file=sys.stderr)
        return 1
    roots = args.root.split(":") if args.root else DEFAULT_ROOTS
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = os.path.join(outdir, f"forensic_{ts}.tar.gz")
    files = []
    for _b, base in iter_sandboxes(roots):
        for sub in SUBDIRS:
            d = os.path.join(base, sub)
            files.extend(walk_files(d, maxdepth=2))
    if not files:
        print("[!] 无可打包文件(检查 scan 输出与权限)")
        return 0
    n = 0
    with tarfile.open(out, "w:gz") as tf:
        for f in files:
            try:
                tf.add(f)
                n += 1
            except Exception:
                pass
    print(f"[+] 打包: {n} 文件 -> {out} ({_size(out)}B)")
    print(f"    回传主机: hdc file recv {out} ./")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="HarmonyOS PC 应用沙箱取证(设备端 Python)")
    ap.add_argument("cmd", nargs="?", default="scan",
                    choices=["scan", "pack"], help="scan=探测+解析(默认), pack=打包回传")
    ap.add_argument("--root", help="覆盖沙箱根, 冒号分隔(校准/测试用)")
    ap.add_argument("--json", action="store_true", help="scan 输出 JSON")
    ap.add_argument("--out", default="/data/local/tmp/harmony_forensics",
                    help="pack 输出目录")
    args = ap.parse_args()
    if args.cmd == "scan":
        cmd_scan(args)
    else:
        sys.exit(cmd_pack(args))


if __name__ == "__main__":
    main()
