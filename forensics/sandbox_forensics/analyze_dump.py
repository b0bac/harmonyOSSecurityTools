#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_dump.py — 主机端分析 sandbox_forensics.sh 回传的取证包/目录

设备上通常没有 sqlite3, 故数据库采集回主机后用本脚本解析:
列出表、行数、列、以及对疑似敏感列(token/session/auth/account/password/secret/key)
打印少量样本。

用法:
    python analyze_dump.py forensic_20260813_120000.tar.gz
    python analyze_dump.py ./解包目录/

只读打开数据库(mode=ro), 不修改原始文件。
"""
import os
import sys
import sqlite3
import tarfile
import tempfile

SENS_KEYS = ("token", "session", "auth", "account", "password", "secret",
             "key", "cookie", "credential")


def is_sqlite(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16)[:15] == b"SQLite format 3"
    except Exception:
        return False


def dump_db(path: str, lines: list):
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except Exception as e:
        lines.append(f"    [打不开] {e}")
        return
    cur = con.cursor()
    try:
        tabs = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    except Exception as e:
        lines.append(f"    [查询失败] {e}")
        con.close()
        return
    lines.append(f"    表({len(tabs)}): {', '.join(tabs) if tabs else '(空)'}")
    for t in tabs:
        try:
            cnt = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            cols = [d[1] for d in cur.execute(f'PRAGMA table_info("{t}")').fetchall()]
            lines.append(f"      - {t}({cnt}行) 列: {', '.join(cols)}")
            sens = [c for c in cols if any(k in c.lower() for k in SENS_KEYS)]
            if sens:
                lines.append(f"        ⚠ 疑似敏感列: {', '.join(sens)}")
                for row in cur.execute(f'SELECT * FROM "{t}" LIMIT 3'):
                    lines.append(f"        样本: {dict(zip(cols, row))}")
        except Exception as e:
            lines.append(f"      - {t}: 读取失败 {e}")
    con.close()


def main():
    if len(sys.argv) < 2:
        print("用法: python analyze_dump.py <dump.tar.gz|目录>")
        sys.exit(1)
    target = sys.argv[1]
    tmpdir = None
    if os.path.isfile(target) and (target.endswith(".gz") or target.endswith(".tgz")):
        tmpdir = tempfile.mkdtemp(prefix="forensic_")
        with tarfile.open(target) as tf:
            tf.extractall(tmpdir)
        root = tmpdir
    elif os.path.isdir(target):
        root = target
    else:
        print(f"目标不存在或类型未知: {target}")
        sys.exit(1)

    print(f"[*] 分析根: {root}")
    nfile = ndb = ncred = 0
    lines = []
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            nfile += 1
            rel = os.path.relpath(p, root)
            if is_sqlite(p):
                ndb += 1
                lines.append(f"\n[DB] {rel}")
                dump_db(p, lines)
            elif any(k in f.lower() for k in SENS_KEYS):
                ncred += 1
                lines.append(f"\n[疑似凭据文件] {rel}")
                try:
                    data = open(p, "rb").read(200)
                    lines.append(f"  预览({len(data)}B): {data[:120]!r}")
                except Exception as e:
                    lines.append(f"  读取失败: {e}")

    print(f"[*] 扫描文件 {nfile} | 数据库 {ndb} | 疑似凭据文件 {ncred}")
    print("\n".join(lines) if lines else "(未发现可解析的数据库/凭据文件)")
    if tmpdir:
        print(f"\n[*] 解包临时目录(可手动复查): {tmpdir}")


if __name__ == "__main__":
    main()
