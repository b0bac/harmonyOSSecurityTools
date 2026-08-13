#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trust_mapper.py — HarmonyOS DSoftBus(分布式软总线)信任拓扑测绘(设备端)

在 HarmonyOS PC 本地运行, 扫描软总线/设备认证相关的存储, 提取已绑定设备与
信任关系, 构建信任拓扑。

  scan  探测信任存储 + 解析 sqlite/文本, 提取设备清单与信任关系(默认)
  graph 输出 Graphviz dot, 回传 Mac 后 `dot -Tpng trust.dot -o trust.png`

纯标准库, 只读。自适应 root/非root。

⚠ 路径/表结构在不同 OpenHarmony 版本差异大: 本工具用候选路径自动探测 + 通用
  启发式解析, 输出自描述报告。真机发现实际路径/字段后, 调整 TRUST_ROOTS /
  启发式即可精确化。

用法:
    python3 trust_mapper.py scan
    python3 trust_mapper.py scan --root /data/service/el2   # 校准/测试
    python3 trust_mapper.py scan --json
    python3 trust_mapper.py graph --root /data/service/el2

仅用于授权安全测试 / 取证。
"""
import os
import sys
import re
import json
import sqlite3
import argparse
from collections import OrderedDict

VERSION = "0.1"

# 信任存储候选路径(userId 用数字目录自动展开)
TRUST_ROOTS = [
    "/data/storage/el2/auth_groups",     # 分布式认证组(可信环/认证凭据/账号服务)—— PC 版
    "/data/storage/el2/database",        # servers_public.db 等
    "/data/storage/el4/database",        # servers_secret.db
    "/data/storage/el1",                 # bundle / el1 服务数据
    "/data/service/el1/public",          # device_auth/huks 兜底(标准 OpenHarmony 路径)
]
# 扫描深度
MAXDEPTH = 3
# 视为信任相关的文件名关键词
FILE_HINTS = ("account", "group", "cred", "device", "trust", "auth",
              "softbus", "hmdfs", "session", "peer", "bind")
# sqlite 表名关键词(放宽: 空则扫所有表)
TABLE_HINTS = ("group", "cred", "account", "device", "trust", "session", "peer", "bind")
# 列名 -> 角色
COL_ID = re.compile(r"(udid|device_?id|peer_?id|uuid|account_?id|^id$)", re.I)
COL_NAME = re.compile(r"(device_?name|peer_?name|account_?name|^name$|alias|hicomname)", re.I)
COL_REL = re.compile(r"(group_?type|bind_?type|auth_?type|relation|role|trust_?level)", re.I)
# UDID 特征: 40+ 位 hex, 或 OpenHarmony 常见 deviceId 串
UDID_RE = re.compile(r"\b[0-9A-Fa-f]{32,64}\b")
# 视为版本指纹的键
VERSION_KEYS = ("softbusversion", "ohversion", "osversion", "version")


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


def walk_files(path, maxdepth=MAXDEPTH):
    if not os.path.isdir(path):
        return
    for dp, dn, fn in os.walk(path):
        rel = dp[len(path):].lstrip(os.sep)
        depth = 0 if rel == "" else rel.count(os.sep) + 1
        if depth > maxdepth:
            dn[:] = []
            continue
        for f in fn:
            yield os.path.join(dp, f)


def iter_trust_files(roots):
    """yield 信任相关文件路径(目录存在性 + 文件名/类型过滤)"""
    for root in roots:
        if not os.path.isdir(root):
            continue
        for f in walk_files(root):
            low = os.path.basename(f).lower()
            if is_sqlite(f):
                yield f
            elif any(h in low for h in FILE_HINTS):
                yield f


def _parse_trust_db(path, state):
    """解析单个 sqlite, 提取设备标识与关系; 写入 state"""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except Exception:
        return
    cur = con.cursor()
    try:
        tabs = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    except Exception:
        con.close()
        return
    state["sources"].add(path)
    for t in tabs:
        if TABLE_HINTS and not any(h in t.lower() for h in TABLE_HINTS):
            continue
        try:
            cols = [d[1] for d in cur.execute(f'PRAGMA table_info("{t}")').fetchall()]
            rows = cur.execute(f'SELECT * FROM "{t}"').fetchall()
        except Exception:
            continue
        for row in rows:
            rec = dict(zip(cols, row))
            ids, names, rels = {}, {}, {}
            for col, val in rec.items():
                if val is None:
                    continue
                sval = str(val)
                if COL_ID.search(col) or UDID_RE.fullmatch(sval):
                    ids[col] = sval
                elif COL_NAME.search(col):
                    names[col] = sval
                elif COL_REL.search(col):
                    rels[col] = sval
            # 收集设备节点(登记本行所有 id)
            node_keys = list(ids.values()) or (
                [v for v in names.values()] if names else [])
            for key in node_keys:
                dev = state["devices"].setdefault(
                    key, {"id": key, "names": set(), "sources": set()})
                dev["sources"].add(path)
            # 设备名只挂到对端(peer/remote)设备, 避免本端误挂对端名;
            # 若无 peer 前缀列(无法区分), 退化为挂到所有节点
            peer_keys = [v for c, v in ids.items()
                         if re.search(r"peer|remote|other", c, re.I)]
            name_targets = peer_keys if peer_keys else node_keys
            for key in name_targets:
                if key in state["devices"]:
                    for n in names.values():
                        state["devices"][key]["names"].add(n)
            # 关系推断: 同行 >=2 个不同设备标识 -> 建边
            uniq_ids = list(dict.fromkeys(ids.values()))
            if len(uniq_ids) >= 2:
                rtype = next(iter(rels.values()), "related")
                for i in range(len(uniq_ids)):
                    for j in range(i + 1, len(uniq_ids)):
                        a, b = uniq_ids[i], uniq_ids[j]
                        if a == b:
                            continue
                        edge = (a, b, rtype)
                        state["edges"].setdefault(edge, set()).add(path)
    con.close()


def _parse_trust_text(path, state):
    """从文本/json 提取 UDID/deviceName 等"""
    try:
        with open(path, "rb") as f:
            text = f.read(200000).decode("utf-8", "replace")
    except Exception:
        return
    state["sources"].add(path)
    # JSON 优先
    try:
        obj = json.loads(text)
        _harvest_json(obj, path, state)
        if obj is not None:
            return
    except Exception:
        pass
    # 正则兜底
    for m in UDID_RE.finditer(text):
        key = m.group(0)
        dev = state["devices"].setdefault(
            key, {"id": key, "names": set(), "sources": set()})
        dev["sources"].add(path)
    nm = re.compile(r'"?device_?[Nn]ame"?\s*[:=]\s*"([^"]+)"')
    for m in nm.finditer(text):
        _attach_name(state, m.group(1), path)


def _harvest_json(obj, path, state, parent_key=""):
    if isinstance(obj, dict):
        ids, names = {}, {}
        for k, v in obj.items():
            kl = k.lower()
            if isinstance(v, str):
                if re.search(r"(udid|device_?id|peer_?id|uuid)", kl) or UDID_RE.fullmatch(v):
                    ids[kl] = v
                elif re.search(r"(device_?name|name|alias|hicomname)", kl):
                    names[kl] = v
            _harvest_json(v, path, state, parent_key=k)
        for key in ids.values():
            dev = state["devices"].setdefault(
                key, {"id": key, "names": set(), "sources": set()})
            dev["sources"].add(path)
            for n in names.values():
                dev["names"].add(n)
    elif isinstance(obj, list):
        for item in obj:
            _harvest_json(item, path, state, parent_key)


def _attach_name(state, name, path):
    # 找最近一个设备节点挂名(粗糙)
    if state["devices"]:
        last = next(reversed(state["devices"]))
        state["devices"][last]["names"].add(name)


def scan(roots):
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    state = {"devices": OrderedDict(), "edges": OrderedDict(),
             "sources": set()}
    for f in iter_trust_files(roots):
        if is_sqlite(f):
            _parse_trust_db(f, state)
        else:
            _parse_trust_text(f, state)
    state["is_root"] = is_root
    return state


# ---- 渲染 ----
def render_text(state):
    out = []
    out.append(f"[+] DSoftBus 信任拓扑测绘 v{VERSION}")
    out.append(f"[+] 权限: {'root' if state['is_root'] else '非root(系统信任数据可能不可读)'}")
    devs = state["devices"]
    edges = state["edges"]
    out.append(f"[+] 信任设备 {len(devs)} 个 | 信任关系 {len(edges)} 条 | "
               f"数据源 {len(state['sources'])}")
    if not state["sources"]:
        out.append("")
        out.append("[!] 未发现信任数据。可能: 权限不足 / 路径不符 / 数据加密。")
        out.append("    排查: ls -la /data/service/el2/<userId>/ ; "
                   "ls -la /data/service/el1/public/")
        return "\n".join(out)
    out.append("\n[+] 信任设备清单")
    for d in devs.values():
        nm = ",".join(d["names"]) or "?"
        out.append(f"    - {d['id'][:24]}  name={nm}")
        out.append(f"        来源 {len(d['sources'])} 个文件")
    if edges:
        out.append("\n[+] 信任关系")
        for (a, b, t), srcs in edges.items():
            out.append(f"    {a[:16]} .. {b[:16]}  [{t}]  ({len(srcs)} 源)")
    out.append("\n[+] 数据源")
    for s in sorted(state["sources"]):
        out.append(f"    {s} ({_size(s)}B)")
    out.append("\n    提示: 回传 --dot 后用 graphviz 画拓扑: "
               "dot -Tpng trust.dot -o trust.png")
    return "\n".join(out)


def render_json(state):
    devs = [{"id": d["id"], "names": sorted(d["names"]),
             "sources": sorted(d["sources"])} for d in state["devices"].values()]
    edges = [{"a": a, "b": b, "type": t, "sources": sorted(s)}
             for (a, b, t), s in state["edges"].items()]
    return json.dumps({"version": VERSION, "is_root": state["is_root"],
                       "devices": devs, "edges": edges,
                       "sources": sorted(state["sources"])},
                      ensure_ascii=False, indent=2)


def render_dot(state):
    lines = ["graph dsoftbus_trust {", '  rankdir=LR;',
             '  node [shape=box, style=filled, fillcolor=lightyellow];']
    for d in state["devices"].values():
        nm = (",".join(d["names"]) or d["id"][:12]).replace('"', "'")
        lines.append(f'  "{d["id"]}" [label="{nm}"];')
    for (a, b, t) in state["edges"]:
        lines.append(f'  "{a}" -- "{b}" [label="{t}"];')
    lines.append("}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="HarmonyOS DSoftBus 信任拓扑测绘(设备端)")
    ap.add_argument("cmd", nargs="?", default="scan", choices=["scan", "graph"])
    ap.add_argument("--root", action="append", default=[],
                    help="覆盖信任存储根(可多次指定, 校准/测试用)")
    ap.add_argument("--json", action="store_true", help="scan 输出 JSON")
    args = ap.parse_args()
    roots = args.root if args.root else TRUST_ROOTS
    state = scan(roots)
    if args.cmd == "graph":
        print(render_dot(state))
    elif args.json:
        print(render_json(state))
    else:
        print(render_text(state))


if __name__ == "__main__":
    main()
