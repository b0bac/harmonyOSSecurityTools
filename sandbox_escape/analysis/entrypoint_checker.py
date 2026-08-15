#!/usr/bin/env python3
# entrypoint_checker.py  [T6 / 路径 B1 深化]
# 功能：对 transition_mapper 给出的 TE 层可达边做「完整可达」复核——
#       按技术文档 §4.1.2 三条件模型 + typetransition 自动转换，判定
#       exec transition 是否真实可走，并给出入口二进制清单
# 定位：sandbox_escape / analysis / B1（第 2 轮真机测试新增，HarmonyOS PC 适配）
# 授权：仅用于已授权设备 dump 出的策略分析，离线静态运行
#
# 三条件（A --exec--> B 完整可达）：
#   1. allow A B:process transition                （process 规则，来自 rules.txt）
#   2. allow B <X>:file execute                    （目标域可执行入口）
#   3. allow A <X>:file { execute entrypoint }     （源域可把它作为入口）
#   加分项：typetransition A <X> process B          （无需 setexeccon 的自动转换）
#   其中 X 是入口二进制的 SELinux 类型，由 file_contexts 映射到实际路径
#
# 输入（均为设备侧 grep 产物，见 harmony_pc_test.sh 流程与 test_log.md）：
#   --process-rules   cil2rules 生成的 sesearch 风格 process 规则
#   --entrypoint-rules "(allow ... (file ... entrypoint ...))" CIL 行
#   --target-file-rules 目标域的 "(allow <tgt> ... (file ...))" CIL 行
#   --typetransitions "(typetransition ... process ...)" CIL 行
#   --typeattrs       typeattributeset 定义（属性展开）
#   --file-contexts   file_contexts（入口类型 → 二进制路径）
#
# 用法：
#   python3 entrypoint_checker.py --start normal_hap \
#     --process-rules rules.txt --entrypoint-rules file_entry_rules.cil \
#     --target-file-rules tgt_file_rules.cil --typetransitions type_trans.cil \
#     --typeattrs typeattrs.cil --file-contexts file_contexts -o ep_report

import argparse
import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cil2rules import parse_typeattrs, AttrEvaluator  # noqa: E402
from transition_mapper import (load_rules, build_reachability, APP_DOMAINS,  # noqa: E402
                               HIGH_DOMAIN_NAMES, HIGH_DOMAIN_PREFIXES,
                               CRITICAL_TARGETS)

ALLOW_FILE_RE = re.compile(
    r"^\(allow\s+(\S+)\s+(\S+)\s+\(file\s+\(([^)]*)\)\)\s*(?:\[.*\])?\)?$")
TYPETRANS_RE = re.compile(
    r"^\(typetransition\s+(\S+)\s+(\S+)\s+process\s+(\S+)\)\s*$")


def load_cil_file_rules(path: str, evaluator: AttrEvaluator, need_perm: str):
    """解析 CIL file 类 allow 规则，展开属性，返回 {(src, type)} 集合"""
    grants = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = ALLOW_FILE_RE.match(line.strip())
            if not m:
                continue
            perms = m.group(3).split()
            if need_perm not in perms:
                continue
            for s in evaluator.eval_name(m.group(1)):
                for t in evaluator.eval_name(m.group(2)):
                    grants.add((s, t))
    return grants


def load_typetransitions(path: str, evaluator: AttrEvaluator):
    """{(src, exec_type, target)}，展开 src 属性"""
    out = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = TYPETRANS_RE.match(line.strip())
            if not m:
                continue
            for s in evaluator.eval_name(m.group(1)):
                out.add((s, m.group(2), m.group(3)))
    return out


def load_file_contexts(path: str) -> dict:
    """入口类型 -> [二进制路径]。行格式：<path_regex> [--|-d...] u:object_r:<type>:s0"""
    by_type = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ctx = parts[-1]
            m = re.match(r"u:object_r:([^:]+):", ctx)
            if not m:
                continue
            path_regex = parts[0]
            if any(c in path_regex for c in r"()^$.*+?[]|{}"):
                # 正则条目：保留原文供人工核对，标注为 regex
                by_type.setdefault(m.group(1), set()).add(f"re:{path_regex}")
            else:
                by_type.setdefault(m.group(1), set()).add(path_regex)
    return by_type


def check(start_domains, process_rules_file, ep_rules_file, tgt_rules_file,
          ttr_file, typeattrs_files, fctx_file):
    rules = load_rules(rules_file=process_rules_file)
    reach = build_reachability(rules, tuple(start_domains))

    attrs = parse_typeattrs(typeattrs_files)
    evaluator = AttrEvaluator(attrs)
    ep_grants = load_cil_file_rules(ep_rules_file, evaluator, "entrypoint")
    exec_grants = load_cil_file_rules(tgt_rules_file, evaluator, "execute")
    ttrs = load_typetransitions(ttr_file, evaluator)
    fctx = load_file_contexts(fctx_file) if fctx_file else {}

    # 目标域集合：可达图里的全部非起始域
    targets = {d for d in reach["paths"] if d not in start_domains}

    ep_by_src = {}
    for s, t in ep_grants:
        ep_by_src.setdefault(s, set()).add(t)
    exec_by_tgt = {}
    for s, t in exec_grants:
        exec_by_tgt.setdefault(s, set()).add(t)
    ttr_by = {}
    for s, x, b in ttrs:
        ttr_by.setdefault((s, b), set()).add(x)

    # 只检查真实存在 process 边的 (src→tgt)：从可达图取直接前驱
    preds = {}
    for src, edges in reach["graph"].items():
        for e in edges:
            if not e.get("unreachable"):
                preds.setdefault(e["dst"], set()).add(src)

    def reachable_without(banned):
        """从起始域 BFS，但不经 banned 域中转（防「目标自身循环伪证」：
        目标域对自己的 exec 有 entrypoint 是重执行场景，不能证明外部可进）"""
        seen, queue = set(start_domains), list(start_domains)
        while queue:
            d = queue.pop(0)
            for e in reach["graph"].get(d, ()):
                if e.get("unreachable"):
                    continue
                t = e["dst"]
                if t != banned and t not in seen:
                    seen.add(t)
                    queue.append(t)
        return seen

    report = []
    for tgt in sorted(targets):
        chain = reach["paths"].get(tgt)
        entry = {
            "target": tgt, "chain": chain, "entrypoints": [], "verdict": None,
        }
        # 合法源域 = 有 process 边进 tgt，且不经过 tgt 就能从起始域到达
        valid_srcs = preds.get(tgt, set()) & reachable_without(tgt)
        for src in sorted(valid_srcs):
            candidates = ep_by_src.get(src, set()) & exec_by_tgt.get(tgt, set())
            auto = {x for x in ttr_by.get((src, tgt), set())
                    if x in candidates}
            for x in sorted(candidates):
                entry["entrypoints"].append({
                    "via": src, "entrypoint_type": x,
                    "binaries": sorted(fctx.get(x, ["<未知路径>"]))[:8],
                    "auto_transition": x in auto,   # True=exec 即自动进域
                })
        if entry["entrypoints"]:
            has_auto = any(e["auto_transition"] for e in entry["entrypoints"])
            entry["verdict"] = ("FULL_AUTO" if has_auto else "FULL_MANUAL")
        else:
            # 无入口 = TE 层可达但缺 entrypoint（需进一步看是否有绕法）
            entry["verdict"] = "TE_ONLY_NO_ENTRYPOINT"
        report.append(entry)

    # 不动点传播「真实可进」：入口源必须是起始域或自身完整可达的域，
    # 否则是循环前提（"若你已在 debug_bin"——但 debug_bin 本身进不去）
    attainable = set(start_domains)
    changed = True
    while changed:
        changed = False
        for entry in report:
            if entry["target"] in attainable:
                continue
            ok = any(e["via"] in attainable for e in entry["entrypoints"])
            if ok:
                attainable.add(entry["target"])
                changed = True
    for entry in report:
        if entry["verdict"].startswith("FULL") and entry["target"] not in attainable:
            # 入口只存在于不可达源域上 → 实际不可进
            entry["verdict"] = "TE_ONLY_CIRCULAR"
    return report


def main():
    ap = argparse.ArgumentParser(description="B1 transition 完整可达复核（三条件模型）")
    ap.add_argument("--start", nargs="+", default=list(APP_DOMAINS))
    ap.add_argument("--process-rules", required=True)
    ap.add_argument("--entrypoint-rules", required=True)
    ap.add_argument("--target-file-rules", required=True)
    ap.add_argument("--typetransitions", required=True)
    ap.add_argument("--typeattrs", nargs="+", required=True)
    ap.add_argument("--file-contexts")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()

    report = check(args.start, args.process_rules, args.entrypoint_rules,
                   args.target_file_rules, args.typetransitions,
                   args.typeattrs, args.file_contexts)

    full = [r for r in report if r["verdict"].startswith("FULL")]
    auto = [r for r in report if r["verdict"] == "FULL_AUTO"]
    te_only = [r for r in report if r["verdict"].startswith("TE_ONLY")]
    print(f"[*] 可达目标 {len(report)} 个：完整可达 {len(full)}"
          f"（其中 exec 自动转换 {len(auto)}），TE 层可达但实际不可进 {len(te_only)}")
    for r in report:
        print(f"\n [{r['verdict']}] {r['target']}")
        print(f"   chain: {' ==> '.join(r['chain'])}")
        for e in r["entrypoints"][:6]:
            auto_mark = "auto" if e["auto_transition"] else "manual"
            print(f"   入口: {e['entrypoint_type']} ({auto_mark}, via {e['via']})")
            print(f"        二进制: {', '.join(e['binaries'][:4])}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n[+] 报告已写入 {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
