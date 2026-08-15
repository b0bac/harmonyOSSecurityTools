#!/usr/bin/env python3
# binder_surface.py  [T3.5 / 路径 C-D 前置]
# 功能：从设备 CIL 提取的 binder 类规则，展开属性后计算指定域的
#       IPC 攻击面（可 binder call/transfer 的目标域清单），并与
#       service_contexts 的 sa_* 对象标签交叉——揭示「进程域级宽授权」
#       与「对象级标签收紧」的双轨差异，为 C1/D 层接口审计选靶
# 定位：sandbox_escape / analysis（第 3 轮真机测试新增）
# 授权：仅用于已授权设备 dump 出的策略分析，离线静态运行
#
# 输入：
#   --binder-rules   设备 grep '(binder' 的 CIL 行（gzip 拉回后解压）
#   --typeattrs      typeattributeset 定义（属性展开）
#   --service-contexts  service_contexts（sa_* 对象标签 → SA id）
#   --domain         要分析的起始域（可多个）
# 输出：每个域的可达目标清单（stdout + 可选 JSON），高价值目标标注
#
# 用法：
#   python3 binder_surface.py --domain normal_hap \
#     --binder-rules binder_rules.cil --typeattrs typeattrs.cil \
#     --service-contexts service_contexts -o binder_surface.json

import argparse
import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cil2rules import parse_typeattrs, AttrEvaluator  # noqa: E402

ALLOW_RE = re.compile(r"^\(allow\s+(\S+)\s+(\S+)\s+\(binder\s+\(([^)]*)\)\)\)?")

# 高价值目标（凭据/密钥/系统管理/虚拟化/调试通道）——命中即标 HIGH
HIGH_VALUE = (
    "samgr", "foundation", "system_server", "native_daemon",
    "huks_service", "useriam", "accountmgr", "accesstoken_service",
    "deviceauth_service", "el5_filekey_manager", "d-bms", "installd",
    "penglai_service", "ohos_vm_manager", "disk_manager", "hdf_devmgr",
    "code_protect", "sandbox_manager_service", "softbus_server",
)


def load_sa_labels(path):
    """service_contexts: {sa_标签: [SA id,...]}"""
    labels = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r"\s*(\S+)\s+u:object_r:(sa_\S+):s0", line)
            if m:
                labels.setdefault(m.group(2), []).append(m.group(1))
    return labels


def surface(domain, allow_rules, evaluator, sa_labels):
    hits = {}
    for s, t, perms in allow_rules:
        if domain in evaluator.eval_name(s):
            for tt in evaluator.eval_name(t):
                hits.setdefault(tt, set()).update(perms.split())
    out = []
    for tgt in sorted(hits):
        perms = sorted(hits[tgt])
        out.append({
            "target": tgt,
            "perms": perms,
            "can_call": "call" in perms,
            "can_transfer": "transfer" in perms,
            "sa_object_label": tgt in sa_labels,   # 双轨：sa_* 对象标签可达
            "risk": "HIGH" if tgt in HIGH_VALUE and "call" in perms else "",
        })
    return out


def main():
    ap = argparse.ArgumentParser(description="C/D 层前置：binder IPC 攻击面计算")
    ap.add_argument("--domain", nargs="+", required=True)
    ap.add_argument("--binder-rules", required=True)
    ap.add_argument("--typeattrs", nargs="+", required=True)
    ap.add_argument("--service-contexts")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()

    evaluator = AttrEvaluator(parse_typeattrs(args.typeattrs))
    allow_rules = []
    neverallow = 0
    with open(args.binder_rules, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("(neverallow"):
                neverallow += 1
                continue
            m = ALLOW_RE.match(line)
            if m:
                allow_rules.append(m.groups())
    sa_labels = load_sa_labels(args.service_contexts) if args.service_contexts else {}

    report = {}
    for domain in args.domain:
        surf = surface(domain, allow_rules, evaluator, sa_labels)
        callable_ = [t for t in surf if t["can_call"]]
        high = [t for t in surf if t["risk"] == "HIGH"]
        sa_callable = [t for t in surf if t["sa_object_label"]]
        report[domain] = surf
        print(f"\n== {domain} ==")
        print(f"  binder 可达域 {len(surf)}（可 call {len(callable_)}），"
              f"高价值目标 {len(high)}，sa_* 对象标签可达 {len(sa_callable)}")
        for t in high:
            print(f"  [HIGH] {t['target']}: {' '.join(t['perms'])}")
    print(f"\n[*] neverallow 规则 {neverallow} 条（编译期断言，不参与运行时判定，"
          f"但可作设计意图参考）")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[+] 报告已写入 {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
