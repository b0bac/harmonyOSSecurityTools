#!/usr/bin/env python3
# transition_mapper.py  [T1 / 路径 B1]
# 功能：分析 sepolicy，导出应用域的 transition 可达域图，回溯多跳攻击链
# 定位：sandbox_escape / analysis / B1 transition 攻击面分析
# 授权：仅用于已授权设备 dump 出的策略分析，离线静态运行
#
# 修正项（对应技术文档 v1.1 勘误编号）：
#   E4  dyntransition 可达需双条件：allow A B:process dyntransition + allow A A:process setcurrent
#   E8  sesearch 命令拼装（-p 是 permission 过滤，policy 作为末尾位置参数）
#   E9  setools4 输出解析（"allow src tgt : process { perm };"，冒号两侧有空格）
#   E10 BFS 全链路回溯，多跳攻击链进报告（不只一跳边）
#   E11 EXPECTED 基线从外置 JSON 加载，不再恒空
#
# 两种输入模式：
#   1. 实时 sesearch 模式（默认）：主机装有 setools4，直接喂 policy.bin
#      sesearch --allow -c process -p transition   <policy>
#      sesearch --allow -c process -p dyntransition <policy>
#      sesearch --allow -c process -p setcurrent    <policy>
#   2. --rules-file 离线模式：先在有 setools4 的机器上把上述三条命令的输出
#      合并保存为文本（或手工构造规则），拷到任意环境分析——真机也能跑
#
# 用法：
#   python3 transition_mapper.py policy.bin --bundle com.example.app
#   python3 transition_mapper.py policy.bin --baseline expected.json -o report
#   python3 transition_mapper.py --rules-file rules.txt --start normal_domain

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict

# ---------- 常量 ----------

APP_DOMAINS = ("untrusted_app", "normal_domain", "untrusted_app_29")

# 顶级高危域——应用域不该能直接/间接到达（E10：间接到达同样算红）
CRITICAL_TARGETS = {"init", "unconfined", "shell", "su", "root", "kernel"}

HIGH_DOMAIN_PREFIXES = ("sa_", "system_", "hiprofiler", "hiperf", "hitrace")

# HarmonyOS PC 风格的高价值目标域（调试/诊断/守护域，命名无 sa_ 前缀）
HIGH_DOMAIN_NAMES = {
    "hidumper", "hiebpf", "native_daemon", "SP_daemon", "hdcd",
    "processdump", "hisysevent", "bytrace", "appspawn", "nativespawn",
}

# setools4 sesearch 典型输出行（E9）：
#   allow normal_domain sa_xxx : process { transition };
#   allow normal_domain normal_domain : process { setcurrent };
#   allow src tgt : process transition;              （单权限无花括号）
#   ... ; [some_bool]                                 （条件规则尾注，忽略）
RULE_RE = re.compile(
    r"^\s*allow\s+(?P<src>\S+)\s+(?P<tgt>\S+)\s*:\s*process\s*"
    r"(?:\{(?P<perms_braced>[^}]*)\}|(?P<perm_single>\S+))\s*;"
)


# ---------- 规则获取：sesearch / 离线规则文件 ----------

def run_sesearch(policy_file: str, permission: str) -> str:
    """调用 setools4 sesearch 查询 process 类指定权限的 allow 规则（E8 修正）"""
    if not subprocess.run(["which", "sesearch"], capture_output=True).returncode == 0:
        raise RuntimeError("未找到 sesearch，请安装 setools4（见 requirements.txt），"
                           "或改用 --rules-file 离线模式")
    cmd = ["sesearch", "--allow", "-c", "process", "-p", permission, policy_file]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"sesearch 失败: {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc.stdout


def load_rules(policy_file: str = None, rules_file: str = None) -> dict:
    """
    返回 {"transition": [(src, tgt), ...],
          "dyntransition": [(src, tgt), ...],
          "setcurrent": [(src, tgt), ...]}
    """
    if rules_file:
        with open(rules_file, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = "\n".join(run_sesearch(policy_file, p)
                         for p in ("transition", "dyntransition", "setcurrent"))

    rules = {"transition": [], "dyntransition": [], "setcurrent": []}
    for line in text.splitlines():
        m = RULE_RE.match(line)
        if not m:
            continue
        perms = (m.group("perms_braced") or m.group("perm_single") or "").split()
        src, tgt = m.group("src"), m.group("tgt")
        for p in ("transition", "dyntransition", "setcurrent"):
            if p in perms:
                rules[p].append((src, tgt))
    return rules


# ---------- 可达图构建与攻击链回溯（E10） ----------

def build_reachability(rules: dict, start_domains) -> dict:
    """
    BFS 构建可达图并记录完整路径（多跳攻击链）。
    dyntransition 边需同时满足源域有 setcurrent 自授权（E4），否则视为不可达。
    返回 {"graph": {domain: [edge, ...]}, "paths": {domain: 攻击链}}
    """
    graph = defaultdict(list)
    setcurrent_domains = {src for src, _ in rules["setcurrent"]}
    paths = {d: [d] for d in start_domains}
    visited = set(start_domains)
    queue = list(start_domains)

    while queue:
        domain = queue.pop(0)
        for e in _adjacency_for(rules, domain, setcurrent_domains):
            graph[domain].append(e)
            if e.get("unreachable"):
                continue  # setcurrent 缺失的 dyntransition 不参与可达扩展（E4）
            tgt = e["dst"]
            if tgt not in visited:
                visited.add(tgt)
                # 记录从起始域出发的完整攻击链（多跳回溯，E10），
                # 链元素形如 ["normal_domain", "A --exec--> B", "B --setcon--> C"]
                paths[tgt] = _chain_extend(paths, domain, tgt, e)
                queue.append(tgt)
    return {"graph": dict(graph), "paths": paths}


def _chain_extend(paths: dict, src_domain: str, tgt: str, edge: dict) -> list:
    prev = paths.get(src_domain) or [src_domain]
    step = edge.get("via", edge["kind"])
    return prev[:-1] + [f"{prev[-1]} --{step}--> {tgt}"]


def _adjacency_for(rules: dict, domain: str, setcurrent_domains: set) -> list:
    """从规则表取 domain 的出边；dyntransition 检查 setcurrent 双条件（E4）"""
    edges = []
    seen = set()
    for src, tgt in rules["transition"]:
        if src != domain:
            continue
        if (src, tgt, "exec") in seen:
            continue
        seen.add((src, tgt, "exec"))
        edges.append({"src": src, "dst": tgt, "kind": "exec_transition",
                      "via": "exec"})
    for src, tgt in rules["dyntransition"]:
        if src != domain:
            continue
        if src not in setcurrent_domains:
            # 策略允许 dyntransition 但源域无 setcurrent → 实际不可达（E4）；
            # 仍记入图（标注 UNREACHABLE）但不参与 BFS 扩展
            edges.append({"src": src, "dst": tgt,
                          "kind": "dyntransition_UNREACHABLE_no_setcurrent",
                          "via": "dyn[!setcurrent]", "unreachable": True})
        elif (src, tgt, "dyn") not in seen:
            seen.add((src, tgt, "dyn"))
            edges.append({"src": src, "dst": tgt, "kind": "dyntransition",
                          "via": "setcon"})
    return edges


# ---------- 风险分类（E11：EXPECTED 从基线文件加载） ----------

def load_baseline(path: str = None) -> set:
    if not path:
        return set()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # 支持 ["domain", ...] 或 [{"from": ..., "to": ...}, ...]
    if data and isinstance(data[0], dict):
        return {(d.get("from"), d.get("to")) for d in data}
    return set(data)


def classify_target(domain: str, from_domain: str, baseline: set) -> str:
    if (from_domain, domain) in baseline or domain in baseline:
        return "EXPECTED"
    if domain in CRITICAL_TARGETS:
        return "CRITICAL"
    if domain in HIGH_DOMAIN_NAMES or domain.startswith(HIGH_DOMAIN_PREFIXES):
        return "HIGH"
    return "UNKNOWN"


RISK_NOTES = {
    "CRITICAL": "应用域可到达顶级高危域，疑似 transition 策略遗漏（直接红）",
    "HIGH": "应用域可到达系统/服务域，需审查该域能力（间接提权跳板）",
    "UNKNOWN": "应用域可到达未分类域，需人工确认",
    "EXPECTED": "基线内的预期转换",
}


# ---------- 主分析流程 ----------

def analyze(rules: dict, start_domains=APP_DOMAINS, baseline: set = None) -> dict:
    baseline = baseline or set()
    reach = build_reachability(rules, tuple(start_domains))
    findings = []
    for domain, chain in reach["paths"].items():
        if domain in start_domains:
            continue
        from_domain = start_domains[0]  # 链首即起始域
        severity = classify_target(domain, from_domain, baseline)
        if severity == "EXPECTED":
            continue
        findings.append({
            "to": domain,
            "severity": severity,
            "chain": chain,  # 多跳攻击链，如 ["normal_domain --exec--> mid_t --setcon--> sa_xxx"]
            "note": RISK_NOTES[severity],
        })
    order = {"CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2}
    findings.sort(key=lambda x: order[x["severity"]])
    return {"start_domains": list(start_domains), "graph": reach["graph"],
            "findings": findings}


def to_dot(report: dict) -> str:
    """输出 dot 拓扑（与 trust_mapper 风格统一，红/黄/灰分级着色）"""
    sev_color = {"CRITICAL": "red", "HIGH": "orange"}
    finding_color = {f["to"]: sev_color.get(f["severity"], "gray")
                     for f in report["findings"]}
    lines = ["digraph transition_attack_surface {",
             '  rankdir=LR; node [shape=box];']
    for f in report["findings"]:
        chain = f["chain"]
        # 链元素形如 "A --exec--> B"，逐段拆成 dot 边
        node = chain[0]
        lines.append(f'  "{node}" [style=filled fillcolor=lightblue];')
        for step in chain[1:]:
            m = re.match(r"(.+) --(.+)--> (.+)", step)
            if m:
                a, via, b = m.groups()
                color = finding_color.get(b, "gray")
                lines.append(f'  "{a}" -> "{b}" [label="{via}", color={color}];')
                if b in finding_color:
                    lines.append(f'  "{b}" [style=filled fillcolor={finding_color[b]}];')
    lines.append("}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="B1 transition 可达域攻击链分析器")
    ap.add_argument("policy", nargs="?", help="dump 出的 policy.bin（sesearch 模式）")
    ap.add_argument("--rules-file", help="离线模式：预导出的 sesearch 规则文本")
    ap.add_argument("--start", nargs="+", default=list(APP_DOMAINS),
                    help="起始应用域（默认 %s）" % "/".join(APP_DOMAINS))
    ap.add_argument("--baseline", help="EXPECTED 基线 JSON 文件（E11）")
    ap.add_argument("-o", "--output", help="报告前缀，生成 <prefix>.json / <prefix>.dot")
    args = ap.parse_args()

    if not args.policy and not args.rules_file:
        ap.error("需提供 policy.bin 或 --rules-file 之一")

    rules = load_rules(args.policy, args.rules_file)
    print(f"[*] 规则载入: transition={len(rules['transition'])} "
          f"dyntransition={len(rules['dyntransition'])} "
          f"setcurrent={len(rules['setcurrent'])}")

    baseline = load_baseline(args.baseline)
    report = analyze(rules, tuple(args.start), baseline)

    crit = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    high = sum(1 for f in report["findings"] if f["severity"] == "HIGH")
    print(f"[+] 可达域 {len(report['findings'])} 个（CRITICAL={crit} HIGH={high}）")
    for f in report["findings"]:
        chain = " ==> ".join(f["chain"])
        print(f"  [{f['severity']}] {chain}\n        {f['note']}")

    if args.output:
        with open(args.output + ".json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        with open(args.output + ".dot", "w", encoding="utf-8") as f:
            f.write(to_dot(report))
        print(f"[+] 报告已写入 {args.output}.json / {args.output}.dot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
