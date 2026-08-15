#!/usr/bin/env python3
# cil2rules.py  [T1 组件 / 路径 B1]
# 功能：把 HarmonyOS PC 的 CIL 格式 SELinux 策略源转换为 sesearch 风格规则文本，
#       供 transition_mapper.py --rules-file 直接消费
# 定位：sandbox_escape / analysis / B1（HarmonyOS PC 实测适配：策略源为
#       /system/etc/selinux/*.cil，无需二进制 policy 与 setools4）
# 授权：仅用于已授权设备 dump 出的策略分析，离线静态运行
#
# 关键实现点（v1.1，真机实测修正）：
#   HarmonyOS PC 的 typeattributeset 值是 S 表达式，含布尔运算
#   (and (domain) (not (sudo_domain hap_domain ...)))——
#   必须完整求值（and/or/not + 递归展开），平铺解析会把「排除集」误当
#   「成员集」，产生假攻击链（实测教训：normal_hap→processdump 即此类误报）。
#
# 输入：
#   --typeattrs  各 CIL 文件 grep 出的 typeattributeset 行（属性定义）
#   --rules      各 CIL 文件 grep 出的 "(allow ... (process ...))" 行
# 输出：
#   sesearch 风格文本：allow <src> <tgt> : process { <perms> };
#
# 用法：
#   python3 cil2rules.py --typeattrs typeattrs.cil \
#       --rules proc_rules_common.cil proc_rules_sys.cil proc_rules_dev.cil \
#       -o rules.txt

import argparse
import re
import sys

TYPEATTR_RE = re.compile(r"^\(typeattributeset\s+(\S+)\s+(.+)\)\s*$")
ALLOW_RE = re.compile(
    r"^\(allow\s+(\S+)\s+(\S+)\s+\(process\s+\(([^)]*)\)\)\s*(?:\[.*\])?\)?$"
)
KEEP_PERMS = ("transition", "dyntransition", "setcurrent")


# ---------- S 表达式解析与求值 ----------

def tokenize(s: str) -> list:
    return s.replace("(", " ( ").replace(")", " ) ").split()


def parse_sexp(tokens: list, pos: int = 0):
    """递归下降解析 S 表达式 → 嵌套 list / 裸 token"""
    if pos >= len(tokens):
        return None, pos
    tok = tokens[pos]
    if tok == "(":
        node, pos2 = [], pos + 1
        while pos2 < len(tokens) and tokens[pos2] != ")":
            child, pos2 = parse_sexp(tokens, pos2)
            if child is not None:
                node.append(child)
        return node, pos2 + 1  # 跳过 ')'
    if tok == ")":
        return None, pos + 1
    return tok, pos + 1


class AttrEvaluator:
    """typeattributeset 布尔表达式求值器（带环保护与结果缓存）"""

    def __init__(self, attrs: dict):
        self.attrs = attrs          # name -> 解析后的表达式树
        self.cache = {}             # name -> frozenset(类型集合)

    def eval_node(self, node, resolving=frozenset()) -> frozenset:
        """求值表达式节点：token → 属性展开/具体类型；list → and/or/not/并集"""
        if isinstance(node, str):
            return self.eval_name(node, resolving)
        if not node:
            return frozenset()
        op = node[0]
        if op == "and":
            result = None
            for arg in node[1:]:
                s = self.eval_node(arg, resolving)
                result = s if result is None else (result & s)
            return result or frozenset()
        if op == "or":
            out = set()
            for arg in node[1:]:
                out |= self.eval_node(arg, resolving)
            return frozenset(out)
        if op == "not":
            # not 必须知道全集：以 domain 属性为全集（CIL 策略惯例）
            universe = self.eval_name("domain", resolving) \
                if "domain" in self.attrs else frozenset()
            inner = frozenset().union(*[self.eval_node(a, resolving)
                                        for a in node[1:]]) if node[1:] else frozenset()
            return frozenset(universe - inner)
        # 无运算符的裸列表 = 成员并集
        out = set()
        for member in node:
            out |= self.eval_node(member, resolving)
        return frozenset(out)

    def eval_name(self, name: str, resolving=frozenset()) -> frozenset:
        if name in self.cache:
            return self.cache[name]
        if name not in self.attrs or name in resolving:
            return frozenset({name})  # 具体类型（或环，按类型处理止递归）
        tree = self.attrs[name]
        result = self.eval_node(tree, resolving | {name})
        self.cache[name] = result
        return result


def parse_typeattrs(paths: list) -> dict:
    """name -> 表达式树"""
    attrs = {}
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = TYPEATTR_RE.match(line.strip())
                if not m:
                    continue
                tokens = tokenize(m.group(2))
                tree, _ = parse_sexp(["("] + tokens + [")"])
                # attrs[name] 仅保留一个定义；CIL 里同名多定义本应求并，
                # 但同一文件内重复出现的多为等价变体，取并集：
                if m.group(1) in attrs:
                    attrs[m.group(1)] = ["or", attrs[m.group(1)], tree]
                else:
                    attrs[m.group(1)] = tree
    return attrs


# ---------- 规则转换 ----------

def convert(rules_paths: list, evaluator: AttrEvaluator,
            max_expand: int = 200000) -> list:
    lines, emitted = [], set()
    for path in rules_paths:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = ALLOW_RE.match(line.strip())
                if not m:
                    continue
                src_a, tgt_a, perms = m.group(1), m.group(2), m.group(3)
                keep = [p for p in KEEP_PERMS if p in perms.split()]
                if not keep:
                    continue
                srcs = sorted(evaluator.eval_name(src_a))
                tgts = sorted(evaluator.eval_name(tgt_a))
                for s in srcs:
                    for t in tgts:
                        if t == "self":
                            t = s
                        key = (s, t, tuple(keep))
                        if key in emitted:
                            continue
                        emitted.add(key)
                        lines.append(f"allow {s} {t} : process "
                                     f"{{ {' '.join(keep)} }};")
                        if len(lines) > max_expand:
                            return lines
    return lines


def main():
    ap = argparse.ArgumentParser(description="CIL 策略 → sesearch 规则转换器")
    ap.add_argument("--typeattrs", nargs="+", required=True,
                    help="typeattributeset 定义文件（可多个）")
    ap.add_argument("--rules", nargs="+", required=True,
                    help="process 类 allow 规则文件（可多个）")
    ap.add_argument("-o", "--output", default="rules.txt")
    args = ap.parse_args()

    attrs = parse_typeattrs(args.typeattrs)
    print(f"[*] 属性定义载入: {len(attrs)} 个")
    evaluator = AttrEvaluator(attrs)

    lines = convert(args.rules, evaluator)
    n_dyn = sum(1 for l in lines if "dyntransition" in l)
    n_set = sum(1 for l in lines if "setcurrent" in l)
    n_trans = len(lines) - n_dyn - n_set
    print(f"[*] 展开后规则 {len(lines)} 条 "
          f"(transition={n_trans} dyntransition={n_dyn} setcurrent={n_set})")

    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] 已写入 {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
