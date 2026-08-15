#!/usr/bin/env python3
# interface_auditor.py  [T4 / 路径 C1]
# 功能：对 SA 接口实现（反编译伪代码/符号/字符串导出）做批量静态审计，
#       挖掘「无校验的特权接口」——C1 直接提权点
# 定位：sandbox_escape / analysis / C1 接口审计（半自动：命中后需人工复核）
# 授权：仅用于已授权分析目标
#
# 修正项（对应技术文档 v1.1 勘误编号）：
#   E12  校验特征分两级：
#        - 判定型（VerifyAccessToken / VerifyPermission / PermissionCheck 等）
#          → 记 has_verify
#        - 取值型（GetCallingUid / GetCallingTokenID 等，取了身份 ≠ 做了校验）
#          → 单独标记 WEAK_VERIFY，避免漏报
#        特权操作词表按接口语义分组（安装/账号/配置/文件/执行），替换原文的宽泛单词匹配
#
# 输入格式（二选一）：
#   1. 目录：每个文件一个接口，文件名 <SA名>.<接口名>.txt（.txt 可省）
#   2. 单文件：用 `### SA名.接口名` 分隔符切分各接口
#
# 用法：
#   python3 interface_auditor.py <反编译导出目录> -o audit_report
#   python3 interface_auditor.py decompiled.txt

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict, field

# ---------- 校验特征（E12 两级） ----------

# 判定型：出现即认为「做了校验」（仍需人工确认逻辑正确性）
VERIFY_STRONG_PATTERNS = (
    r"VerifyAccessToken",
    r"VerifyPermission",
    r"PermissionCheck",
    r"CheckPermission",
    r"AccessTokenKit\s*::\s*Verify",
    r"IsSystemApp",
    r"CheckCallerIsSystemApp",
    r"VerifyCaller",
)

# 取值型：只取了调用方身份，未见到比较/判定逻辑——单独标记，不算已校验
VERIFY_WEAK_PATTERNS = (
    r"GetCallingUid",
    r"GetCallingPid",
    r"GetCallingTokenID",
    r"GetCallingDeviceID",
    r"IPCSkeleton\s*::\s*GetCalling",
    r"GetFirstCallerTokenID",
)

# ---------- 特权操作词表（按语义分组，E12） ----------

PRIVILEGED_OP_GROUPS = {
    "install":   (r"\b[Ss]ilentInstall\b", r"\bInstall[A-Z]\w*", r"\bUninstall\w*"),
    "account":   (r"resetPassword", r"\bManageAccount\w*", r"\bDelete[A-Z]\w*Account",
                  r"createAccount"),
    "permission": (r"\bGrant\w*Permission", r"\bRevoke\w*Permission",
                   r"grantRuntime", r"revokeRuntime"),
    "config":    (r"\bSetSystemParam\w*", r"\bSet[A-Z]\w*Config\b",
                  r"\bWriteSystemFile\w*"),
    "file":      (r"\bWriteFile\w*", r"\bReadData\w*", r"\b[A-Z]\w*Write\b"),
    "exec":      (r"\bExec\w*", r"\brunCommand\b", r"\bStartAbility[A-Z]\w*",
                  r"\bStartService\w*", r"\bshell\w*\("),
    "device":    (r"factoryReset", r"\bReboot\w*", r"\bWipe\w*", r"\bOta\w*Upgrade"),
}


@dataclass
class InterfaceAudit:
    sa: str
    interface: str
    verify: str          # STRONG / WEAK / NONE（E12：WEAK 与 NONE 区分）
    privileged_ops: list = field(default_factory=list)  # 命中的语义组名列表
    risk: str = ""       # HIGH / HIGH- / MEDIUM / LOW

    def __post_init__(self):
        if self.privileged_ops and self.verify == "NONE":
            self.risk = "HIGH"      # 特权操作 + 无任何校验特征 = 优先复核
        elif self.privileged_ops and self.verify == "WEAK":
            self.risk = "HIGH-"     # 取了身份但没判定 = 高疑，需看比较逻辑
        elif self.privileged_ops:
            self.risk = "MEDIUM"    # 有判定型校验，需人工确认校验正确性
        else:
            self.risk = "LOW"


def _match_any(patterns: tuple, text: str) -> bool:
    return any(re.search(p, text) for p in patterns)


def audit_interface(sa: str, interface: str, source_text: str) -> InterfaceAudit:
    """审计单个接口：校验分级 + 特权操作语义组命中"""
    if _match_any(VERIFY_STRONG_PATTERNS, source_text):
        verify = "STRONG"
    elif _match_any(VERIFY_WEAK_PATTERNS, source_text):
        verify = "WEAK"
    else:
        verify = "NONE"
    ops = [grp for grp, pats in PRIVILEGED_OP_GROUPS.items()
           if _match_any(pats, source_text)]
    return InterfaceAudit(sa=sa, interface=interface, verify=verify,
                          privileged_ops=ops)


# ---------- 输入解析 ----------

def load_interfaces(path: str) -> list:
    """
    返回 [(sa, interface, source_text), ...]
    目录 → 每文件一个接口（<sa>.<iface>.txt）；单文件 → ### sa.iface 分隔
    """
    items = []
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if name.startswith("."):
                continue
            stem = os.path.splitext(name)[0]
            if "." not in stem:
                continue  # 命名不符合 <sa>.<iface>，跳过
            sa, iface = stem.split(".", 1)
            with open(os.path.join(path, name), "r", encoding="utf-8",
                      errors="ignore") as f:
                items.append((sa, iface, f.read()))
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        current_key, buf = None, []
        for line in text.splitlines(keepends=True):
            m = re.match(r"^###\s*(\S+)\.(\S+)\s*$", line)
            if m:
                if current_key:
                    items.append((*current_key, "".join(buf)))
                current_key, buf = (m.group(1), m.group(2)), []
            else:
                buf.append(line)
        if current_key:
            items.append((*current_key, "".join(buf)))
    return items


def batch_audit(sa_interfaces: list) -> list:
    """批量审计并按风险排序（HIGH → HIGH- → MEDIUM → LOW）"""
    results = [audit_interface(sa, iface, src)
               for sa, iface, src in sa_interfaces]
    order = {"HIGH": 0, "HIGH-": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda x: order.get(x.risk, 9))
    return results


def main():
    ap = argparse.ArgumentParser(description="C1 无校验特权接口挖掘（半自动）")
    ap.add_argument("input", help="反编译导出目录或带 ### sa.iface 分隔的单文件")
    ap.add_argument("-o", "--output", help="报告输出路径（JSON），缺省打印到终端")
    args = ap.parse_args()

    interfaces = load_interfaces(args.input)
    if not interfaces:
        print("[!] 未解析到任何接口，请检查输入格式（目录内文件名 <sa>.<iface>.txt，"
              "或单文件内 ### sa.iface 分隔）")
        return 1

    results = batch_audit(interfaces)
    high = sum(1 for r in results if r.risk.startswith("HIGH"))
    print(f"[+] 审计 {len(results)} 个接口，HIGH 级（优先复核）{high} 个")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
        print(f"[+] 报告已写入 {args.output}")
    for r in results:
        flag = "★复核" if r.risk.startswith("HIGH") else " "
        print(f" {flag} [{r.risk}] {r.sa}.{r.interface} "
              f"verify={r.verify} privOps={r.privileged_ops}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
