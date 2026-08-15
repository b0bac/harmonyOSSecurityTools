#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""svc_interface_audit.py  [T11 / C 层服务端接口校验覆盖审计（r2 驱动）]

固化第 9 轮对 libaccountmgr.z.so 的审计方法：不依赖源码/反编译导出产物，
直接对服务端 .so 做「命令级校验覆盖」量化。

方法（对应 test_log 第 9 轮，三个坑的规避已内置）：
  1. 权限字符串 + 校验类 PLT 全量 xref → 有校验函数集
     （绕开坑①：LLVM 内联使 PermissionCheck 符号零调用者；
       绕开坑②：C++ 虚表间接调用 blr 使直调图失效——用数据引用反查）
  2. 服务方法全集（afl 类名过滤）规范化（thunk 归并/排除 ctor 等）→ 差集
  3. --check ADDR 逐个复核疑点方法的传递校验（尾调用/Common 助手——坑③）

用法：
  python3 svc_interface_audit.py libaccountmgr.z.so -o c1_audit.json
  python3 svc_interface_audit.py libaccountmgr.z.so --check 0x000e0098   # 疑点复核
  python3 svc_interface_audit.py libaccountmgr.z.so --class OsAccountManagerService

依赖：radare2 在 PATH（r2）；目标 .so 未 strip 动态符号（服务库通常满足）。
授权：仅用于已授权设备安全测试。
"""
import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict

# 校验类 API 关键词（进程域取值类按 T4/E12 属 WEAK，单独标注）
STRONG_KW = ('VerifyPermission', 'VerifyAccessToken', 'VerifyNativeAccessToken',
             'CheckCallerIsSystemApp', 'VerifyAdminAuthPermission')
WEAK_KW = ('GetCallingUid', 'GetCallingPid', 'GetCallingTokenID',
           'GetCallingFullTokenID', 'IsSystemAppByFullTokenID', 'CheckSystemApp')
PERM_STR_PREFIX = ('ohos.permission.', 'constraint.')

R2_CMDS_HEAD = ['e scr.color=0', 'e bin.relocs.apply=true', 'e anal.timeout=900', 'aaa']


def r2_run(path, cmds):
    """跑一次 r2（脚本落临时文件——r2 在 macOS 上不吃 /dev/stdin 脚本），返回 stdout。"""
    import tempfile, os
    script = '\n'.join(R2_CMDS_HEAD + cmds) + '\nq\n'
    fd, sfile = tempfile.mkstemp(suffix='.r2')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        p = subprocess.run(['r2', '-q', '-i', sfile, path],
                           capture_output=True, text=True, timeout=1800)
        return p.stdout
    finally:
        os.unlink(sfile)


def parse_func_ref(line):
    """axt 输出行 → 函数名。返回 None 表示非函数引用。"""
    m = re.match(r'((?:method|sym|fcn)\.\S+)', line)
    return m.group(1) if m else None


def norm(name, want_class=None):
    """函数名规范化：剥前缀/thunk，归并重载到 类::方法（类名取最后命名空间段）。"""
    name = re.sub(r'^(method|sym|fcn)\.', '', name)
    for t in ('non_virtual_thunk_to_', 'virtual_thunk_to_'):
        name = name.replace(t, '')
    name = name.replace('OHOS::', '')
    m = re.match(r'([A-Za-z_][\w:]*?(?:Service|Manager|Stub))::([~\w]+)', name)
    if not m:
        return None
    cls, meth = m.group(1), m.group(2)
    cls = cls.split('::')[-1]  # 'AccountSA::OsAccountManagerService' → 'OsAccountManagerService'
    if meth.startswith('operator') or meth.startswith('_Z'):
        return None
    if want_class and cls != want_class:
        return None
    return f'{cls}::{meth}'


def collect(path, want_class=None):
    out = {}

    # ---- 1. 权限字符串地址 ----
    raw = r2_run(path, ['iz~+ohos.permission.', 'iz~+constraint.'])
    perm_addrs = sorted({m.group(1) for m in re.finditer(r'0x([0-9a-f]+)\s+\S+\s+0x\1', raw)})
    # iz 行格式：idx vaddr paddr len ... 稳妥取第二列
    perm_addrs = sorted({line.split()[1] for line in raw.splitlines()
                         if len(line.split()) > 4 and line.split()[1].startswith('0x')})

    # ---- 2. 校验类导入 PLT 地址（用 ii 导入表：is 会混入本地符号且地址列有占位）----
    raw = r2_run(path, ['ii~+Verify', 'ii~+Calling', 'ii~+IsSystemApp', 'ii~+CheckSystemApp'])
    plt = {}
    for line in raw.splitlines():
        m = re.search(r'(sym\.imp\.\S+)', line)
        if not m:
            continue
        name = m.group(1)
        am = re.search(r'0x[0-9a-f]+', line)
        if not am:
            continue
        addr = am.group(0)
        if any(k in name for k in STRONG_KW):
            plt[addr] = ('STRONG', name)
        elif any(k in name for k in WEAK_KW):
            plt[addr] = ('WEAK', name)

    # ---- 3. 全量 xref：字符串 + PLT → 校验函数集 ----
    verified = defaultdict(set)  # norm(func) -> {级别}
    cmds = []
    for a in perm_addrs:
        cmds.append(f'axt @ {a}')
    for a in plt:
        cmds.append(f'axt @ {a}')
    raw = r2_run(path, cmds)
    for line in raw.splitlines():
        fn = parse_func_ref(line)
        if not fn:
            continue
        n = norm(fn, want_class)
        if n:
            verified[n].add('STRONG')  # 字符串引用视为强信号（参与权限判定）

    # ---- 4. 服务方法全集 ----
    raw = r2_run(path, ['afl~Service', 'afl~Manager'])
    all_methods = set()
    for line in raw.splitlines():
        m = re.search(r'((?:method|sym|fcn)\.\S+)', line)
        if not m:
            continue
        n = norm(m.group(1), want_class)
        if n:
            all_methods.add(n)

    return perm_addrs, plt, verified, all_methods


def check_one(path, addr):
    """疑点复核：dump 函数内全部调用/跳转目标 + 权限字符串引用（防尾调用/助手坑）。"""
    raw = r2_run(path, [f'pdf @ {addr}'])
    calls, perms = [], []
    for line in raw.splitlines():
        for m in re.finditer(r'\b(?:bl|b)\s+(?:sym\.imp\.)?(\S+)', line):
            t = m.group(1).strip()
            if any(k in t for k in STRONG_KW + WEAK_KW) and 'cfi' not in t:
                calls.append(t[:120])
        for m in re.finditer(r'0x([0-9a-f]+)\s*;? *(str\.\S*ohos\.permission\.\S+|str\.\S*constraint\.\S+)', line):
            perms.append(m.group(2))
    return {'address': addr, 'verify_calls': sorted(set(calls)), 'permission_strings': sorted(set(perms)),
            'verdict': 'STRONG' if (calls or perms) else 'NONE(直接层)——继续查 Common 助手/尾调用目标'}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument('target', help='服务端 .so 路径')
    ap.add_argument('-o', '--output', help='JSON 报告输出路径')
    ap.add_argument('--class', dest='klass', help='只审计指定服务类（如 OsAccountManagerService）')
    ap.add_argument('--check', action='append', default=[], metavar='ADDR',
                    help='疑点方法地址复核（可多次）')
    args = ap.parse_args()

    subprocess.run(['r2', '-v'], capture_output=True, check=True)  # r2 存在性检查

    perm_addrs, plt, verified, all_methods = collect(args.target, args.klass)
    unverified = sorted(all_methods - set(verified))

    report = {
        'target': args.target,
        'permission_strings': len(perm_addrs),
        'verify_plts': {a: v for a, v in plt.items()},
        'methods_total': len(all_methods),
        'methods_verified': len(all_methods & set(verified)),
        'methods_unverified': unverified,
        'spot_checks': [check_one(args.target, a) for a in args.check],
        'caveats': [
            '差集=未【直接】触达校验 API；结论前必须对可疑项做传递性复核'
            '（内联/虚表间接调用/Common 助手三种假阴性来源，见 --check）',
            'WEAK 级（GetCallingUid 等）只证明取了调用方身份，不证明做了比较判定（T4/E12）',
        ],
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(text + '\n')
        print(f'报告已写入 {args.output}', file=sys.stderr)
    print(text)


if __name__ == '__main__':
    main()
