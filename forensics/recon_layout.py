#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_layout.py — HarmonyOS PC 设备数据布局探测(诊断 / 路径校准用)

为什么需要:PC 版 HarmonyOS 的 /data 布局与手机/嵌入式 OpenHarmony 不同。
(实测某机型 /data/service 下只有 el0/el1/hnp,无 el2;el1/public 下也无
 device_auth/huks。)这会让 sandbox_forensics / sensitive_collector /
trust_mapper 按默认路径扫到全空。

本脚本探测本机真实布局,输出"应用沙箱 / 信任数据 / 软总线运行状态"的真实位置,
作为校准 DEFAULT_ROOTS / TRUST_ROOTS 的依据。

  - 只读(ls/find/ps/netstat),不收集任何凭据值。
  - 顺带修复 scp 丢失的 *.sh 执行位。
  - 建议 sudo 运行以读全 /data 深处。

用法:
    sudo python3 recon_layout.py
    sudo python3 recon_layout.py --json        # 末尾追加机器可读 JSON(便于回传)
"""
import os
import re
import sys
import json
import glob
import subprocess

VERSION = "0.3"
TIMEOUT = 30


def sh(cmd):
    """跑 shell 命令取 stdout(超时/异常返回空串)"""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=TIMEOUT)
        return (p.stdout or "").strip()
    except Exception:
        return ""


def lines(s):
    return [l for l in s.splitlines() if l.strip()]


def bar(t):
    print(f"\n{'=' * 64}\n{t}\n{'=' * 64}")


def main():
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    print(f"recon_layout v{VERSION} | root={is_root} | 主机={sh('hostname') or '?'}")
    if not is_root:
        print("⚠ 非 root,/data 深处可能读不到。建议: sudo python3 recon_layout.py")

    # 顺带修复 scp 丢失的 .sh 执行位
    here = os.path.dirname(os.path.abspath(__file__))
    fixed = 0
    for f in glob.glob(os.path.join(here, "**", "*.sh"), recursive=True):
        try:
            os.chmod(f, 0o755)
            fixed += 1
        except Exception:
            pass
    if fixed:
        print(f"[+] 已修复 {fixed} 个 .sh 的执行位(chmod +x)")

    R = {"version": VERSION, "is_root": is_root, "data_layout": {},
         "app_sandbox": {}, "trust_softbus": {}, "runtime": {}}

    # ---- A. /data 布局 ----
    bar("A. /data 布局")
    layout = {}
    for p in ["/data", "/data/app", "/data/service", "/data/storage",
              "/data/storage/el2", "/data/storage/el1", "/data/storage/el4",
              "/data/service/el1/public", "/data/service/el0", "/data/misc"]:
        out = sh(f"ls -la {p} 2>/dev/null")
        print(f"\n-- {p} --\n{out or '(不存在/不可读)'}")
        layout[p] = lines(out)
    R["data_layout"] = layout

    # ---- B. 应用沙箱真实位置 ----
    bar("B. 应用沙箱候选(com.* / el2 / bundle 目录)")
    bundle = sh("find /data -maxdepth 5 -type d \\( -name 'com.*' -o -name 'el2' "
                "-o -iname '*bundle*' \\) 2>/dev/null | head -40")
    print(bundle or "(无)")
    print("\n-- .db 文件(前 40) --")
    dbs = sh("find /data -maxdepth 6 -name '*.db' 2>/dev/null | head -40")
    print(dbs or "(无)")
    bundle_dirs = lines(bundle)
    bundle_parents = sorted(set(
        os.path.dirname(l) for l in bundle_dirs
        if l.split("/")[-1].startswith("com.")))
    R["app_sandbox"] = {"bundle_dirs": bundle_dirs,
                        "bundle_parent_dirs": bundle_parents,
                        "db_files": lines(dbs)}

    # ---- C. 信任 / 软总线 / 密钥 ----
    bar("C. 信任 / 软总线 / 密钥 相关路径")
    trust = sh("find /data -maxdepth 7 \\( -iname '*softbus*' -o -iname '*device_auth*' "
               "-o -iname '*account*' -o -iname '*huks*' -o -iname '*trust*' "
               "-o -iname '*cred*' \\) 2>/dev/null | head -50")
    print(trust or "(无)")
    R["trust_softbus"] = {"paths": lines(trust)}

    # ---- D. 运行时:版本 / 进程 / 端口 / IP ----
    bar("D. 设备版本 / 软总线状态 / 网络")
    param = sh("ls /etc/param/ 2>/dev/null; head -30 /etc/param/*.param 2>/dev/null")
    print(f"-- /etc/param --\n{param or '(无)'}")
    ps_sb = sh("ps -ef | grep -iE 'softbus|distributed' | grep -v grep")
    print(f"-- softbus 进程 --\n{ps_sb or '(未发现)'}")
    port = sh("netstat -ulnp 2>/dev/null | grep -E ':5683|:5684'; "
              "ss -ulnp 2>/dev/null | grep -E '5683|5684'")
    print(f"-- 5683/5684 端口 --\n{port or '(未监听)'}")
    ipout = sh("ip -o -4 addr show 2>/dev/null || ifconfig 2>/dev/null")
    ips = [m.group(1)
           for m in re.finditer(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", ipout)
           if not m.group(1).startswith("127.")]
    print(f"-- 本机非回环 IP --\n{ips or '(无法获取)'}")
    R["runtime"] = {"param": lines(param), "softbus_running": bool(ps_sb),
                    "port_5683_5684_open": bool(port), "ips": ips}

    # ---- F. auth_groups 深挖(信任数据格式) ----
    bar("F. auth_groups 内部结构(信任数据格式探查)")
    ag = "/data/storage/el2/auth_groups"
    ag_dirs = lines(sh(f"ls -1 {ag} 2>/dev/null"))
    print(f"auth_groups 下 {len(ag_dirs)} 个应用组(抽样前 3 个看格式)")
    ag_detail = {}
    for b in ag_dirs[:3]:
        bp = os.path.join(ag, b)
        listing = sh(f"ls -la {bp} 2>/dev/null")
        files = lines(sh(f"find {bp} -maxdepth 3 -type f 2>/dev/null | head -20"))
        print(f"\n-- {bp} --\n{listing or '(空/不可读)'}")
        print("  内含文件:", files or "(无)")
        ag_detail[b] = files
    R["auth_groups_detail"] = ag_detail

    # ---- G. 设备版本指纹 ----
    bar("G. 设备版本指纹")
    version = {}
    for pf in ["build_info.para", "ohos.para", "hmos.para", "ohos_const"]:
        p = f"/etc/param/{pf}"
        content = sh(f"cat {p} 2>/dev/null | head -20")
        print(f"\n-- {p} --\n{content or '(无/不可读)'}")
        version[pf] = lines(content)
    R["version"] = version

    # ---- H. 所有 .db 的表与行数(Python sqlite3, 不依赖 sqlite3 CLI) ----
    bar("H. 所有 .db 的表与行数(Python sqlite3 直接查)")
    import sqlite3 as _sqlite3
    all_dbs = lines(sh("find /data/storage /data/service /data/local /data/global "
                        "/data/certificates -name '*.db' 2>/dev/null | head -60"))
    print(f"发现 {len(all_dbs)} 个 .db(逐个解析表)")
    db_tables = {}
    for db in all_dbs:
        tabs, err = [], None
        try:
            con = _sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            cur = con.cursor()
            for (t,) in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                try:
                    cnt = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                except Exception:
                    cnt = -1
                tabs.append(f"{t}({cnt}行)")
            con.close()
        except Exception as e:
            err = str(e)
        line = ", ".join(tabs) if tabs else (f"(打不开: {err})" if err else "(空库)")
        print(f"\n-- {db}\n   {line}")
        db_tables[db] = {"tables": tabs, "error": err}
    R["db_tables"] = db_tables

    # ---- I. 应用数据目录内容(按 el 层 / 数据类型, 判断是否加密/可取证) ----
    bar("I. 应用数据目录内容(el 层 × 数据类型)")
    data_sample = {}
    for el in ["el1", "el2", "el3", "el4"]:
        for sub in ["base", "database", "distributedfiles", "files", "cache", "log"]:
            d = f"/data/storage/{el}/{sub}"
            files = lines(sh(f"find {d} -maxdepth 4 -type f 2>/dev/null | head -12"))
            if files:
                print(f"\n-- {d} --")
                for f in files:
                    sz = sh(f"stat -c %s '{f}' 2>/dev/null || stat -f %z '{f}' 2>/dev/null")
                    print(f"   {f} ({sz or '?'}B)")
                data_sample[d] = files
    R["data_sample"] = data_sample

    # ---- J. 用户家目录凭据点(/storage/Users 等, 参考 Linux 取证 checklist)----
    bar("J. 用户家目录凭据点(/storage/Users 等, 参考 Linux 取证 checklist)")
    home_roots = ["/storage/Users", "/home", "/root"]
    # 与 sensitive_collector HOME_CRED_RELS 对齐的已知高价值 dot 文件/目录
    cred_dots = [".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
                 ".config", ".m2", ".gradle", ".terraform.d", ".gem",
                 ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".gitconfig",
                 ".my.cnf", ".pgpass", ".msmtprc", ".vault-token",
                 ".env", ".bashrc", ".zshrc", ".profile",
                 ".bash_history", ".zsh_history", ".mysql_history", ".psql_history"]
    home_cred = {}
    any_found = False
    for hr in home_roots:
        users = lines(sh(f"ls -1 {hr} 2>/dev/null"))
        if not users:
            continue
        print(f"\n-- {hr}/ ({len(users)} 个用户) --")
        for u in users[:10]:
            ud = f"{hr}/{u}"
            hits = [d for d in cred_dots if os.path.exists(f"{ud}/{d}")]
            if hits:
                any_found = True
                print(f"   {ud}/  发现 {len(hits)} 个凭据点")
                for dot in hits:
                    p = f"{ud}/{dot}"
                    tag = "目录" if os.path.isdir(p) else "文件"
                    print(f"      ⚠ {dot} [{tag}]")
                    if dot == ".ssh":
                        # 列出 .ssh 内所有文件(含 id_ed25519 / 改名私钥)
                        print("         ", sh(f"ls -la {p} 2>/dev/null")
                              .replace("\n", "\n          "))
            home_cred[ud] = hits
    if not any_found:
        print("(未发现家目录凭据点)")
    R["home_cred"] = home_cred

    # ---- E. 校准建议 ----
    bar("E. 校准建议(把本节或 --json 输出贴回,开发者据此调整扫描根)")
    if bundle_parents:
        print("★ 应用沙箱根候选 → sandbox_forensics / sensitive_collector 的 --root / DEFAULT_ROOTS:")
        for p in bundle_parents:
            print("   ", p)
    else:
        print("✗ /data 下未找到 com.* 应用目录 —— 应用数据可能不在 /data")
        print("  (补查: sudo find /home /opt /storage -maxdepth 4 -name 'com.*' 2>/dev/null)")
    if dbs:
        print(f"\n★ 发现 {len(lines(dbs))} 个 .db(示例,可能含应用数据):")
        for d in lines(dbs)[:8]:
            print("   ", d)
    if trust:
        print("\n★ 信任/软总线路径候选 → trust_mapper 的 --root / TRUST_ROOTS:")
        for t in lines(trust)[:15]:
            print("   ", t)
    else:
        print("\n✗ 未发现信任/软总线数据 → trust_mapper 在本机无数据(可能在他机或未启用)")
    if not ps_sb and not port:
        print("\n✗ 软总线未运行且未监听 5683/5684 → 本机不是 softbus 节点")
        print("  (vuln_mapper scan / proto_fuzzer 改从同网段主机对【他机】IP 跑)")
    print(f"\n本机 IP: {ips}  (主动探测工具的 --target 用同网段【对端】IP,不是本机)")

    if "--json" in sys.argv:
        print("\n" + json.dumps(R, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
