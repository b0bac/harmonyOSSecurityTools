#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HarmonyOS DSoftBus (分布式软总线) 探测与指纹识别工具

在局域网内发现 HarmonyOS/OpenHarmony 设备，识别设备形态
(电视 / PC / 手机 / 平板)，输出带置信度的指纹报告。

技术栈 (全部基于网络协议，纯标准库实现):
  - DSoftBus 发现:  CoAP over UDP 5684, 资源 /.well-known/core
  - UPnP/SSDP:      UDP 1900, 抓 description.xml (识别电视)
  - ICMP/TTL:       区分 Windows(128) vs Linux/HarmonyOS(64)
  - TCP 端口:       SMB(445) / RDP(3389) / adb(5037)
  - 行为时序:       连续监测在线率 (区分常驻/休眠)

用法:
  python dsoftbus_scanner.py scan                  # 全网扫描 (默认)
  python dsoftbus_scanner.py scan --subnet 192.168.3.0/24
  python dsoftbus_scanner.py deep --ip 192.168.3.72
  python dsoftbus_scanner.py monitor --rounds 10 --interval 12
  python dsoftbus_scanner.py multicast
  python dsoftbus_scanner.py linktest --ip 192.168.3.72
  python dsoftbus_scanner.py export --format json

仅使用 Python 标准库，零依赖。
"""

import argparse
import io
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Windows 终端 UTF-8 输出
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass

# ============================================================
# 常量
# ============================================================
DSOFTBUS_PORTS = [5684, 5683]          # DSoftBus CoAP 端口
DSOFTBUS_MCAST = "224.0.0.14"          # DSoftBus 组播地址
SSDP_MCAST = "239.255.255.250"         # SSDP 组播地址
SSDP_PORT = 1900
WELL_KNOWN_CORE = ".well-known/core"

# CoAP 消息类型
COAP_CON = 0  # Confirmable
COAP_NON = 1  # Non-confirmable
COAP_ACK = 2  # Acknowledgement
COAP_RST = 3  # Reset

# CoAP 方法码
COAP_EMPTY = 0x00
COAP_GET = 0x01
COAP_POST = 0x02

# DSoftBus DEV_TYPE 枚举 (用于识别设备形态，未授权无法获取)
DEV_TYPES = {
    0: "UNKNOWN", 9: "PC", 10: "TV", 11: "SMART_DISPLAY",
    13: "AUDIO", 14: "PHONE", 15: "CAR", 17: "PAD",
    0x0C: "IPC", 0x83: "WATCH", 0x84: "CAR2",
}

# 关键 TCP 端口
TCP_PORTS = {
    22: "SSH", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS",
    445: "SMB", 3389: "RDP", 5037: "HDC/adb", 5555: "adb",
    5900: "VNC", 8000: "HTTP-Alt", 8001: "HTTP-Alt",
    8080: "HTTP-Alt", 7626: "TV-Cast", 9614: "TV-Cast",
    49152: "UPnP",
}

# ============================================================
# 终端颜色
# ============================================================
class C:
    R = "\033[31m"  # 红 - 离线/否定
    G = "\033[32m"  # 绿 - 铁证确认
    Y = "\033[33m"  # 黄 - 推断
    B = "\033[34m"  # 蓝 - 信息
    M = "\033[35m"  # 紫 - 强调
    C = "\033[36m"  # 青 - 次要
    B0 = "\033[1m"  # 加粗
    X = "\033[0m"   # 重置

def _color_enabled():
    return sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

if not _color_enabled():
    for _a in dir(C):
        if not _a.startswith("_") and isinstance(getattr(C, _a), str):
            setattr(C, _a, "")


# ============================================================
# 1. CoAP 协议层
# ============================================================
def coap_option(delta, length):
    """编码 CoAP Option 的 delta-length 字节"""
    d = min(delta, 12)
    l = min(length, 12)
    out = struct.pack("B", (d << 4) | l)
    if delta >= 13:
        out += struct.pack("B", delta - 13)
    if length >= 13:
        out += struct.pack("B", length - 13)
    return out


def coap_build(msg_type=COAP_CON, code=COAP_GET, mid=0x0001,
               uri_paths=None, payload=b"", token=b"", content_format=None):
    """
    构造一个 CoAP 数据包
    msg_type: COAP_CON / COAP_NON
    code: COAP_EMPTY(ping) / COAP_GET / COAP_POST
    uri_paths: list[str] 如 [".well-known", "core"] 或 ["device_discover"]
    """
    ver = 1
    tkl = len(token)
    header = (ver << 30) | (msg_type << 28) | (tkl << 24) | (code << 16) | (mid & 0xFFFF)
    pkt = struct.pack("!I", header) + token

    # Uri-Path option (编号 11)
    if uri_paths:
        for i, seg in enumerate(uri_paths):
            delta = 11 if i == 0 else 0
            data = seg.encode()
            pkt += coap_option(delta, len(data)) + data

    # Content-Format option (编号 12)
    if content_format is not None:
        pkt += coap_option(12, 1) + struct.pack("B", content_format)

    if payload:
        pkt += b"\xff" + payload
    return pkt


def coap_parse(data):
    """解析 CoAP 响应，返回 dict 或 None"""
    if not data or len(data) < 4:
        return None
    header = struct.unpack("!I", data[:4])[0]
    ver = (header >> 30) & 0x3
    t = (header >> 28) & 0x3
    tkl = (header >> 24) & 0xF
    code = (header >> 16) & 0xFF
    mid = header & 0xFFFF
    cclass = (code >> 5) & 0x7
    cdetail = code & 0x1F
    code_str = f"{cclass}.{cdetail:02d}"

    # 解析 options
    opts = []
    idx = 4 + tkl
    cur = 0
    while idx < len(data):
        b = data[idx]
        if b == 0xFF:
            idx += 1
            break
        d = (b >> 4) & 0xF
        l = b & 0xF
        idx += 1
        if d == 13:
            d = data[idx] + 13
            idx += 1
        if l == 13:
            l = data[idx] + 13
            idx += 1
        cur += d
        opts.append((cur, data[idx:idx + l]))
        idx += l

    payload = data[idx:] if idx < len(data) else b""
    return {
        "ver": ver, "type": t, "tkl": tkl,
        "code": code_str, "mid": mid,
        "opts": opts, "payload": payload, "raw": data.hex(),
    }


def coap_code_name(t):
    """CoAP type 数字 → 名称"""
    return {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}.get(t, str(t))


# ============================================================
# 2. 网络工具层
# ============================================================
def detect_platform():
    return "win" if sys.platform == "win32" else "nix"


def _decode_subprocess_output(raw):
    """健壮解码 subprocess 输出 (中文 Windows 是 GBK)"""
    for enc in ("utf-8", "gbk", "latin1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return raw.decode("utf-8", errors="replace")


def get_local_info():
    """获取本机 IP 和默认网段"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    # 推断 /24 网段
    parts = local_ip.split(".")
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "192.168.1.0/24"
    return local_ip, subnet


def ping_once(ip, timeout_ms=200):
    """单次 ping，返回 TTL 或 None"""
    plat = detect_platform()
    if plat == "win":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=3)
        txt = _decode_subprocess_output(r.stdout)
        m = re.search(r"[Tt][Tt][Ll][=:]?\s*(\d+)", txt)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None


def ping_sweep(subnet, concurrency=32, timeout_ms=200, progress_cb=None):
    """
    并发 ping 扫描整个网段
    返回 {ip: ttl}
    """
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    results = {}
    total = len(hosts)

    def _ping(ip):
        return ip, ping_once(ip, timeout_ms)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(_ping, ip): ip for ip in hosts}
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                ip, ttl = fut.result()
                if ttl is not None:
                    results[ip] = ttl
            except Exception:
                pass
            if progress_cb:
                progress_cb(done, total)
    return results


def arp_lookup():
    """读取 ARP 表，返回 {ip: mac}"""
    plat = detect_platform()
    cmd = ["arp", "-a"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=5)
    except Exception:
        return {}
    txt = _decode_subprocess_output(r.stdout)
    arp_map = {}
    for line in txt.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})", line)
        if m:
            ip = m.group(1)
            mac = m.group(2).replace(":", "-").upper()
            arp_map[ip] = mac
    return arp_map


def mac_is_random(mac):
    """判断 MAC 是否为本地管理地址 (随机化，隐私保护)"""
    if not mac or mac == "?":
        return False
    try:
        first = int(mac.split("-")[0], 16)
        return (first & 0x02) == 0x02
    except Exception:
        return False


def tcp_scan(ip, ports=None, timeout=0.8):
    """扫描 TCP 端口，返回 [open_port, ...]"""
    if ports is None:
        ports = list(TCP_PORTS.keys())
    open_ports = []

    def _scan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                return port
        except Exception:
            pass
        finally:
            s.close()
        return None

    with ThreadPoolExecutor(max_workers=16) as pool:
        for p in pool.map(_scan, ports):
            if p:
                open_ports.append(p)
    return sorted(open_ports)


def udp_send_recv(pkt, host, port, timeout=2.0, bind_port=0):
    """发送 UDP 包并等待响应，返回 (data, addr) 或 (None, None)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if bind_port:
            s.bind(("0.0.0.0", bind_port))
        s.sendto(pkt, (host, port))
        s.settimeout(timeout)
        data, addr = s.recvfrom(4096)
        return data, addr
    except (socket.timeout, OSError):
        return None, None
    finally:
        s.close()


# ============================================================
# 3. DSoftBus 探测层
# ============================================================
def probe_dsoftbus(ip, wake=True, timeout=2.5):
    """
    探测 DSoftBus 服务 (UDP 5684)
    wake: 是否先发唤醒包 (移动端 doze 时需唤醒)
    返回 dict: {is_dsoftbus, port, wkc, ping_resp}
    """
    result = {"is_dsoftbus": False, "port": None, "wkc": None, "ping_resp": None}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    try:
        # 唤醒: 连发 3 个 CoAP ping
        if wake:
            ping_pkt = coap_build(msg_type=COAP_CON, code=COAP_EMPTY, mid=0x0001)
            for _ in range(3):
                try:
                    s.sendto(ping_pkt, (ip, 5684))
                except OSError:
                    pass
                time.sleep(0.15)

        # 探测各端口
        for port in DSOFTBUS_PORTS:
            # CoAP ping
            data, _ = udp_send_recv_socket(s, coap_build(code=COAP_EMPTY, mid=0x0002), ip, port, 1.5)
            if not data:
                continue
            p = coap_parse(data)
            if not p:
                continue
            result["is_dsoftbus"] = True
            result["port"] = port
            result["ping_resp"] = f"type={coap_code_name(p['type'])} code={p['code']}"

            # GET /.well-known/core
            wkc_pkt = coap_build(code=COAP_GET, mid=0x0003,
                                 uri_paths=[".well-known", "core"])
            data2, _ = udp_send_recv_socket(s, wkc_pkt, ip, port, 2.0)
            if data2:
                p2 = coap_parse(data2)
                if p2 and p2["payload"]:
                    result["wkc"] = p2["payload"].decode("utf-8", "replace")
            break
    finally:
        s.close()
    return result


def udp_send_recv_socket(s, pkt, host, port, timeout=2.0):
    """用已有 socket 发收 UDP"""
    try:
        s.sendto(pkt, (host, port))
        s.settimeout(timeout)
        data, addr = s.recvfrom(4096)
        return data, addr
    except (socket.timeout, OSError):
        return None, None


def dsoftbus_is_confirmed(wkc):
    """检查 .well-known/core 是否包含 DSoftBus 特征路径"""
    if not wkc:
        return False
    markers = ["device_discover", "service_msg", "short_notification_message"]
    return any(m in wkc for m in markers)


# ============================================================
# 4. SSDP/UPnP 探测层 (识别电视的关键)
# ============================================================
def ssdp_probe(ip, timeout=3.0):
    """
    SSDP M-SEARCH 探测，返回 list[{location, server, description}]
    电视/智慧屏会返回 MediaRenderer 信息
    """
    sts = [
        "ssdp:all",
        "upnp:rootdevice",
        "urn:schemas-upnp-org:device:MediaRenderer:1",
        "urn:schemas-upnp-org:device:MediaServer:1",
        "urn:dial-multiscreen-org:service:dial:1",
        "urn:schemas-upnp-org:device:Basic:1",
    ]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    found = []
    seen = set()
    try:
        for st in sts:
            msg = (
                f"M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {SSDP_MCAST}:{SSDP_PORT}\r\n"
                f'MAN: "ssdp:discover"\r\n'
                f"MX: 2\r\n"
                f"ST: {st}\r\n\r\n"
            ).encode()
            try:
                s.sendto(msg, (ip, SSDP_PORT))
            except OSError:
                pass

        s.settimeout(timeout)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, _ = s.recvfrom(4096)
                txt = data.decode("latin1", "replace")
                loc = srv = None
                for line in txt.split("\r\n"):
                    ll = line.lower()
                    if ll.startswith("location:"):
                        loc = line.split(":", 1)[1].strip()
                    if ll.startswith("server:"):
                        srv = line.split(":", 1)[1].strip()
                key = (loc, srv)
                if key not in seen and (loc or srv):
                    seen.add(key)
                    found.append({"location": loc, "server": srv})
            except socket.timeout:
                break
            except OSError:
                break
    finally:
        s.close()
    return found


def fetch_upnp_description(location_url, timeout=3.0):
    """抓取 UPnP description.xml，返回关键字段 dict"""
    if not location_url:
        return None
    try:
        req = urllib.request.Request(location_url, headers={"User-Agent": "DSoftBusScanner/1.0"})
        data = urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
    except Exception:
        return None
    fields = {}
    for tag in ["friendlyName", "modelName", "manufacturer", "deviceType",
                "modelNumber", "UDN", "castService"]:
        m = re.search(rf"<{tag}>(.*?)</{tag}>", data)
        if m:
            fields[tag] = m.group(1)
    fields["_raw"] = data
    return fields


# ============================================================
# 5. 分析层: 综合指纹推断设备形态
# ============================================================
def load_known_devices(path=None):
    """加载已知设备库 {mac_upper: {form, note}}"""
    path = path or KNOWN_FILE
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 归一化 MAC 为大写连字符
        norm = {}
        for mac, info in data.items():
            norm[mac.upper().replace(":", "-")] = info
        return norm
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    except Exception:
        return {}


def save_known_device(mac, form, note="", path=None):
    """保存/更新一条已知设备"""
    path = path or KNOWN_FILE
    known = load_known_devices(path)
    known[mac.upper().replace(":", "-")] = {"form": form, "note": note}
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(known, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def classify(device, known_devices=None):
    """
    根据综合指纹推断设备形态
    device: dict 含 ttl, dsoftbus, wkc, ssdp, upnp_desc, tcp, mac
    known_devices: 已知设备库 {mac: {form, note}} (优先级最高)
    返回: {form, confidence, stars, evidence}
    form: TV / PC / PHONE / TABLET / MOBILE / WINDOWS / UNKNOWN
    confidence: 5(铁证) / 4(强) / 3(弱)
    """
    form = "UNKNOWN"
    confidence = 1
    evidence = []

    upnp = device.get("upnp_desc") or {}
    ssdp = device.get("ssdp") or []
    tcp = device.get("tcp") or []
    ttl = device.get("ttl")
    mac = device.get("mac", "")
    dsoftbus = device.get("dsoftbus", {})
    wkc = dsoftbus.get("wkc", "")

    # --- 规则 0: 已知设备库 (最高优先级，解决鸿蒙PC等自动识别不了的设备) ---
    if known_devices and mac and mac != "?":
        norm_mac = mac.upper().replace(":", "-")
        if norm_mac in known_devices:
            info = known_devices[norm_mac]
            known_form = info.get("form", "").upper()
            known_note = info.get("note", "")
            stars = "★" * 5 + "☆" * 0
            form_display = {
                "TV": "📺 电视", "PC": "💻 PC", "PHONE": "📱 手机",
                "TABLET": "📲 平板", "MOBILE": "📱 移动端",
            }.get(known_form, known_form)
            return {
                "form": known_form,
                "form_display": form_display,
                "confidence": 5,
                "stars": stars,
                "evidence": f"已知设备库标注{': ' + known_note if known_note else ''}",
            }

    # --- 规则 1: UPnP MediaRenderer → 电视/智慧屏 (铁证) ---
    dev_type = upnp.get("deviceType", "")
    friendly = upnp.get("friendlyName", "")
    model = upnp.get("modelName", "")
    if "MediaRenderer" in dev_type or ssdp:
        form = "TV"
        confidence = 5
        bits = []
        if friendly:
            bits.append(friendly)
        if model:
            bits.append(model)
        if "MediaRenderer" in dev_type:
            bits.append("MediaRenderer")
        evidence.append("UPnP: " + " / ".join(bits))
        if upnp.get("castService"):
            evidence.append(f"支持投屏(cast={upnp['castService']})")

    # --- 规则 2: TTL=128 → Windows ---
    if confidence < 5 and ttl and ttl >= 100:
        form = "WINDOWS"
        confidence = 3
        evidence.append(f"TTL={ttl} (Windows 内核)")
        if 445 in tcp or 139 in tcp:
            confidence = 4
            evidence.append("SMB 开放 (445/139)")

    # --- 规则 3: 445/3389 → Windows PC ---
    if confidence < 5 and (445 in tcp or 3389 in tcp or 139 in tcp):
        form = "PC"
        confidence = 4
        pc_ports = [f"{p}({TCP_PORTS.get(p, '')})" for p in [139, 445, 3389] if p in tcp]
        evidence.append("PC 端口: " + ", ".join(pc_ports))

    # --- 规则 4: DSoftBus + 仅 5684 + 无其他特征 → HarmonyOS 移动端/PC ---
    if confidence < 5 and dsoftbus.get("is_dsoftbus"):
        form = "MOBILE"
        confidence = 3
        if dsoftbus_is_confirmed(wkc):
            evidence.append("DSoftBus 确认 (device_discover/service_msg)")
        else:
            evidence.append("DSoftBus 端口响应")
        if mac_is_random(mac):
            evidence.append("随机 MAC (隐私)")
        if ttl and ttl <= 64:
            evidence.append(f"TTL={ttl} (Linux/HarmonyOS)")
        # 移动端调试端口
        if 5037 in tcp or 5555 in tcp:
            form = "PHONE"
            confidence = 4
            evidence.append("adb/HDC 端口开放")

    # --- 兜底 ---
    if not evidence:
        if ttl:
            evidence.append(f"TTL={ttl}")
        else:
            evidence.append("无特征")

    stars = "★" * confidence + "☆" * (5 - confidence)
    form_display = {
        "TV": "📺 电视",
        "PC": "💻 PC",
        "PHONE": "📱 手机",
        "TABLET": "📲 平板",
        "MOBILE": "📱 移动端",
        "WINDOWS": "🖥 Windows",
        "UNKNOWN": "❓ 未知",
    }.get(form, form)

    return {
        "form": form,
        "form_display": form_display,
        "confidence": confidence,
        "stars": stars,
        "evidence": "; ".join(evidence),
    }


# ============================================================
# 6. 输出层
# ============================================================
def print_banner(title):
    width = 64
    print(C.B + C.B0 + "=" * width + C.X)
    print(C.B + C.B0 + f"  {title}" + C.X)
    print(C.B + C.B0 + "=" * width + C.X)


def print_info(msg):
    print(f"{C.G}[+]{C.X} {msg}")


def print_warn(msg):
    print(f"{C.Y}[!]{C.X} {msg}")


def print_err(msg):
    print(f"{C.R}[-]{C.X} {msg}")


def fmt_confidence_color(c):
    if c >= 5:
        return C.G
    elif c >= 4:
        return C.Y
    else:
        return C.C


def print_device_table(devices):
    """打印设备结果表"""
    if not devices:
        print_warn("无设备")
        return
    print(f"\n{C.B0}{'IP':<16}{'MAC':<20}{'TTL':<5}{'DSoftBus':<10}{'形态':<14}{'置信':<12}依据{C.X}")
    print("-" * 100)
    for d in devices:
        ip = d["ip"]
        mac = d.get("mac", "?") or "?"
        ttl = str(d.get("ttl") or "-")
        ds = d.get("dsoftbus", {})
        ds_mark = f"{C.G}✓{C.X}" if ds.get("is_dsoftbus") else f"{C.R}✗{C.X}"
        cls = d.get("classify", {})
        form = cls.get("form_display", "?")
        stars = cls.get("stars", "")
        color = fmt_confidence_color(cls.get("confidence", 0))
        ev = cls.get("evidence", "")
        print(f"{ip:<16}{mac:<20}{ttl:<5}{ds_mark:<14}{color}{form:<12}{stars:<18}{C.X}{ev}")


# ============================================================
# 7. 子命令实现
# ============================================================
LAST_SCAN_RESULT = {"devices": [], "time": None}
REPORT_FILE_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dsoftbus_report.json")
REPORT_FILE_MD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dsoftbus_report.md")
KNOWN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dsoftbus_known.json")  # 已知设备库 (MAC→形态)


def full_scan_device(ip, ttl, arp_map, do_ssdp=True, do_tcp=True, known_devices=None):
    """对单台设备做完整指纹采集"""
    device = {"ip": ip, "ttl": ttl, "mac": arp_map.get(ip, "?")}

    # DSoftBus
    device["dsoftbus"] = probe_dsoftbus(ip, wake=True)

    # SSDP (电视识别关键)
    if do_ssdp:
        ssdp_res = ssdp_probe(ip, timeout=2.5)
        device["ssdp"] = ssdp_res
        device["upnp_desc"] = None
        for item in ssdp_res:
            if item.get("location"):
                desc = fetch_upnp_description(item["location"])
                if desc:
                    device["upnp_desc"] = desc
                    break
    else:
        device["ssdp"] = []
        device["upnp_desc"] = None

    # TCP 端口
    if do_tcp:
        device["tcp"] = tcp_scan(ip, timeout=0.7)
    else:
        device["tcp"] = []

    # 推断
    device["classify"] = classify(device, known_devices=known_devices)
    return device


def cmd_scan(args):
    """全网扫描 + 指纹识别"""
    local_ip, default_subnet = get_local_info()
    subnet = args.subnet or default_subnet

    print_banner(f"HarmonyOS DSoftBus 设备扫描  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"本机: {C.C}{local_ip}{C.X}  网段: {C.C}{subnet}{C.X}")

    # Ping sweep
    print_info(f"Ping sweep 中... (并发 {args.concurrency})")
    last_pct = -1

    def progress(done, total):
        nonlocal last_pct
        pct = done * 100 // total
        if pct >= last_pct + 10:
            last_pct = pct
            sys.stdout.write(f"\r{C.C}  扫描进度: {pct}% ({done}/{total}){C.X}    ")
            sys.stdout.flush()

    alive = ping_sweep(subnet, concurrency=args.concurrency, progress_cb=progress)
    sys.stdout.write("\r" + " " * 60 + "\r")
    print_info(f"存活主机 {C.G}{len(alive)}{C.X} 台: {', '.join(sorted(alive, key=lambda x: int(x.split('.')[-1])))}")

    # ARP
    arp_map = arp_lookup()

    # 已知设备库
    known_devices = load_known_devices()
    if known_devices:
        print_info(f"已知设备库: {C.C}{len(known_devices)}{C.X} 条标注 ({KNOWN_FILE})")

    # 逐台深度探测
    print_info("逐台采集指纹 (DSoftBus + SSDP + TCP)...")
    devices = []
    sorted_ips = sorted(alive.keys(), key=lambda x: int(x.split(".")[-1]))
    for ip in sorted_ips:
        sys.stdout.write(f"\r{C.C}  探测 {ip} ...{C.X}    ")
        sys.stdout.flush()
        try:
            d = full_scan_device(ip, alive[ip], arp_map, known_devices=known_devices)
            devices.append(d)
        except Exception as e:
            print_warn(f"{ip} 探测异常: {e}")
    sys.stdout.write("\r" + " " * 60 + "\r")

    # 排序: DSoftBus 设备优先, 然后按 IP
    devices.sort(key=lambda d: (not d["dsoftbus"].get("is_dsoftbus"),
                                int(d["ip"].split(".")[-1])))

    LAST_SCAN_RESULT["devices"] = devices
    LAST_SCAN_RESULT["time"] = datetime.now().isoformat()

    print_device_table(devices)

    # 统计
    ds_count = sum(1 for d in devices if d["dsoftbus"].get("is_dsoftbus"))
    tv_count = sum(1 for d in devices if d["classify"]["form"] == "TV")
    pc_count = sum(1 for d in devices if d["classify"]["form"] in ("PC", "WINDOWS"))
    mobile_count = sum(1 for d in devices if d["classify"]["form"] in ("MOBILE", "PHONE", "TABLET"))
    print(f"\n{C.B0}统计:{C.X} DSoftBus {C.G}{ds_count}{C.X} 台 | "
          f"电视 {C.G}{tv_count}{C.X} | PC {C.G}{pc_count}{C.X} | "
          f"移动端 {C.G}{mobile_count}{C.X}")

    # 自动保存 JSON
    try:
        save_report_json(devices)
        print_info(f"报告已保存: {C.C}{REPORT_FILE_JSON}{C.X}")
    except Exception as e:
        print_warn(f"保存报告失败: {e}")

    return devices


def cmd_deep(args):
    """单 IP 全协议深探"""
    ip = args.ip
    print_banner(f"深度探测 {ip}")
    local_ip, _ = get_local_info()
    print_info(f"本机: {local_ip}")

    # TTL 多次取样
    print_info("TTL 采样 (5 次)...")
    ttls = [ping_once(ip, 300) for _ in range(5)]
    ttls = [t for t in ttls if t]
    ttl = max(set(ttls), key=ttls.count) if ttls else None
    print(f"  TTL: {ttls} → 众数 {ttl}")

    arp_map = arp_lookup()
    mac = arp_map.get(ip, "?")
    print(f"  MAC: {mac}{' (随机化)' if mac_is_random(mac) else ''}")

    # DSoftBus
    print_info("DSoftBus (UDP 5684/5683)...")
    ds = probe_dsoftbus(ip, wake=True)
    if ds["is_dsoftbus"]:
        print(f"  {C.G}✓ 确认 DSoftBus{C.X} (端口 {ds['port']})")
        print(f"    Ping 响应: {ds['ping_resp']}")
        if ds["wkc"]:
            print(f"    /.well-known/core: {C.C}{ds['wkc']}{C.X}")
            if dsoftbus_is_confirmed(ds["wkc"]):
                print(f"    {C.G}>>> 含 device_discover/service_msg 特征 = OpenHarmony DSoftBus <<<{C.X}")
    else:
        print(f"  {C.R}✗ 无 DSoftBus 响应{C.X}")

    # SSDP
    print_info("SSDP/UPnP (UDP 1900)...")
    ssdp_res = ssdp_probe(ip)
    if ssdp_res:
        for item in ssdp_res:
            print(f"  {C.G}✓{C.X} SERVER: {item.get('server', '?')}")
            print(f"    LOCATION: {item.get('location', '?')}")
            if item.get("location"):
                desc = fetch_upnp_description(item["location"])
                if desc:
                    for k, v in desc.items():
                        if k != "_raw":
                            print(f"    {C.C}{k}{C.X}: {v}")
    else:
        print(f"  {C.R}✗ 无 SSDP 响应{C.X} (非电视/投屏接收端)")

    # TCP
    print_info("TCP 端口扫描...")
    tcp = tcp_scan(ip, timeout=0.8)
    if tcp:
        for p in tcp:
            print(f"  {C.G}✓{C.X} {p:<6} {TCP_PORTS.get(p, '')}")
    else:
        print(f"  {C.R}✗ 无开放端口{C.X}")

    # 尝试 DSoftBus 发现请求 (观察响应行为)
    print_info("DSoftBus 发现请求测试 (POST /device_discover)...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    try:
        if ds["is_dsoftbus"]:
            payloads = [
                ("最小", b'{"COAP_CMD_TYPE":0}'),
                ("带PKG", b'{"COAP_CMD_TYPE":0,"PKG_NAME":"com.nearby","DEVICE_ID":"0000000000000000"}'),
            ]
            for label, pl in payloads:
                pkt = coap_build(code=COAP_POST, mid=0x30,
                                 uri_paths=["device_discover"], payload=pl, content_format=50)
                data, _ = udp_send_recv_socket(s, pkt, ip, ds["port"] or 5684, 2.0)
                if data:
                    p = coap_parse(data)
                    if p:
                        print(f"  [{label}] → type={coap_code_name(p['type'])} code={p['code']} "
                              f"(payload {len(p['payload'])}B)")
                        note = {2: "ACK(收到)", 3: "RST(拒绝)"}.get(p["type"], "")
                        if note:
                            print(f"           {C.C}{note}{C.X}")
                else:
                    print(f"  [{label}] → (无响应)")
        else:
            print(f"  {C.C}(设备无 DSoftBus，跳过){C.X}")
    finally:
        s.close()

    # 综合推断
    device = {"ip": ip, "ttl": ttl, "mac": mac,
              "dsoftbus": ds, "ssdp": ssdp_res,
              "upnp_desc": fetch_upnp_description(ssdp_res[0]["location"]) if ssdp_res and ssdp_res[0].get("location") else None,
              "tcp": tcp}
    cls = classify(device)
    print_banner("推断结果")
    color = fmt_confidence_color(cls["confidence"])
    print(f"  形态: {color}{cls['form_display']}{C.X}")
    print(f"  置信: {cls['stars']}")
    print(f"  依据: {cls['evidence']}")
    if mac and mac != "?" and cls["confidence"] < 5:
        print(f"\n  {C.Y}提示:{C.X} 若已知此设备形态，可用以下命令标注:")
        print(f"  {C.C}python dsoftbus_scanner.py note --mac {mac} --form PC --note \"我的鸿蒙PC\"{C.X}")


def cmd_monitor(args):
    """稳定性监测: 区分常驻/休眠设备"""
    print_banner(f"DSoftBus 在线稳定性监测  {args.rounds} 轮 × {args.interval}s")
    targets = args.targets
    if not targets:
        # 自动发现 DSoftBus 设备
        print_info("未指定目标，先做快速扫描...")
        local_ip, subnet = get_local_info()
        alive = ping_sweep(subnet, concurrency=64)
        arp_map = arp_lookup()
        targets = []
        for ip in sorted(alive, key=lambda x: int(x.split(".")[-1])):
            ds = probe_dsoftbus(ip, wake=True, timeout=1.5)
            if ds["is_dsoftbus"]:
                targets.append(ip)
        if not targets:
            print_err("未发现 DSoftBus 设备")
            return
        print_info(f"目标: {', '.join(targets)}")

    def check(ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            pkt = coap_build(code=COAP_EMPTY, mid=0x0001)
            t0 = time.time()
            s.sendto(pkt, (ip, 5684))
            s.settimeout(1.5)
            try:
                s.recvfrom(128)
                return True, round((time.time() - t0) * 1000, 1)
            except (socket.timeout, OSError):
                return False, None
        finally:
            s.close()

    stats = {ip: [] for ip in targets}
    print(f"\n{C.B0}{'轮':<5}", end="")
    for ip in targets:
        print(f"{ip.split('.')[-1]:>8}", end="")
    print(f"{C.X}")
    print("-" * (5 + 8 * len(targets)))

    for r in range(args.rounds):
        print(f"{r+1:<5}", end="")
        for ip in targets:
            ok, ms = check(ip)
            stats[ip].append((ok, ms))
            if ok:
                print(f"{C.G}  ✓{ms:>5.0f}ms{C.X}", end="")
            else:
                print(f"{C.R}  ✗    {C.X}", end="")
        print()
        if r < args.rounds - 1:
            time.sleep(args.interval)

    # 统计
    print_banner("监测结论")
    print(f"{C.B0}{'IP':<16}{'在线率':<10}{'平均时延':<12}{'推断':<30}{C.X}")
    print("-" * 70)
    for ip in targets:
        data = stats[ip]
        hits = sum(1 for ok, _ in data if ok)
        rate = hits / len(data)
        mss = [ms for ok, ms in data if ok]
        avg = round(sum(mss) / len(mss), 1) if mss else None
        if rate >= 0.9:
            guess = f"{C.G}常驻 → PC/电视/亮屏设备{C.X}"
        elif rate >= 0.5:
            guess = f"{C.Y}半在线 → 平板?{C.X}"
        else:
            guess = f"{C.R}间歇 → 手机 (灭屏 doze){C.X}"
        avg_s = f"{avg}ms" if avg else "-"
        print(f"{ip:<16}{hits}/{len(data):<8}{avg_s:<12}{guess}")


def cmd_multicast(args):
    """组播发现: 向 DSoftBus 组播地址喊全网"""
    print_banner("DSoftBus 组播发现")
    local_ip, _ = get_local_info()
    print_info(f"本机: {local_ip}")
    print_info(f"向 {C.C}{DSOFTBUS_MCAST}{C.X} 发送组播 (UDP 5684)...")

    # 发送 CoAP GET 到组播地址
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 5684))
    ttl_val = 1
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_val)

    wkc_pkt = coap_build(code=COAP_GET, mid=0x1234,
                         uri_paths=[".well-known", "core"])
    ping_pkt = coap_build(code=COAP_EMPTY, mid=0x1235)

    try:
        # 连发 (唤醒 + 发现)
        for _ in range(3):
            s.sendto(ping_pkt, (DSOFTBUS_MCAST, 5684))
            time.sleep(0.1)
        s.sendto(wkc_pkt, (DSOFTBUS_MCAST, 5684))

        print_info("监听响应中 (10 秒)...")
        s.settimeout(10.0)
        end = time.time() + 10
        responses = {}
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
                ip = addr[0]
                p = coap_parse(data)
                if ip not in responses:
                    responses[ip] = []
                responses[ip].append({
                    "type": coap_code_name(p["type"]) if p else "?",
                    "code": p["code"] if p else "?",
                    "payload": p["payload"].decode("utf-8", "replace")[:80] if p and p["payload"] else "",
                })
            except socket.timeout:
                break
            except OSError:
                break
    finally:
        s.close()

    if not responses:
        print_warn("无组播响应 (设备可能屏蔽组播或休眠)")
        print_info(f"{C.C}提示: 组播发现在很多路由器上会被隔离 (IGMP snooping)，{C.X}")
        print_info(f"{C.C}      建议改用 {C.B0}scan{C.X}{C.C} 命令做单播扫描。{C.X}")
        return

    print_info(f"收到 {C.G}{len(responses)}{C.X} 台设备响应:")
    print(f"\n{C.B0}{'IP':<16}{'响应'}{C.X}")
    print("-" * 60)
    for ip, resps in sorted(responses.items(), key=lambda x: int(x[0].split(".")[-1])):
        summary = "; ".join(f"{r['type']}/{r['code']}" for r in resps[:3])
        print(f"{ip:<16}{C.C}{summary}{C.X}")
        for r in resps:
            if r["payload"]:
                print(f"{'':<16}{C.C}  payload: {r['payload']}{C.X}")


def cmd_linktest(args):
    """亮灭屏关联测试: 实时盯一个 IP，配合物理亮灭屏"""
    ip = args.ip
    print_banner(f"亮灭屏关联测试  目标 {ip}")
    print_info(f"实时监测 {ip}:5684 在线状态 (每 {args.interval}s 探一次)")
    print()
    print(f"  {C.Y}操作方法:{C.X}")
    print(f"  1. 现在观察基准状态")
    print(f"  2. {C.B0}灭屏{C.X}目标设备 → 观察本工具是否变 {C.R}离线{C.X}")
    print(f"  3. {C.B0}亮屏{C.X}目标设备 → 观察是否恢复 {C.G}在线{C.X}")
    print(f"  4. {C.B0}Ctrl+C{C.X} 退出")
    print()
    sys.stdout.flush()

    prev_state = None
    try:
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                pkt = coap_build(code=COAP_EMPTY, mid=0x0001)
                t0 = time.time()
                s.sendto(pkt, (ip, 5684))
                s.settimeout(1.5)
                try:
                    s.recvfrom(128)
                    ok, ms = True, round((time.time() - t0) * 1000)
                except (socket.timeout, OSError):
                    ok, ms = False, None
            finally:
                s.close()

            ts = datetime.now().strftime("%H:%M:%S")
            if ok:
                state_str = f"{C.G}在线{C.X} {ms:>4}ms"
            else:
                state_str = f"{C.R}离线{C.X}"
            # 状态变化提醒
            change = ""
            if prev_state is not None and ok != prev_state:
                if ok:
                    change = f"  {C.G}{C.B0}← 设备亮屏/唤醒!{C.X}"
                else:
                    change = f"  {C.R}{C.B0}← 设备灭屏/休眠!{C.X}"
            print(f"  [{ts}] {state_str}{change}")
            prev_state = ok
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!]{C.X} 已停止")


def cmd_export(args):
    """导出报告"""
    fmt = args.format
    if not LAST_SCAN_RESULT["devices"]:
        # 尝试读 JSON 文件
        if os.path.exists(REPORT_FILE_JSON):
            try:
                with open(REPORT_FILE_JSON, "r", encoding="utf-8") as f:
                    LAST_SCAN_RESULT["devices"] = json.load(f).get("devices", [])
            except Exception:
                pass
    if not LAST_SCAN_RESULT["devices"]:
        print_err("无扫描数据，请先运行 scan")
        return

    devices = LAST_SCAN_RESULT["devices"]
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if fmt == "json":
        with open(REPORT_FILE_JSON, "w", encoding="utf-8") as f:
            json.dump({"time": ts, "devices": devices}, f, ensure_ascii=False, indent=2)
        print_info(f"JSON 报告: {C.C}{REPORT_FILE_JSON}{C.X}")
    elif fmt == "md":
        lines = [
            f"# HarmonyOS DSoftBus 设备探测报告",
            f"",
            f"**生成时间**: {ts}",
            f"",
            f"## 设备清单",
            f"",
            f"| IP | MAC | TTL | DSoftBus | 形态 | 置信度 | 依据 |",
            f"|---|---|---|---|---|---|---|",
        ]
        for d in devices:
            cls = d.get("classify", {})
            lines.append(
                f"| {d['ip']} | {d.get('mac','?')} | {d.get('ttl','-')} | "
                f"{'✓' if d.get('dsoftbus',{}).get('is_dsoftbus') else '✗'} | "
                f"{cls.get('form_display','?')} | {cls.get('stars','')} | {cls.get('evidence','')} |"
            )
        lines.append("")
        with open(REPORT_FILE_MD, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print_info(f"Markdown 报告: {C.C}{REPORT_FILE_MD}{C.X}")


def save_report_json(devices):
    """自动保存 JSON 报告"""
    ts = datetime.now().isoformat()
    data = {"time": ts, "devices": devices}
    with open(REPORT_FILE_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def cmd_note(args):
    """标注已知设备 (MAC → 形态)，解决鸿蒙PC等自动识别不了的设备"""
    print_banner("已知设备库管理")
    mac = (args.mac or "").upper().replace(":", "-")

    if args.action == "add":
        if not args.form:
            print_err("add 需要 --form 参数 (TV/PC/PHONE/TABLET/MOBILE)")
            return
        if save_known_device(mac, args.form, args.note or ""):
            print_info(f"已保存: {C.C}{mac}{C.X} → {C.G}{args.form}{C.X}"
                       + (f" ({args.note})" if args.note else ""))
            print_info(f"库文件: {C.C}{KNOWN_FILE}{C.X}")
            print_info(f"{C.Y}下次 scan 将自动应用此标注 (置信度 ★★★★★){C.X}")
        else:
            print_err("保存失败")
    elif args.action == "list":
        known = load_known_devices()
        if not known:
            print_warn(f"已知设备库为空 ({KNOWN_FILE})")
            return
        print_info(f"已知设备库 ({len(known)} 条):")
        print(f"\n{C.B0}{'MAC':<20}{'形态':<10}备注{C.X}")
        print("-" * 50)
        for m, info in known.items():
            print(f"{m:<20}{C.G}{info.get('form','?'):<8}{C.X}{info.get('note','')}")
    elif args.action == "del":
        known = load_known_devices()
        if mac in known:
            del known[mac]
            try:
                with open(KNOWN_FILE, "w", encoding="utf-8") as f:
                    json.dump(known, f, ensure_ascii=False, indent=2)
                print_info(f"已删除: {mac}")
            except Exception:
                print_err("删除失败")
        else:
            print_warn(f"{mac} 不在库中")


# ============================================================
# 8. argparse 主入口
# ============================================================
def build_parser():
    parser = argparse.ArgumentParser(
        description="HarmonyOS DSoftBus 探测与指纹识别工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s scan                          # 全网扫描 (默认)
  %(prog)s scan --subnet 192.168.3.0/24  # 指定网段
  %(prog)s deep --ip 192.168.3.72        # 单 IP 全协议深探
  %(prog)s monitor --rounds 10           # 稳定性监测
  %(prog)s multicast                     # 组播发现
  %(prog)s linktest --ip 192.168.3.72    # 亮灭屏关联
  %(prog)s note add --mac 22-16-52-EE-F9-50 --form PC --note "鸿蒙PC"
  %(prog)s note list                     # 查看已知设备库
  %(prog)s export --format md            # 导出 Markdown 报告
""",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="全网扫描 + 指纹识别")
    p_scan.add_argument("--subnet", help="网段，如 192.168.3.0/24 (默认自动检测)")
    p_scan.add_argument("--concurrency", type=int, default=32, help="并发数 (默认 32)")
    p_scan.set_defaults(func=cmd_scan)

    # deep
    p_deep = sub.add_parser("deep", help="单 IP 全协议深探")
    p_deep.add_argument("--ip", required=True, help="目标 IP")
    p_deep.set_defaults(func=cmd_deep)

    # monitor
    p_mon = sub.add_parser("monitor", help="在线稳定性监测 (区分常驻/休眠)")
    p_mon.add_argument("--rounds", type=int, default=10, help="监测轮数 (默认 10)")
    p_mon.add_argument("--interval", type=int, default=12, help="间隔秒数 (默认 12)")
    p_mon.add_argument("--targets", nargs="+", help="目标 IP 列表 (默认自动发现)")
    p_mon.set_defaults(func=cmd_monitor)

    # multicast
    p_mc = sub.add_parser("multicast", help="组播发现 (喊全网休眠设备)")
    p_mc.set_defaults(func=cmd_multicast)

    # linktest
    p_link = sub.add_parser("linktest", help="亮灭屏关联测试 (实时盯 5684)")
    p_link.add_argument("--ip", required=True, help="目标 IP")
    p_link.add_argument("--interval", type=float, default=3.0, help="探测间隔秒 (默认 3)")
    p_link.set_defaults(func=cmd_linktest)

    # export
    p_exp = sub.add_parser("export", help="导出报告")
    p_exp.add_argument("--format", choices=["json", "md"], default="json", help="格式 (默认 json)")
    p_exp.set_defaults(func=cmd_export)

    # note
    p_note = sub.add_parser("note", help="管理已知设备库 (标注 MAC→形态, 解决鸿蒙PC自动识别问题)")
    p_note.add_argument("action", choices=["add", "list", "del"], help="add/list/del")
    p_note.add_argument("--mac", help="MAC 地址 (add/del 必填)")
    p_note.add_argument("--form", choices=["TV", "PC", "PHONE", "TABLET", "MOBILE"], help="设备形态 (add 必填)")
    p_note.add_argument("--note", help="备注 (如 '我的鸿蒙PC')")
    p_note.set_defaults(func=cmd_note)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        # 无子命令时默认 scan
        args = parser.parse_args(["scan"])
    try:
        args.func(args)
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!]{C.X} 已中断")
        sys.exit(130)
    except PermissionError as e:
        print_err(f"权限不足: {e}")
        print_info(f"{C.C}(UDP 5684 可能需要管理员权限，或被其他程序占用){C.X}")
        sys.exit(1)


if __name__ == "__main__":
    main()
