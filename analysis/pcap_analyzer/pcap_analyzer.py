#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_analyzer.py — HarmonyOS DSoftBus(分布式软总线)PCAP 深度分析器

读取抓包文件(.pcap / .pcapng), 离线解析软总线相关流量:
  - CoAP over UDP(5683/5684)设备发现(device_discover)
  - 从 cJSON payload 提取 deviceId / devicename / type / mode 等明文字段
  - 设备清单 + 发现事件时间线 + 明文敏感字段告警
  - 若发现版本字段, 提示联动 vuln_mapper 核对受影响 CVE

纯标准库(不依赖 scapy), macOS / Linux 自带 python3 即可运行。
支持链路层: Ethernet(1) / Linux-SLL(113) / Raw-IP(228,101)。

用法:
    python3 pcap_analyzer.py capture.pcap
    python3 pcap_analyzer.py capture.pcapng --json
    python3 pcap_analyzer.py capture.pcap --devices        # 仅打印设备清单

仅用于授权安全测试 / 流量审计。离线分析, 不联网、不触碰网络。
"""
import os
import sys
import json
import re
import struct
import socket
import argparse
from collections import OrderedDict

VERSION = "0.1"

# CoAP / CoAPS 端口
COAP_PORTS = {5683, 5684}
# Uri-Path 含这些片段视为软总线设备发现
DISCOVER_HINTS = ("discover", "deviceauth", "softbus")
# 视为敏感明文字段的 payload 键
SENS_KEYS = ("deviceId", "devicename", "deviceName", "hicomname",
             "deviceType", "accountid", "uuid", "sessionKey", "token")
# 视为版本指纹的键
VERSION_KEYS = ("version", "softbusVersion", "ohVersion", "osVersion",
                "devicetype")  # devicetype 常含型号+版本混合


# ---------------------------------------------------------------------------
# pcap / pcapng 读取 -> 迭代 (ts, link_type, raw_bytes)
# ---------------------------------------------------------------------------
def read_packets(data: bytes):
    """自动识别 pcap/pcapng, yield (ts, link_type, raw)"""
    if len(data) < 4:
        raise ValueError("文件过小, 不是合法抓包文件")
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0x0A0D0D0A:
        yield from _read_pcapng(data)
    elif magic in (0xA1B2C3D4, 0xA1B23C4D, 0xD4C3B2A1, 0x4D3CB2A1):
        yield from _read_pcap(data, magic)
    else:
        raise ValueError(f"未知文件 magic: {magic:#010x}(非 pcap/pcapng)")


def _read_pcap(data: bytes, magic: int):
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
        ns = magic == 0xA1B23C4D
    else:
        endian = ">"
        ns = magic == 0x4D3CB2A1
    # 全局头 24B: magic ver(2x2) zone sigfigs snaplen network
    gh = struct.unpack(endian + "IHHIIII", data[:24])
    link_type = gh[6]
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII",
                                                     data[off:off + 16])
        off += 16
        if off + incl > n:
            break
        pkt = data[off:off + incl]
        off += incl
        ts = ts_sec + (ts_frac / 1e9 if ns else ts_frac / 1e6)
        yield ts, link_type, pkt


def _read_pcapng(data: bytes):
    endian = "<"
    off = 0
    n = len(data)
    iface_link = {}  # iface_id -> link_type
    iface_order = []
    while off + 8 <= n:
        bt = struct.unpack(endian + "I", data[off:off + 4])[0]
        bl = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        if bl < 12 or off + bl > n:
            break
        body = data[off + 8:off + bl - 4]
        if bt == 0x0A0D0D0A:  # Section Header Block —— 检测字节序
            bom = struct.unpack("<I", body[:4])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            bl = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
            body = data[off + 8:off + bl - 4]
        elif bt == 0x00000001:  # Interface Description Block
            lt = struct.unpack(endian + "H", body[:2])[0]
            iface_link[len(iface_order)] = lt
            iface_order.append(lt)
        elif bt == 0x00000006:  # Enhanced Packet Block
            iface_id, ts_hi, ts_lo, incl = struct.unpack(
                endian + "IIII", body[:16])
            pkt = body[16:16 + incl]
            ts = (ts_hi * 4294967296 + ts_lo) / 1e6
            yield ts, iface_link.get(iface_id, 1), pkt
        elif bt == 0x00000003:  # Simple Packet Block
            yield 0.0, iface_link.get(0, 1), body
        off += bl


# ---------------------------------------------------------------------------
# 链路层 -> IPv4/IPv6 -> UDP -> (src,dst,sport,dport,payload)
# ---------------------------------------------------------------------------
def extract_udp(raw: bytes, link_type: int):
    """返回 (src, dst, sport, dport, udp_payload) 或 None"""
    off = 0
    if link_type == 1:                       # Ethernet
        if len(raw) < 14:
            return None
        etype = struct.unpack("!H", raw[12:14])[0]
        off = 14
        while etype == 0x8100 and off + 4 <= len(raw):  # VLAN tag
            etype = struct.unpack("!H", raw[off + 2:off + 4])[0]
            off += 4
    elif link_type == 113:                   # Linux cooked capture (SLL)
        if len(raw) < 16:
            return None
        etype = struct.unpack("!H", raw[14:16])[0]
        off = 16
    elif link_type in (228, 101, 12):        # raw IP
        off = 0
    else:
        return None

    if len(raw) < off + 1:
        return None
    ver = raw[off] >> 4
    if ver == 4:
        return _ipv4_udp(raw, off)
    if ver == 6:
        return _ipv6_udp(raw, off)
    return None


def _ipv4_udp(raw, off):
    if len(raw) < off + 20:
        return None
    ihl = (raw[off] & 0x0F) * 4
    proto = raw[off + 9]
    if proto != 17:
        return None
    src = ".".join(str(b) for b in raw[off + 12:off + 16])
    dst = ".".join(str(b) for b in raw[off + 16:off + 20])
    u = off + ihl
    if len(raw) < u + 8:
        return None
    sport, dport, _len, _cs = struct.unpack("!HHHH", raw[u:u + 8])
    return src, dst, sport, dport, raw[u + 8:]


def _ipv6_udp(raw, off):
    if len(raw) < off + 40:
        return None
    nxt = raw[off + 6]
    if nxt != 17:
        return None
    src = socket.inet_ntop(socket.AF_INET6, raw[off + 8:off + 24])
    dst = socket.inet_ntop(socket.AF_INET6, raw[off + 24:off + 40])
    u = off + 40
    if len(raw) < u + 8:
        return None
    sport, dport, _len, _cs = struct.unpack("!HHHH", raw[u:u + 8])
    return src, dst, sport, dport, raw[u + 8:]


# ---------------------------------------------------------------------------
# CoAP 解析(请求/响应通用)
# ---------------------------------------------------------------------------
def _code_str(code):
    return f"{code >> 5}.{code & 0x1F}"


def parse_coap(payload: bytes):
    """返回 dict{ver,type,tkl,code,mid,uri_paths,options,payload} 或 None"""
    if len(payload) < 4:
        return None
    b0 = payload[0]
    ver = (b0 >> 6) & 0x03
    if ver != 1:                 # CoAP 版本必为 1
        return None
    mtype = (b0 >> 4) & 0x03
    tkl = b0 & 0x0F
    code = payload[1]
    mid = struct.unpack("!H", payload[2:4])[0]
    off = 4 + tkl
    if off > len(payload):
        return None
    options = []
    cur = 0
    while off < len(payload):
        b = payload[off]
        if b == 0xFF:            # payload marker
            off += 1
            break
        d = (b >> 4) & 0x0F
        ln = b & 0x0F
        off += 1
        try:
            if d == 13:                       # RFC7252: 实际值 = ext + 13
                d = payload[off] + 13; off += 1
            elif d == 14:                     # 实际值 = ext + 269
                d = struct.unpack("!H", payload[off:off + 2])[0] + 269; off += 2
            elif d == 15:
                return None
            if ln == 13:
                ln = payload[off] + 13; off += 1
            elif ln == 14:
                ln = struct.unpack("!H", payload[off:off + 2])[0] + 269; off += 2
            elif ln == 15:
                return None
        except IndexError:
            return None
        cur += d
        val = payload[off:off + ln]
        off += ln
        options.append((cur, val))
    coap_payload = payload[off:] if off <= len(payload) else b""
    uri_paths = [v.decode("utf-8", "replace") for num, v in options if num == 11]
    return {"type": mtype, "code": code, "mid": mid,
            "uri_paths": uri_paths, "options": options,
            "payload": coap_payload}


def _looks_coap(payload: bytes):
    return len(payload) >= 4 and (payload[0] >> 6) == 1


# ---------------------------------------------------------------------------
# device_discover payload 解析
# ---------------------------------------------------------------------------
def extract_device_info(coap):
    """从 CoAP payload 提取设备信息 dict; 非法/无则 None"""
    p = coap.get("payload") or b""
    if not p:
        return None
    text = p.decode("utf-8", "replace")
    # 优先 JSON
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    # 降级: 正则提取已知键
    info = {}
    for key in set(SENS_KEYS) | set(VERSION_KEYS) | {"type", "mode"}:
        # key 引号可选, 容错非严格 cJSON
        m = re.search(r'"?%s"?\s*:\s*"([^"]*)"' % re.escape(key), text)
        if m:
            info[key] = m.group(1)
    return info or None


# ---------------------------------------------------------------------------
# 主分析
# ---------------------------------------------------------------------------
def analyze(path):
    with open(path, "rb") as f:
        data = f.read()

    devices = OrderedDict()      # key -> info
    events = []
    stats = {"total": 0, "udp": 0, "coap": 0, "discovery": 0,
             "ports": {}, "plaintext_fields": []}
    plaintext_seen = set()

    for ts, lt, raw in read_packets(data):
        stats["total"] += 1
        u = extract_udp(raw, lt)
        if not u:
            continue
        stats["udp"] += 1
        src, dst, sport, dport, payload = u
        stats["ports"][dport] = stats["ports"].get(dport, 0) + 1
        coap = None
        on_coap_port = sport in COAP_PORTS or dport in COAP_PORTS
        if on_coap_port or _looks_coap(payload):
            coap = parse_coap(payload)
        # 非CoAP端口的启发式命中: 要求至少有 uri 或 payload, 否则视为噪声丢弃
        if coap and not on_coap_port and not coap["uri_paths"] and not coap["payload"]:
            coap = None
        if not coap:
            continue
        stats["coap"] += 1
        uri = "/".join(coap["uri_paths"])
        is_disc = any(h in uri.lower() for h in DISCOVER_HINTS)
        if is_disc:
            stats["discovery"] += 1
        info = extract_device_info(coap) if coap.get("payload") else None

        # 明文敏感字段告警(去重)
        if info:
            for k in SENS_KEYS:
                if k in info:
                    sig = (src, k)
                    if sig not in plaintext_seen:
                        plaintext_seen.add(sig)
                        stats["plaintext_fields"].append(
                            {"src": src, "field": k, "value": info[k]})
            # 设备聚合
            dev_id = (info.get("deviceId") or info.get("devicename")
                      or info.get("uuid") or src)
            rec = devices.setdefault(dev_id, OrderedDict())
            rec["key"] = dev_id
            rec.setdefault("first_seen", ts)
            rec["last_seen"] = ts
            rec.setdefault("src_ips", set()).add(src)
            rec.setdefault("events", 0)
            rec["events"] += 1
            for k, v in info.items():
                rec[k] = v

        if is_disc or info:
            events.append(OrderedDict([
                ("ts", round(ts, 6)), ("src", src), ("dst", dst),
                ("sport", sport), ("dport", dport),
                ("code", _code_str(coap["code"])), ("uri", uri),
                ("discovery", is_disc), ("info", info),
            ]))

    return {"devices": devices, "events": events, "stats": stats}


# ---------------------------------------------------------------------------
# 报告渲染
# ---------------------------------------------------------------------------
def _set2list(d):
    """把 info 里的 set 序列化(只处理 devices 顶层)"""
    out = OrderedDict()
    for k, v in d.items():
        out[k] = sorted(v) if isinstance(v, set) else v
    return out


def render_text(result):
    lines = []
    st = result["stats"]
    lines.append(f"[+] DSoftBus PCAP 分析 v{VERSION}")
    lines.append(f"    总包数 {st['total']} | UDP {st['udp']} | "
                 f"CoAP {st['coap']} | 设备发现 {st['discovery']}")
    if st["ports"]:
        top = sorted(st["ports"].items(), key=lambda x: -x[1])[:8]
        lines.append("    目的端口 TOP: " + ", ".join(f"{p}:{c}" for p, c in top))

    devs = result["devices"]
    lines.append(f"\n[+] 设备清单({len(devs)} 个)")
    if not devs:
        lines.append("    (未发现软总线设备发现流量)")
    for d in devs.values():
        name = d.get("devicename") or d.get("hicomname") or "?"
        dtype = d.get("type") or d.get("deviceType") or "?"
        ips = ",".join(sorted(d.get("src_ips", set()))) or "?"
        lines.append(f"    - {name} [{dtype}] {d['key']}")
        lines.append(f"        IP {ips} | 事件 {d.get('events',0)} | "
                     f"首见 {d.get('first_seen'):.2f}")
        ver = next((d[k] for k in VERSION_KEYS if k in d), None)
        if ver:
            lines.append(f"        版本字段: {ver}  -> 可联动 "
                         "vuln_mapper query --version <版本>")

    pf = st["plaintext_fields"]
    lines.append(f"\n[!] 明文敏感字段告警({len(pf)})")
    if pf:
        for x in pf:
            lines.append(f"    - {x['src']}  {x['field']} = {x['value']}")
    else:
        lines.append("    (未发现明文敏感字段)")

    ev = result["events"]
    lines.append(f"\n[+] 发现事件时间线({len(ev)})")
    for e in ev[:20]:
        tag = "DISC" if e["discovery"] else "DATA"
        lines.append(f"    {e['ts']:.3f} {e['src']} -> {e['dst']}"
                     f":{e['dport']} [{e['code']}] /{e['uri']} ({tag})")
    if len(ev) > 20:
        lines.append(f"    ... 还有 {len(ev) - 20} 条(用 --json 查看全部)")

    return "\n".join(lines)


def render_json(result):
    devs = [_set2list(d) for d in result["devices"].values()]
    return json.dumps({"version": VERSION, "stats": result["stats"],
                       "devices": devs, "events": result["events"]},
                      ensure_ascii=False, indent=2)


def main():
    ap = argparse.ArgumentParser(description="HarmonyOS DSoftBus PCAP 深度分析器")
    ap.add_argument("pcap", help="抓包文件 .pcap / .pcapng")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--devices", action="store_true", help="仅打印设备清单")
    args = ap.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"文件不存在: {args.pcap}", file=sys.stderr)
        sys.exit(1)
    try:
        result = analyze(args.pcap)
    except Exception as e:
        print(f"分析失败: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(render_json(result))
    elif args.devices:
        for d in result["devices"].values():
            name = d.get("devicename") or d.get("hicomname") or d["key"]
            print(f"{name}\t{d.get('type','?')}\t"
                  f"{','.join(sorted(d.get('src_ips',set())))}")
    else:
        print(render_text(result))


if __name__ == "__main__":
    main()
