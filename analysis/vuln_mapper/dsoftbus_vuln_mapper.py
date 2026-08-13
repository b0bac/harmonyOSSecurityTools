#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dsoftbus_vuln_mapper.py — HarmonyOS DSoftBus 脆弱性映射器

把 cve_db 中的 CVE 知识库与现场设备联动,产出"资产 — 疑似受影响 CVE"报告。

三种用法:
  query  纯离线查询(不需网络):
         query --version "OpenHarmony v5.0.2-Release"   按版本查受影响 CVE
         query --cve CVE-2025-23409                      查单个 CVE 详情
         query --list                                    列出全部
  map    读取 dsoftbus_probe / DSoftBusScanner 的设备 JSON,做 CVE 映射:
         map --input devices.json
  scan   轻量 CoAP 发现局域网 DSoftBus 设备,再做映射(需与设备同网段):
         scan --subnet 255.255.255.255 --timeout 3

说明:host 侧通常拿不到设备的精确 OpenHarmony 版本,故 scan/map 产出的是
     "该设备运行 DSoftBus → 相关 CVE 全集 + 影响版本范围",最终研判靠人工
     对照设备实际版本。query 模式则是精确匹配。

依赖:Python 3.7+ 标准库(cve_db 与本程序同目录)。
仅用于授权安全测试 / 资产盘点。
"""
import argparse
import json
import os
import socket
import struct
import sys
import time
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cve_db
from cve_db import CVEEntry

# ---------------- CoAP / DSoftBus 常量 ----------------
DSOFTBUS_PORT = 5684
DISCOVER_URI = "device_discover"
BCAST = "255.255.255.255"

# 最小 device_discover payload(cJSON),字段尽量贴近 json_payload.h
DISCOVER_PAYLOAD = json.dumps({
    "deviceId": "vuln-mapper", "devicename": "vuln-mapper", "type": 0, "mode": 0,
    "hwAccountHash": "0", "authPort": 0, "capabilityBitmap": [], "business": 0,
    "bType": 0, "bData": "", "customData": "", "sessionKey": "",
    "serviceData": "", "extendServiceData": "", "seqNo": 1,
    "coapUri": "/device_discover",
}, separators=(",", ":")).encode()


# ---------------- CoAP 报文构造 ----------------
def _coap_option(delta: int, length: int) -> bytes:
    d = min(delta, 12)
    l = min(length, 12)
    out = struct.pack("B", (d << 4) | l)
    if delta >= 13:
        out += struct.pack("B", delta - 13)
    if length >= 13:
        out += struct.pack("B", length - 13)
    return out


def coap_build(msg_type: int = 1, code: int = 0x02, mid: int = 0x0001,
               uri_paths=None, payload: bytes = b"") -> bytes:
    """构造 CoAP 报文。msg_type:1=NON 2=ACK; code:0x02=POST。"""
    token = b""
    hdr = struct.pack("!BBH", (1 << 6) | (msg_type << 4) | len(token), code, mid)
    opts = b""
    delta = 0
    for p in uri_paths or []:
        opts += _coap_option(11 - delta, len(p)) + p.encode()  # Option 11 = Uri-Path
        delta = 11
    marker = b"\xFF" if payload else b""
    return hdr + token + opts + marker + payload


def parse_coap_response(data: bytes, src_ip: str) -> Dict[str, Any]:
    """从 CoAP 响应里分离并解析 cJSON payload。"""
    try:
        sep = data.index(b"\xff")
        body = data[sep + 1:]
    except ValueError:
        body = data[4:]
    try:
        obj = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return {"ip": src_ip, "raw": data[:64].hex()}
    obj["ip"] = src_ip
    return obj


def discover_devices(target: str = BCAST, timeout: float = 3.0,
                     port: int = DSOFTBUS_PORT) -> List[Dict[str, Any]]:
    """广播 device_discover,收集响应设备。"""
    pkt = coap_build(msg_type=1, code=0x02, mid=0x1234,
                     uri_paths=[DISCOVER_URI], payload=DISCOVER_PAYLOAD)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("", 0))
    s.sendto(pkt, (BCAST, port))
    deadline = time.time() + timeout
    seen: Dict[str, Dict[str, Any]] = {}
    s.settimeout(0.5)
    while time.time() < deadline:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        dev = parse_coap_response(data, addr[0])
        key = dev.get("deviceId") or addr[0]
        seen[key] = dev
    s.close()
    return list(seen.values())


# ---------------- 报告渲染 ----------------
def fmt_cve_line(e: CVEEntry) -> str:
    cvss = e.cvss if e.cvss is not None else "N/A"
    return (f"  • {e.cve} | {e.title} | CVSS {cvss} ({e.vector}) | "
            f"影响: {', '.join(e.affected)} | 修复: {e.fixed}")


def render_device_report(devices: List[Dict[str, Any]], as_json: bool = False):
    cves = cve_db.all_dsoftbus_cves()
    if as_json:
        return {"devices": devices, "dsoftbus_cves": cve_db.to_jsonable(cves),
                "note": "host侧无法精确判版本,请对照设备实际OH版本研判affected字段"}
    lines = [f"发现 {len(devices)} 台 DSoftBus 设备:"]
    for d in devices:
        name = d.get("devicename") or d.get("deviceName") or "?"
        did = d.get("deviceId") or "?"
        lines.append(f"  - {name}  (id={did}, ip={d.get('ip', '?')})")
    lines.append("")
    lines.append("当前已知 DSoftBus 相关 CVE(请对照设备实际版本研判):")
    for e in cves:
        lines.append(fmt_cve_line(e))
    lines.append("")
    lines.append("提示: 若设备版本落在某 CVE 的 affected 区间即判定受影响。"
                 "可用 `query --version <版本名>` 精确查询。")
    return "\n".join(lines)


def render_version_report(version: str, as_json: bool = False):
    cves = cve_db.cves_for_version(version)
    if as_json:
        return {"version": version, "matched_cves": cve_db.to_jsonable(cves)}
    if not cves:
        return (f"版本 {version}: 库内无匹配的 DSoftBus CVE"
                f"(可能不受影响,或版本名需精确到 Release 全称)。")
    lines = [f"版本 {version} 受影响的 DSoftBus CVE({len(cves)} 条):"]
    for e in cves:
        lines.append(fmt_cve_line(e))
    return "\n".join(lines)


def render_cve_detail(cve_id: str, as_json: bool = False):
    e = cve_db.get_cve(cve_id)
    if not e:
        return f"未找到 {cve_id}"
    if as_json:
        return cve_db.to_jsonable([e])[0]
    return "\n".join([
        f"CVE 详情: {e.cve}",
        f"  组件: {e.component}",
        f"  类型: {e.title}",
        f"  向量: {e.vector}  CVSS: {e.cvss} ({e.cvss_source})",
        f"  影响: {', '.join(e.affected)}",
        f"  修复: {e.fixed}",
        f"  公告: {e.bulletin}",
        f"  说明: {e.desc}",
        f"  DSoftBus相关: {'是' if e.related_dsoftbus else '否(订正)'}",
    ])


def render_list(as_json: bool = False):
    cves = cve_db.DSOFTBUS_CVES
    if as_json:
        return cve_db.to_jsonable(cves)
    lines = [f"库内 CVE 共 {len(cves)} 条(DSoftBus相关 {len(cve_db.all_dsoftbus_cves())}):"]
    for e in cves:
        lines.append(fmt_cve_line(e))
    return "\n".join(lines)


def load_devices(path: str) -> List[Dict[str, Any]]:
    """兼容 dsoftbus_probe / DSoftBusScanner 的 JSON 输出(list 或 {devices:[...]})。"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("devices", "result", "items"):
            if k in data and isinstance(data[k], list):
                return data[k]
        return [data]
    return []


def emit(out, as_json: bool):
    if as_json and not isinstance(out, str):
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(out)


def main():
    ap = argparse.ArgumentParser(description="HarmonyOS DSoftBus 脆弱性映射器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pq = sub.add_parser("query", help="离线查询 CVE 库")
    pq.add_argument("--version", help="按 OpenHarmony 版本查(如 'OpenHarmony v5.0.2-Release')")
    pq.add_argument("--cve", help="按 CVE 编号查详情")
    pq.add_argument("--list", action="store_true", help="列出全部")

    pm = sub.add_parser("map", help="读设备 JSON 做 CVE 映射")
    pm.add_argument("--input", required=True, help="probe/scanner 的设备 JSON 文件")

    ps = sub.add_parser("scan", help="轻量 CoAP 发现 + 映射")
    ps.add_argument("--subnet", default=BCAST, help="广播地址(默认 255.255.255.255)")
    ps.add_argument("--timeout", type=float, default=3.0, help="发现超时秒")

    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    if args.cmd == "query":
        if args.cve:
            out = render_cve_detail(args.cve, args.json)
        elif args.version:
            out = render_version_report(args.version, args.json)
        else:
            out = render_list(args.json)
        emit(out, args.json)
    elif args.cmd == "map":
        devs = load_devices(args.input)
        emit(render_device_report(devs, args.json), args.json)
    elif args.cmd == "scan":
        print(f"[*] 扫描 {args.subnet}(超时 {args.timeout}s)...", file=sys.stderr)
        devs = discover_devices(args.subnet, args.timeout)
        emit(render_device_report(devs, args.json), args.json)


if __name__ == "__main__":
    main()
