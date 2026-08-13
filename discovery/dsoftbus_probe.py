#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dsoftbus_probe.py — HarmonyOS NEXT (PC) DSoftBus 设备发现探测工具

基础功能（默认，纯标准库）：
  scan   主动探测：构造 CoAP POST device_discover 报文，向局域网广播 / 定向
         目标发送，收集响应设备画像。
  sniff  被动监听：优先 scapy 深度嗅探 UDP/5684 全部流量，无 scapy/无权限时
         自动降级为 socket 绑定 5684 接收广播。

可选功能（参数启用）：
  --device-name/--device-type/--capability/--device-id/--service-data/--mode
         scan 伪装：自定义探测报文中的本机设备字段。
  --pcap PATH
         pcap 落盘：把捕获的 UDP/5684 报文合成 Ether+IPv4+UDP 帧写入 pcap，
         可用 Wireshark 直接打开分析。
  --ble / ble 子命令
         BLE 通道被动扫描：用 bleak 监听 BLE 广播，按 HarmonyOS 软总线 TLV
         格式 + 华为蓝牙 SIG company id(0x01D6) 识别并解析设备。
  nan 子命令
         WiFi Aware(NAN) 通道：PC 上无成熟跨平台 Python 实现，给出可行性说明。

协议依据（OpenHarmony communication_dsoftbus 源码）：
  * coap_app.h        : COAP_SRV_DEFAULT_PORT="5684"  COAP_SRV_DEFAULT_ADDR="0.0.0.0"
  * coap_discover.c   : 发现报文 = CoAP POST, URI-Path="device_discover",
                        广播 NON / 单播响应用 CON/ACK
  * json_payload.h    : CoAP payload 为 cJSON（deviceId/devicename/type/typeEx/
                        mode/deviceHash/serviceData/capabilityBitmap/wlanIp/
                        coapUri/bType/bData/extendServiceData/seqNo）
  * disc_ble_constant_struct.h / disc_ble_utils.c :
                        BLE 广播 = 固定头(7B)[version,business,businessExt,
                        userIdHash×2,capability,capabilityExt] + TLV(type<<4|len);
                        TLV: deviceIdHash(0x01)/deviceType(0x02)/deviceName(0x03)/
                        brMac(0x05); BLE_VERSION=4

适用：授权安全测试 / 协议分析 / 网络空间测绘。仅发现探测与被动监听，
     不发送攻击性载荷。请勿用于未授权网络。

依赖：Python 3.7+ 标准库即可（socket 模式）。
      可选：scapy（深度被动嗅探）、bleak（BLE 通道扫描）。
"""

import argparse
import hashlib
import json
import os
import random
import socket
import struct
import sys
import threading
import time

# ---------------------------------------------------------------------------
# 终端着色
# ---------------------------------------------------------------------------
_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "gray": "\033[90m",
}


def c(text, color):
    if not sys.stdout.isatty():
        return str(text)
    return f"{_ANSI.get(color, '')}{text}{_ANSI['reset']}"


# ---------------------------------------------------------------------------
# DSoftBus CoAP 常量（源码确认）
# ---------------------------------------------------------------------------
DSOFTBUS_PORT = 5684                       # COAP_SRV_DEFAULT_PORT
DISCOVER_URI = "device_discover"           # COAP_DEVICE_DISCOVER_URI
DEFAULT_BCAST = "255.255.255.255"          # 受限广播

# ---------------------------------------------------------------------------
# BLE 软总线发现常量（disc_ble_constant_struct.h / 蓝牙 SIG）
# ---------------------------------------------------------------------------
BLE_SOFTBUS_VERSION = 4                    # BLE_VERSION
HUAWEI_MANUFACTURER_ID = 0x01D6            # 蓝牙 SIG 分配给华为，company id=470
TLV_TYPE_DEVICE_ID_HASH = 0x01
TLV_TYPE_DEVICE_TYPE = 0x02
TLV_TYPE_DEVICE_NAME = 0x03
TLV_TYPE_CUST = 0x04
TLV_TYPE_BR_MAC = 0x05
TLV_TYPE_RANGE_POWER = 0x06
TLV_TYPE_ACTION = 0x07

# 设备类型 type 字段映射
# 注意：OpenHarmony 开源版与 HarmonyOS NEXT 商用版的 type 枚举值不同！
#   开源版(softbus_common.h DeviceType): 0=音箱 1=台式 2=笔记本 3=手机 4=平板 5=手表 6=车机 7=儿童表 8=TV
#   商用版实测: MateBook=0 / Mate X5=14 / MatePad Air=17（与开源版冲突）
# 因此 type 字段仅供参考，准确判断优先用 guess_type_by_name() 名称启发式。
DEVICE_TYPE_MAP = {
    # OpenHarmony softbus_common.h DeviceType（开源版基线）
    0x00: "智能音箱(Speaker)", 0x01: "台式机(Desktop)", 0x02: "笔记本(Laptop)",
    0x03: "手机(Phone)", 0x04: "平板(Pad)", 0x05: "手表(Watch)",
    0x06: "车机(Car)", 0x07: "儿童手表(KidsWatch)", 0x08: "智慧屏(TV)",
    # HarmonyOS NEXT 商用版实测（※标注，枚举与开源版不同）
    0x0E: "手机(Phone)※",   # Mate X5 实测
    0x11: "平板(Pad)※",     # MatePad Air 实测
}


def device_type_str(t):
    """单值 type/typeEx 映射（BLE 等简单场景用）。"""
    if isinstance(t, (int, float)) and not isinstance(t, bool):
        return DEVICE_TYPE_MAP.get(int(t), f"未知({int(t)})")
    if t == "" or t is None:
        return "?"
    return str(t)


# 华为/常见设备型号 → 类型 启发式规则（按优先级，名称命中即判定）
# HarmonyOS 设备名通常含型号（MateBook/MatePad/Mate X…），准确率高于 type 字段。
_NAME_TYPE_RULES = [
    (["matebook", "magicbook", "macbook", "notebook", "laptop", "thinkpad",
      "台式", "desktop", "笔记本"], "笔记本/PC"),
    (["matepad", "ipad", "tablet", "平板", "pad air", "pad pro"], "平板(Pad)"),
    (["matetv", "mate tv", "vision", "智慧屏", "电视", "smart tv"], "智慧屏(TV)"),
    (["mate x", "mate xt", "pura", "nova", "麦芒", "畅享", "redmi", "galaxy",
      "iphone", "phone", "手机", "mate", "p40", "p50", "p60", "p70"], "手机(Phone)"),
    (["watch", "手表", " gt 2", " gt 3", " gt 4", " gt 5"], "手表(Watch)"),
    (["band", "手环"], "手环(Band)"),
    (["freebuds", "earbuds", "耳机", "buds"], "耳机(Earbuds)"),
    (["音箱", "speaker", "sound", "小艺"], "音箱(Speaker)"),
    (["车机", " car", "问界", "智界", "享界"], "车机(Car)"),
]


def guess_type_by_name(name):
    """从设备名启发式判断类型，返回类型名 or None。"""
    if not name:
        return None
    n = name.lower()
    for keys, label in _NAME_TYPE_RULES:
        if any(k in n for k in keys):
            return label
    return None


def resolve_device_type(dev):
    """
    综合判定设备类型，返回 (label, raw_info, source)。
    优先级：设备名启发式(最准) > typeEx 映射 > type 映射。
    source ∈ {"name","typeEx","type","?"}，用于表格置信标记。
    """
    name = (dev.get("devicename") or "").strip()
    raw = dev.get("raw") if isinstance(dev.get("raw"), dict) else {}
    t = dev.get("type", raw.get("type", ""))
    tx = dev.get("typeEx", raw.get("typeEx", ""))
    gname = guess_type_by_name(name)
    if gname:
        return gname, f"type={t}/typeEx={tx}", "name"
    if isinstance(tx, (int, float)) and not isinstance(tx, bool) and int(tx) in DEVICE_TYPE_MAP:
        return DEVICE_TYPE_MAP[int(tx)], f"type={t}/typeEx={tx}", "typeEx"
    if isinstance(t, (int, float)) and not isinstance(t, bool):
        return DEVICE_TYPE_MAP.get(int(t), f"未知({int(t)})"), f"type={t}/typeEx={tx}", "type"
    return "未知", f"type={t}/typeEx={tx}", "?"


def load_type_map(path):
    """从 JSON 文件加载 {type_int: "名称"}，合并进 DEVICE_TYPE_MAP（用户校准用）。"""
    with open(path, "r", encoding="utf-8") as f:
        m = json.load(f)
    for k, v in m.items():
        DEVICE_TYPE_MAP[int(k, 0) if isinstance(k, str) else int(k)] = v
    log(f"已加载自定义类型映射 {c(path, 'cyan')}（{len(m)} 项）", "green")


# ---------------------------------------------------------------------------
# CoAP 编解码（RFC 7252，纯标准库）
# ---------------------------------------------------------------------------
COAP_TYPE_CON = 0
COAP_TYPE_NON = 1
COAP_TYPE_ACK = 2
COAP_TYPE_RST = 3

COAP_CODE_EMPTY = 0x00
COAP_CODE_GET = 0x01
COAP_CODE_POST = 0x02
COAP_CODE_PUT = 0x03
COAP_CODE_DELETE = 0x04
COAP_CODE_CREATED = 0x41     # 2.01
COAP_CODE_CONTENT = 0x45     # 2.05

OPT_URI_HOST = 3
OPT_URI_PORT = 7
OPT_URI_PATH = 11
OPT_CONTENT_FORMAT = 12

COAP_VERSION = 1
PAYLOAD_MARKER = 0xFF

_TYPE_NAME = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}


def _nibble_encode(n):
    if n < 13:
        return n, b""
    if n < 269:
        return 13, bytes([n - 13])
    return 14, struct.pack("!H", n - 269)


def _nibble_decode(data, offset, nibble_val):
    if nibble_val < 13:
        return nibble_val, offset
    if nibble_val == 13:
        return data[offset] + 13, offset + 1
    if nibble_val == 14:
        return struct.unpack_from("!H", data, offset)[0] + 269, offset + 2
    raise ValueError("CoAP option nibble = 15 非法")


def coap_build_options(options):
    out = bytearray()
    prev = 0
    for num, val in sorted(options, key=lambda x: x[0]):
        if num < prev:
            raise ValueError("option 必须升序")
        delta = num - prev
        d_nib, d_ext = _nibble_encode(delta)
        l_nib, l_ext = _nibble_encode(len(val))
        out.append((d_nib << 4) | l_nib)
        out += d_ext + l_ext + val
        prev = num
    return bytes(out)


def coap_parse_options(data, offset):
    opts = []
    num = 0
    i = offset
    while i < len(data):
        b = data[i]
        if b == PAYLOAD_MARKER:
            return opts, i + 1
        d_nib = (b >> 4) & 0x0F
        l_nib = b & 0x0F
        delta, i = _nibble_decode(data, i + 1, d_nib)
        length, i = _nibble_decode(data, i, l_nib)
        value = data[i:i + length]
        num += delta
        opts.append((num, value))
        i += length
    return opts, i


def coap_build_request(mtype, code, msg_id, token=b"",
                       options=None, payload=b""):
    if len(token) > 8:
        raise ValueError("token 最长 8 字节")
    options = options or []
    header = bytes([
        (COAP_VERSION << 6) | (mtype << 4) | len(token),
        code & 0xFF,
    ]) + struct.pack("!H", msg_id & 0xFFFF)
    body = bytearray(token)
    body += coap_build_options(options)
    if payload:
        body.append(PAYLOAD_MARKER)
        body += payload
    return header + bytes(body)


def _code_str(code):
    return f"{(code >> 5) & 0x07}.{code & 0x1F:02d}"


def coap_parse(data):
    if len(data) < 4:
        raise ValueError("CoAP 报文过短")
    b0 = data[0]
    ver = (b0 >> 6) & 0x03
    mtype = (b0 >> 4) & 0x03
    tkl = b0 & 0x0F
    code = data[1]
    msg_id = struct.unpack_from("!H", data, 2)[0]
    if ver != COAP_VERSION:
        raise ValueError(f"CoAP 版本号非法: {ver}")
    off = 4 + tkl
    token = data[4:off]
    options, off = coap_parse_options(data, off)
    payload = data[off:] if off <= len(data) else b""
    return {
        "version": ver, "type": mtype, "type_name": _TYPE_NAME.get(mtype, "?"),
        "tkl": tkl, "token": token, "code": code, "code_str": _code_str(code),
        "msg_id": msg_id, "options": options, "payload": payload, "raw": data,
    }


def options_to_dict(options):
    d = {}
    for num, val in options:
        try:
            sv = val.decode("utf-8")
        except UnicodeDecodeError:
            sv = val
        d.setdefault(num, []).append(sv)
    return d


# ---------------------------------------------------------------------------
# DSoftBus payload 构造 / 解析（依据 json_payload.h）
# ---------------------------------------------------------------------------
def build_discover_payload(local_ip, seq_no=None, disguise=None):
    """构造 device_discover 探测 payload。disguise(dict) 覆盖默认伪装字段。"""
    d = disguise or {}
    device_id = d.get("device_id") or _gen_device_id()
    device_name = d.get("device_name") or "dsoftbus_probe"
    dev_type = d.get("device_type", 3)
    if isinstance(dev_type, str):
        dev_type = int(dev_type, 0)
    payload = {
        "deviceId": device_id,
        "devicename": device_name,
        "type": dev_type,
        "typeEx": d.get("device_type_ex", dev_type),
        "mode": d.get("mode", 1),
        "deviceHash": d.get("device_hash") or hashlib.sha256(device_id.encode()).hexdigest()[:16],
        "serviceData": d.get("service_data", ""),
        "capabilityBitmap": d.get("capability", [0]),
        "wlanIp": local_ip,
        "coapUri": f"coap://{local_ip}:{DSOFTBUS_PORT}/{DISCOVER_URI}",
        "bType": d.get("b_type", 0),
        "bData": d.get("b_data", ""),
        "extendServiceData": d.get("extend_service_data", ""),
        "seqNo": seq_no if seq_no is not None else random.randint(1, 0xFFFFFF),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _gen_device_id():
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def parse_device_payload(payload_bytes):
    if not payload_bytes:
        return None
    text = payload_bytes.decode("utf-8", errors="ignore").strip()
    i = text.find("{")
    if i < 0:
        return None
    text = text[i:]
    j = text.rfind("}")
    if j >= 0:
        text = text[:j + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _clean_device_id(did):
    """清洗 deviceId：部分设备返回 {"UDID":"xxx"} 包装格式，提取其中的 UDID 值。"""
    if not isinstance(did, str) or not did:
        return did or ""
    s = did.strip()
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                for k in ("UDID", "udid", "deviceId", "id"):
                    if k in obj:
                        return str(obj[k])
                return str(next(iter(obj.values())))
        except json.JSONDecodeError:
            pass
    return s


def summarize_device(info, source_ip):
    return {
        "deviceId": _clean_device_id(info.get("deviceId", "")),
        "devicename": info.get("devicename", ""),
        "type": info.get("type", ""),
        "typeEx": info.get("typeEx", ""),
        "deviceHash": info.get("deviceHash", ""),
        "wlanIp": info.get("wlanIp", "") or source_ip,
        "sourceIp": source_ip,
        "capabilityBitmap": info.get("capabilityBitmap", []),
        "serviceData": info.get("serviceData", ""),
        "bType": info.get("bType", ""),
        "coapUri": info.get("coapUri", ""),
        "seqNo": info.get("seqNo", ""),
        "channel": "CoAP/5684",
        "firstSeen": time.strftime("%Y-%m-%d %H:%M:%S"),
        "lastSeen": time.strftime("%Y-%m-%d %H:%M:%S"),
        "raw": info,
    }


# ---------------------------------------------------------------------------
# 设备登记表
# ---------------------------------------------------------------------------
class DeviceRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._devices = {}

    def _key(self, dev):
        if dev.get("deviceId"):
            return ("id", dev["deviceId"])
        return ("ipname", dev.get("sourceIp", ""), dev.get("devicename", ""))

    def add(self, dev):
        k = self._key(dev)
        with self._lock:
            old = self._devices.get(k)
            dev["lastSeen"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if old is None:
                self._devices[k] = dev
                return True
            old.update(dev)
            return False

    def all(self):
        with self._lock:
            return list(self._devices.values())

    def __len__(self):
        with self._lock:
            return len(self._devices)


# ---------------------------------------------------------------------------
# 网络工具
# ---------------------------------------------------------------------------
def get_local_ip(prefer_ip=None):
    if prefer_ip:
        return prefer_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def expand_targets(spec):
    import ipaddress
    result = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                if net.num_addresses > 1:
                    result.extend(str(h) for h in net.hosts())
                else:
                    result.append(str(net.network_address))
            except ValueError as e:
                log(f"无效 CIDR {part}: {e}", "yellow")
        elif "-" in part and part.count(".") == 3:
            base, _, tail = part.rpartition(".")
            lo, _, hi = tail.partition("-")
            try:
                for n in range(int(lo), int(hi) + 1):
                    result.append(f"{base}.{n}")
            except ValueError:
                result.append(part)
        else:
            result.append(part)
    return result


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_VERBOSE = False


def log(msg, color=None):
    ts = time.strftime("%H:%M:%S")
    print(f"{c(ts, 'gray')}  {c(msg, color or 'reset')}", flush=True)


def dbg(msg):
    if _VERBOSE:
        log(msg, "dim")


# ---------------------------------------------------------------------------
# pcap 落盘（轻量 libpcap writer，合成 Ether+IPv4+UDP 帧）
# ---------------------------------------------------------------------------
class PcapWriter:
    """libpcap 文件写入器。把 UDP payload 合成 Ethernet+IP+UDP 帧后写入。"""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "wb")
        self._lock = threading.Lock()
        # 全局头：magic, ver2/4, thiszone=0, sigfigs=0, snaplen=65535, network=1(Ethernet)
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    @staticmethod
    def _ip_checksum(header):
        if len(header) % 2:
            header = header + b"\x00"
        total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return (~total) & 0xFFFF

    def write_udp(self, src_ip, dst_ip, src_port, dst_port, payload, ts=None):
        ts = ts or time.time()
        sec, usec = int(ts), int((ts - int(ts)) * 1e6)
        try:
            src_b = socket.inet_aton(src_ip)
            dst_b = socket.inet_aton(dst_ip)
        except OSError:
            return  # 非法 IP（如广播/组播地址 inet_aton 其实支持，少数不支持则跳过）
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", src_port & 0xFFFF, dst_port & 0xFFFF, udp_len, 0) + payload
        ip = bytearray(struct.pack("!BBHHHBBH4s4s",
            0x45, 0, 20 + udp_len, random.randint(0, 0xFFFF), 0, 64, 17, 0, src_b, dst_b))
        cs = self._ip_checksum(ip)
        struct.pack_into("!H", ip, 10, cs)
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        frame = eth + bytes(ip) + udp
        with self._lock:
            self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            self.f.write(frame)
            self.f.flush()

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# BLE 通道：软总线 payload 解析 + 被动扫描
# ---------------------------------------------------------------------------
def parse_softbus_ble_service_data(data):
    """
    解析 HarmonyOS 软总线 BLE service data：固定头(7B) + TLV。
    返回 dict（含解析出的字段）或 None（格式不符）。
    依据：disc_ble_constant_struct.h / disc_ble_utils.c
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
        return None
    info = {
        "version": data[0], "business": data[1], "businessExt": data[2],
        "userIdHash": bytes(data[3:5]).hex(),
        "capability": data[5], "capabilityExt": data[6],
    }
    tlv = data[7:]
    i = 0
    while i + 1 <= len(tlv):
        t = (tlv[i] >> 4) & 0x0F
        l = tlv[i] & 0x0F
        i += 1
        if l == 0:                      # 不定长：剩余全部归该 TLV
            l = len(tlv) - i
            if l <= 0:
                break
        if i + l > len(tlv):
            break
        val = bytes(tlv[i:i + l])
        i += l
        if t == TLV_TYPE_DEVICE_ID_HASH:
            info["deviceIdHash"] = val.hex()
        elif t == TLV_TYPE_DEVICE_TYPE:
            info["deviceType"] = struct.unpack("<H", val[:2])[0] if len(val) >= 2 else val[0]
        elif t == TLV_TYPE_DEVICE_NAME:
            info["deviceName"] = val.decode("utf-8", "ignore")
        elif t == TLV_TYPE_BR_MAC:
            info["brMac"] = ":".join("%02x" % b for b in val[:6])
        elif t == TLV_TYPE_RANGE_POWER and val:
            info["rangePower"] = val[0]
        elif t == TLV_TYPE_CUST:
            info["custData"] = val.hex()
    return info


def _looks_softbus(parsed):
    """判断解析结果是否像软总线广播（version 合理范围）。"""
    if not parsed:
        return False
    v = parsed.get("version", -1)
    return 1 <= v <= 15


def run_ble_scan(duration, registry, verbose=False, live=None):
    """BLE 被动扫描：用 bleak 监听广播并识别 HarmonyOS 软总线/华为设备。"""
    try:
        import asyncio
        from bleak import BleakScanner
    except ImportError:
        log("BLE 扫描需要 bleak 库：pip install bleak", "red")
        log("macOS 首次运行需在系统设置授予终端蓝牙权限。", "dim")
        return

    log(f"BLE 被动扫描中，时长={c(str(duration), 'cyan')}s，"
        f"按软总线 TLV + 华为 company id(0x01D6) 识别...", "bold")
    log("提示：BLE 主动广播（伪装被发现）在 PC 上跨平台库支持不稳定，本工具仅做被动扫描。", "dim")
    if live:
        live.start("BLE 扫描中")

    def on_detection(device, advertisement_data):
        addr = device.address
        name = (getattr(advertisement_data, "local_name", None)
                or getattr(device, "name", None) or "")
        md = dict(getattr(advertisement_data, "manufacturer_data", None) or {})
        sd = dict(getattr(advertisement_data, "service_data", None) or {})
        suuids = list(getattr(advertisement_data, "service_uuids", None) or [])
        rssi = getattr(advertisement_data, "rssi", None) or getattr(device, "rssi", None)

        info = None
        label = None
        # 1) service data 解析软总线 TLV
        for uuid, sdata in sd.items():
            parsed = parse_softbus_ble_service_data(sdata)
            if _looks_softbus(parsed):
                info = {
                    "deviceId": parsed.get("deviceIdHash", ""),
                    "devicename": parsed.get("deviceName") or name,
                    "type": parsed.get("deviceType", ""),
                    "deviceHash": parsed.get("deviceIdHash", ""),
                    "wlanIp": "",
                    "sourceIp": addr,
                    "capabilityBitmap": [parsed["capability"]] if "capability" in parsed else [],
                    "serviceData": f"BLE softbus v{parsed.get('version')} biz={parsed.get('business')}",
                    "coapUri": "",
                    "rssi": rssi,
                    "channel": "BLE",
                    "firstSeen": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "lastSeen": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "raw": {"ble": parsed, "service_uuid": str(uuid)},
                }
                label = "软总线"
                break
        # 2) 华为 manufacturer data 兜底
        if info is None and HUAWEI_MANUFACTURER_ID in md:
            mdata = md[HUAWEI_MANUFACTURER_ID]
            info = {
                "deviceId": "", "devicename": name, "type": "",
                "deviceHash": bytes(mdata).hex()[:32], "wlanIp": "",
                "sourceIp": addr, "capabilityBitmap": [],
                "serviceData": f"Huawei BLE mfr-data ({len(bytes(mdata))}B)",
                "coapUri": "", "rssi": rssi, "channel": "BLE",
                "firstSeen": time.strftime("%Y-%m-%d %H:%M:%S"),
                "lastSeen": time.strftime("%Y-%m-%d %H:%M:%S"),
                "raw": {"ble_mfr": bytes(mdata).hex(), "service_uuids": suuids},
            }
            label = "华为设备(疑似)"

        if info is not None:
            if registry.add(info) and live:
                live.add(info)
        elif verbose:
            dbg(f"BLE {addr} ({rssi}) name={name!r} "
                f"mfr={ {hex(k): bytes(v).hex()[:10] for k, v in md.items()} } suuid={suuids}")

    async def scan():
        scanner = BleakScanner(detection_callback=on_detection)
        await scanner.start()
        try:
            if duration and duration > 0:
                await asyncio.sleep(duration)
            else:
                log("持续 BLE 扫描，Ctrl+C 停止...", "dim")
                while True:
                    await asyncio.sleep(1)
        finally:
            await scanner.stop()

    try:
        asyncio.run(scan())
    except KeyboardInterrupt:
        log("BLE 扫描已停止", "yellow")


# ---------------------------------------------------------------------------
# WiFi Aware (NAN) 通道说明
# ---------------------------------------------------------------------------
def run_nan_check():
    """WiFi Aware 通道可行性评估。PC 上无成熟跨平台 Python 实现。"""
    import platform
    log("WiFi Aware (NAN) 通道评估：", "bold")
    log(f"  平台: {platform.system()} {platform.release()}", "dim")
    log("  HarmonyOS DSoftBus 的 NAN 发现需要 Wi-Fi Aware 硬件 + 驱动支持。", "yellow")
    log("  PC 端 Python 无成熟跨平台库可被动监听/主动模拟 NAN 发现帧。", "yellow")
    log("  结论：PC 上 NAN 通道不可行。建议聚焦 BLE（--ble）与 CoAP（默认 5684）通道。", "cyan")
    log("  如需 NAN 测试，建议用 HarmonyOS 真机作为主动端。", "dim")


# ---------------------------------------------------------------------------
# 主动 scan
# ---------------------------------------------------------------------------
def build_probe_packet(local_ip, target_ip, msg_id, token, disguise=None):
    payload = build_discover_payload(local_ip, disguise=disguise)
    options = [
        (OPT_URI_HOST, target_ip.encode()),
        (OPT_URI_PATH, DISCOVER_URI.encode()),
    ]
    return coap_build_request(COAP_TYPE_NON, COAP_CODE_POST, msg_id,
                              token=token, options=options, payload=payload)


def _try_extract_device(data, src_ip):
    try:
        pkt = coap_parse(data)
    except ValueError:
        return None, None
    dev = parse_device_payload(pkt["payload"])
    if dev:
        return pkt, summarize_device(dev, src_ip)
    return pkt, None


def run_scan(targets, bcast, local_ip, iface, timeout, interval, count,
             registry, disguise=None, pcap=None, live=None):
    local = local_ip
    if disguise:
        log(f"伪装字段已启用：name={c(disguise.get('device_name') or '随机','cyan')} "
            f"type={c(str(disguise.get('device_type',3)),'cyan')} "
            f"cap={c(str(disguise.get('capability')),'cyan')} "
            f"id={c((disguise.get('device_id') or '随机')[:12],'cyan')}", "magenta")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        pass
    if iface:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        except (OSError, AttributeError):
            dbg("当前平台不支持 SO_BINDTODEVICE，忽略 --iface")
    sock.bind((local, 0))
    sock.settimeout(0.5)
    src_port = sock.getsockname()[1]
    dbg(f"发送 socket 绑定 {local}:{src_port}")

    listen_sock = None
    try:
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        listen_sock.bind(("0.0.0.0", DSOFTBUS_PORT))
        listen_sock.settimeout(0.5)
        dbg("附加监听 0.0.0.0:5684")
    except OSError as e:
        dbg(f"无法绑定 5684 附加监听（{e}），仅依赖发送 socket 收响应")

    stop = threading.Event()

    def receiver():
        socks = [s for s in (sock, listen_sock) if s is not None]
        while not stop.is_set():
            for s in socks:
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                src_ip = addr[0]
                if pcap:
                    pcap.write_udp(src_ip, local, addr[1], DSOFTBUS_PORT, data)
                pkt, dev = _try_extract_device(data, src_ip)
                if dev:
                    if registry.add(dev) and live:
                        live.add(dev)
                elif pkt and _VERBOSE:
                    dbg(f"<- {src_ip} CoAP {pkt['type_name']} code={pkt['code_str']} "
                        f"len={len(pkt['payload'])} (非 DSoftBus 报文)")

    t = threading.Thread(target=receiver, daemon=True)
    t.start()

    def send_once():
        mid = random.randint(1, 0xFFFF)
        token = bytes(random.randint(0, 255) for _ in range(2))
        try:
            pkt = build_probe_packet(local, DEFAULT_BCAST, mid, token, disguise)
            sock.sendto(pkt, (bcast, DSOFTBUS_PORT))
            dbg(f"-> 广播 {bcast}:{DSOFTBUS_PORT} ({len(pkt)}B)")
        except OSError as e:
            log(f"广播发送失败: {e}", "yellow")
        for ip in targets:
            try:
                pkt = build_probe_packet(local, ip, mid + 1,
                                         bytes(random.randint(0, 255) for _ in range(2)), disguise)
                sock.sendto(pkt, (ip, DSOFTBUS_PORT))
                if pcap:
                    pcap.write_udp(local, ip, src_port, DSOFTBUS_PORT, pkt)
                dbg(f"-> {ip}:{DSOFTBUS_PORT} ({len(pkt)}B)")
            except OSError as e:
                log(f"发送 {ip} 失败: {e}", "yellow")

    mode = "持续轮询(主动雷达)" if count == 0 else f"{count} 轮"
    log(f"开始主动探测：广播={c(bcast, 'cyan')}  定向目标={c(str(len(targets)), 'cyan')} 个  "
        f"模式={c(mode, 'cyan')}  间隔={interval}s", "bold")
    if count == 0:
        log("主动雷达模式：周期性广播探测，可发现息屏/空闲设备（对端 5684 服务常驻即响应）。Ctrl+C 停止。", "magenta")
    if live:
        live.start("scan 主动探测中")

    sent_count = 0
    i = 0
    try:
        while count == 0 or i < count:
            send_once()
            sent_count += 1
            i += 1
            if count == 0:
                log(f"[主动雷达] 第 {i} 轮广播已发出，等待响应...", "dim")
            elif count > 1:
                log(f"第 {i}/{count} 轮探测已发出，等待响应...", "dim")
            time.sleep(interval)
    except KeyboardInterrupt:
        log("用户中断发送，继续收尾 2s...", "yellow")
        time.sleep(2)

    log(f"发送完成（{sent_count} 轮），继续监听 {timeout}s 收集响应...", "dim")
    time.sleep(timeout)
    stop.set()
    t.join(timeout=1.0)
    sock.close()
    if listen_sock:
        listen_sock.close()


# ---------------------------------------------------------------------------
# 被动 sniff
# ---------------------------------------------------------------------------
def run_sniff_sniff(registry, duration, iface, pcap=None, live=None):
    try:
        from scapy.all import sniff, IP, UDP  # noqa: F401
    except ImportError:
        return False

    bpf = "udp port 5684 or udp port 5683"
    log(f"scapy 嗅探中：filter={c(bpf, 'cyan')}  时长={duration}s", "bold")
    if live:
        live.start("sniff 深度嗅探中")

    def handler(pkt):
        try:
            udp = pkt["UDP"]
        except (IndexError, KeyError):
            return
        data = bytes(udp.payload)
        src_ip = pkt["IP"].src if pkt.haslayer("IP") else "?"
        dst_ip = pkt["IP"].dst if pkt.haslayer("IP") else "?"
        if pcap:
            pcap.write_udp(src_ip, dst_ip, int(udp.sport), int(udp.dport), data)
        coap, dev = _try_extract_device(data, src_ip)
        if dev:
            if registry.add(dev) and live:
                live.add(dev)
        elif coap and _VERBOSE:
            dbg(f"<- {src_ip}->{dst_ip}  CoAP {coap['type_name']} code={coap['code_str']} "
                f"len={len(coap['payload'])}")
            od = options_to_dict(coap["options"])
            dbg(f"   opts: host={od.get(OPT_URI_HOST)} path={od.get(OPT_URI_PATH)}")

    kwargs = {"filter": bpf, "prn": handler, "store": False}
    if iface:
        kwargs["iface"] = iface
    if duration and duration > 0:
        kwargs["timeout"] = duration
    try:
        sniff(**kwargs)
    except PermissionError:
        log("scapy 无原始套接字权限，请用 sudo/root 运行；降级到 socket 模式", "yellow")
        return False
    except KeyboardInterrupt:
        log("嗅探已中断", "yellow")
    return True


def run_sniff_socket(registry, duration, iface, pcap=None, local_ip=None, live=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    if iface:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        except (OSError, AttributeError):
            pass
    try:
        sock.bind(("0.0.0.0", DSOFTBUS_PORT))
    except OSError as e:
        log(f"无法绑定 0.0.0.0:{DSOFTBUS_PORT}（{e}）。可能端口被占用或需 root。", "red")
        return
    sock.settimeout(0.5)
    log(f"socket 被动监听 0.0.0.0:{c(str(DSOFTBUS_PORT), 'cyan')}（仅收广播/发给本机的报文）", "bold")
    log("提示：抓不到他人间单播响应。深度嗅探请装 scapy 并用 sudo 运行。", "dim")
    if live:
        live.start("sniff socket 监听中")

    start = time.time()
    try:
        while True:
            if duration and duration > 0 and (time.time() - start) >= duration:
                break
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            src_ip = addr[0]
            if pcap:
                pcap.write_udp(src_ip, local_ip or "127.0.0.1", addr[1], DSOFTBUS_PORT, data)
            coap, dev = _try_extract_device(data, src_ip)
            if dev:
                if registry.add(dev) and live:
                    live.add(dev)
            elif coap and _VERBOSE:
                dbg(f"<- {src_ip}  CoAP {coap['type_name']} code={coap['code_str']} "
                    f"len={len(coap['payload'])}")
    except KeyboardInterrupt:
        log("监听已中断", "yellow")
    finally:
        sock.close()


def run_sniff(registry, duration, iface, pcap=None, local_ip=None, live=None):
    if not run_sniff_sniff(registry, duration, iface, pcap, live):
        run_sniff_socket(registry, duration, iface, pcap, local_ip, live)


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def print_device_table(devices):
    if not devices:
        log("未发现任何 DSoftBus 设备。", "yellow")
        return
    log(f"共发现 {c(str(len(devices)), 'green')} 台 DSoftBus/相关设备：", "bold")
    print(f"  {c('#','bold')}  {c('通道','bold'):<11}{c('IP/BLE-addr','bold'):<17} "
          f"{c('设备名','bold'):<26} {c('类型  [✓=名称启发(准) / ※=type字段(参考)]','bold')}")
    print(c("-" * 100, "dim"))
    for i, d in enumerate(sorted(devices, key=lambda x: (x.get("channel", ""), x.get("sourceIp", ""))), 1):
        ch = str(d.get("channel", "CoAP/5684"))
        ip = str(d.get("wlanIp") or d.get("sourceIp") or "")
        name = str(d.get("devicename", ""))[:24]
        label, raw_info, src = resolve_device_type(d)
        if src == "name":
            mark = c(" ✓", "green")
        else:
            mark = c(f" ※ [{raw_info}]", "yellow")
        did = str(d.get("deviceId") or d.get("deviceHash") or "")[:30]
        ch_color = "magenta" if "BLE" in ch else "cyan"
        print(f"  {c(str(i),'cyan'):<3}{c(ch, ch_color):<11}{ip:<17} {name:<26} "
              f"{label}{mark}  {c(did, 'dim')}")
    print()


def format_device_row(idx, dev):
    """格式化单个设备为表格行（供流式打印用）。"""
    ch = str(dev.get("channel", "CoAP/5684"))
    ip = str(dev.get("wlanIp") or dev.get("sourceIp") or "")
    name = str(dev.get("devicename", ""))[:24]
    label, raw_info, src = resolve_device_type(dev)
    if src == "name":
        mark = c(" ✓", "green")
    else:
        mark = c(f" ※ [{raw_info}]", "yellow")
    did = str(dev.get("deviceId") or dev.get("deviceHash") or "")[:30]
    ch_color = "magenta" if "BLE" in ch else "cyan"
    return (f"  {c(str(idx), 'cyan'):<3}{c(ch, ch_color):<11}{ip:<17} {name:<26} "
            f"{label}{mark}  {c(did, 'dim')}")


class LiveTable:
    """流式设备表格：表头打印一次，每发现一台新设备追加一行（过程安静）。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._n = 0
        self._started = False

    def start(self, title="设备实时发现"):
        with self._lock:
            if self._started:
                return
            self._started = True
        log(f"{title}（识别到新设备即追加一行，重复设备静默；Ctrl+C 结束）", "bold")
        print(f"  {c('#', 'bold')}  {c('通道', 'bold'):<11}{c('IP/BLE-addr', 'bold'):<17} "
              f"{c('设备名', 'bold'):<26} {c('类型  [✓=名称启发(准) / ※=type字段(参考)]', 'bold')}")
        print(c("-" * 100, "dim"))

    def add(self, dev):
        with self._lock:
            self._n += 1
            idx = self._n
        print(format_device_row(idx, dev), flush=True)

    def count(self):
        with self._lock:
            return self._n


def save_json(devices, path, mode_label):
    out = {
        "tool": "dsoftbus_probe",
        "mode": mode_label,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device_count": len(devices),
        "devices": devices,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    log(f"结果已写入 {c(path, 'cyan')}（{len(devices)} 台设备）", "green")


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------
def selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        status = c("PASS", "green") if cond else c("FAIL", "red")
        print(f"  [{status}] {name}")
        ok = ok and cond

    print(c("== selftest ==", "bold"))

    opts = coap_build_options([
        (OPT_URI_HOST, b"1.2.3.4"),
        (OPT_URI_PATH, b"device_discover"),
    ])
    expect = bytes([0x37]) + b"1.2.3.4" + bytes([0x8D, 0x02]) + b"device_discover"
    check("option 编码 (host+path)", opts == expect)

    payload = build_discover_payload("192.168.1.100",
                                     disguise={"device_id": "deadbeef" * 4,
                                               "device_name": "t", "device_type": 3})
    pkt = coap_build_request(
        COAP_TYPE_NON, COAP_CODE_POST, 0x1234, token=b"\xab\xcd",
        options=[(OPT_URI_HOST, b"255.255.255.255"),
                 (OPT_URI_PATH, b"device_discover")],
        payload=payload,
    )
    parsed = coap_parse(pkt)
    check("header ver/type", parsed["version"] == 1 and parsed["type"] == COAP_TYPE_NON)
    check("header code=POST", parsed["code"] == COAP_CODE_POST and parsed["code_str"] == "0.02")
    check("header msgId", parsed["msg_id"] == 0x1234)
    check("header token", parsed["token"] == b"\xab\xcd")
    od = options_to_dict(parsed["options"])
    check("option Uri-Host", od.get(OPT_URI_HOST) == ["255.255.255.255"])
    check("option Uri-Path", od.get(OPT_URI_PATH) == ["device_discover"])
    check("payload 完整", parsed["payload"] == payload)

    dev = parse_device_payload(payload)
    check("payload JSON 解析", dev is not None and dev["devicename"] == "t")
    check("payload coapUri", dev and dev["coapUri"] == "coap://192.168.1.100:5684/device_discover")

    # 伪装字段生效
    payload2 = build_discover_payload("10.0.0.1", disguise={
        "device_name": "GhostPC", "device_type": 0, "capability": [1, 2], "mode": 0})
    dev2 = parse_device_payload(payload2)
    check("伪装 device_name 生效", dev2 and dev2["devicename"] == "GhostPC")
    check("伪装 capability 生效", dev2 and dev2["capabilityBitmap"] == [1, 2])

    noisy = b"\x00garbage" + b'{"deviceId":"x","devicename":"y"}' + b"tail"
    dev3 = parse_device_payload(noisy)
    check("payload 容错（前导噪音）", dev3 is not None and dev3["devicename"] == "y")

    try:
        coap_parse(b"\x00")
        check("畸形报文拒绝", False)
    except ValueError:
        check("畸形报文拒绝", True)

    # BLE softbus payload 解析
    ble = bytes([BLE_SOFTBUS_VERSION, 1, 0, 0xAA, 0xBB, 0x03, 0,
                 (TLV_TYPE_DEVICE_ID_HASH << 4) | 8]) + b"\x11\x22\x33\x44\x55\x66\x77\x88" + \
        bytes([(TLV_TYPE_DEVICE_TYPE << 4) | 2]) + struct.pack("<H", 3) + \
        bytes([(TLV_TYPE_DEVICE_NAME << 4) | 7]) + b"Harmony"
    bp = parse_softbus_ble_service_data(ble)
    check("BLE 解析 version", bp and bp["version"] == BLE_SOFTBUS_VERSION)
    check("BLE 解析 deviceIdHash", bp and bp.get("deviceIdHash") == "1122334455667788")
    check("BLE 解析 deviceType", bp and bp.get("deviceType") == 3)
    check("BLE 解析 deviceName", bp and bp.get("deviceName") == "Harmony")

    # 设备名启发式（解决 HarmonyOS NEXT 商用版 type 枚举与开源版不一致）
    check("启发式 MateBook→笔记本", guess_type_by_name("MateBook 14") == "笔记本/PC")
    check("启发式 MatePad→平板", guess_type_by_name("MatePad Air") == "平板(Pad)")
    check("启发式 Mate X5→手机", guess_type_by_name("Mate X5") == "手机(Phone)")
    check("启发式 Pura→手机", guess_type_by_name("华为Pura 70") == "手机(Phone)")
    check("启发式 Mate60→手机", guess_type_by_name("Mate60 Pro") == "手机(Phone)")
    check("启发式 MateTV→智慧屏", guess_type_by_name("智慧屏 MateTV") == "智慧屏(TV)")
    check("deviceId 提取 UDID", _clean_device_id('{"UDID":"0123456789ABCDEF"}') == "0123456789ABCDEF")
    lab, _ri, src = resolve_device_type({"devicename": "MateBook 14", "type": 0, "typeEx": 0})
    check("resolve 名称优先(MateBook type=0)", lab == "笔记本/PC" and src == "name")

    # pcap writer round-trip
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.close()
    pw = PcapWriter(tmp.name)
    pw.write_udp("10.0.0.1", "10.0.0.2", 12345, 5684, b"hello-coap")
    pw.close()
    with open(tmp.name, "rb") as f:
        head = f.read(4)
    check("pcap 文件 magic", head == struct.pack("<I", 0xA1B2C3D4))
    os.unlink(tmp.name)

    print(c("== selftest 完成 ==" if ok else "== selftest 存在失败 ==", "bold"))
    return ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _add_disguise_args(p):
    p.add_argument("--device-name", default=None, help="伪装设备名 devicename")
    p.add_argument("--device-type", default=None, help="伪装设备类型 type（开源版:2=笔记本 3=手机 4=平板；商用版枚举不同）")
    p.add_argument("--capability", default=None, help="伪装能力位图，逗号分隔（如 0,1,2）")
    p.add_argument("--device-id", default=None, help="伪装 deviceId")
    p.add_argument("--service-data", default=None, help="伪装 serviceData")
    p.add_argument("--mode", type=int, default=None, help="伪装发布模式 mode")


def _parse_disguise(args):
    cap = None
    if getattr(args, "capability", None):
        try:
            cap = [int(x) for x in args.capability.split(",")]
        except ValueError:
            log(f"无效 capability: {args.capacity}", "yellow")
    return {
        "device_name": getattr(args, "device_name", None),
        "device_type": getattr(args, "device_type", None),
        "capability": cap,
        "device_id": getattr(args, "device_id", None),
        "service_data": getattr(args, "service_data", None),
        "mode": getattr(args, "mode", None),
    }


def _open_pcap(path):
    if not path:
        return None
    try:
        return PcapWriter(path)
    except OSError as e:
        log(f"无法创建 pcap 文件 {path}: {e}", "red")
        return None


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="dsoftbus_probe.py",
        description="HarmonyOS NEXT (PC) DSoftBus 设备发现探测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 dsoftbus_probe.py selftest\n"
            "  python3 dsoftbus_probe.py scan                            # 广播探测整网\n"
            "  python3 dsoftbus_probe.py scan -n 0 --interval 5          # 无限轮询(主动雷达,覆盖息屏设备)\n"
            "  python3 dsoftbus_probe.py scan -t 192.168.1.0/24          # CIDR 定向\n"
            "  python3 dsoftbus_probe.py scan --device-name GhostPC --device-type 0 --capability 1,2\n"
            "  python3 dsoftbus_probe.py scan --pcap cap.pcap            # 落盘 pcap\n"
            "  sudo python3 dsoftbus_probe.py sniff                      # scapy 深度被动嗅探\n"
            "  sudo python3 dsoftbus_probe.py sniff --pcap cap.pcap\n"
            "  python3 dsoftbus_probe.py ble -d 15                       # BLE 被动扫描\n"
            "  python3 dsoftbus_probe.py nan                             # WiFi Aware 可行性\n"
        ),
    )
    sub = p.add_subparsers(dest="command")

    ps = sub.add_parser("scan", help="主动探测 DSoftBus 设备")
    ps.add_argument("-t", "--target", default="", help="定向目标 IP / CIDR / 范围 / 逗号列表")
    ps.add_argument("-b", "--bcast", default=DEFAULT_BCAST, help=f"广播地址（默认 {DEFAULT_BCAST}）")
    ps.add_argument("--ip", default=None, help="指定本机出口 IP（默认自动探测）")
    ps.add_argument("-i", "--iface", default=None, help="绑定网络接口名")
    ps.add_argument("--timeout", type=float, default=3.0, help="发送后继续监听响应时长（秒）")
    ps.add_argument("--interval", type=float, default=1.0, help="每轮探测间隔（秒）")
    ps.add_argument("-n", "--count", type=int, default=1, help="探测轮数（0=无限轮询/主动雷达，默认 1）")
    ps.add_argument("-o", "--output", default=None, help="结果落盘 JSON 路径")
    ps.add_argument("--pcap", default=None, help="pcap 落盘路径（含合成帧）")
    ps.add_argument("-v", "--verbose", action="store_true", help="详细调试输出")
    ps.add_argument("--type-map", default=None, help="自定义类型映射 JSON 文件 {type_int:'名称'}")
    _add_disguise_args(ps)

    pn = sub.add_parser("sniff", help="被动监听 DSoftBus 报文")
    pn.add_argument("-d", "--duration", type=float, default=0, help="监听时长秒（0=持续）")
    pn.add_argument("-i", "--iface", default=None, help="监听网卡")
    pn.add_argument("--fallback", action="store_true", help="强制 socket 降级模式")
    pn.add_argument("-o", "--output", default=None, help="结果落盘 JSON 路径")
    pn.add_argument("--pcap", default=None, help="pcap 落盘路径")
    pn.add_argument("--type-map", default=None, help="自定义类型映射 JSON 文件")
    pn.add_argument("-v", "--verbose", action="store_true", help="详细调试输出")

    pb = sub.add_parser("ble", help="BLE 通道被动扫描（需 bleak）")
    pb.add_argument("-d", "--duration", type=float, default=15, help="扫描时长秒（默认 15）")
    pb.add_argument("-o", "--output", default=None, help="结果落盘 JSON 路径")
    pb.add_argument("--type-map", default=None, help="自定义类型映射 JSON 文件")
    pb.add_argument("-v", "--verbose", action="store_true", help="打印所有 BLE 广播")

    pnan = sub.add_parser("nan", help="WiFi Aware(NAN) 通道可行性说明")

    pc = sub.add_parser("both", help="先 scan 一次再持续 sniff")
    pc.add_argument("-t", "--target", default="", help="定向目标")
    pc.add_argument("-b", "--bcast", default=DEFAULT_BCAST, help="广播地址")
    pc.add_argument("--ip", default=None, help="指定本机出口 IP")
    pc.add_argument("-i", "--iface", default=None, help="网卡")
    pc.add_argument("--timeout", type=float, default=3.0, help="scan 监听响应时长")
    pc.add_argument("--pcap", default=None, help="pcap 落盘路径")
    _add_disguise_args(pc)
    pc.add_argument("-o", "--output", default=None, help="结果落盘 JSON 路径")
    pc.add_argument("--type-map", default=None, help="自定义类型映射 JSON 文件")
    pc.add_argument("-v", "--verbose", action="store_true", help="详细调试输出")

    sub.add_parser("selftest", help="运行内置自检")
    return p


def main(argv=None):
    global _VERBOSE
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    _VERBOSE = getattr(args, "verbose", False)

    if args.command == "selftest":
        return 0 if selftest() else 1

    if args.command == "nan":
        run_nan_check()
        return 0

    print(c("╔══════════════════════════════════════════════════╗\n", "cyan")
          + c("║   DSoftBus Probe  —  HarmonyOS NEXT 设备发现     ║\n", "cyan")
          + c("║   UDP/5684 CoAP · BLE · device_discover          ║\n", "cyan")
          + c("╚══════════════════════════════════════════════════╝", "cyan"))
    log("仅用于授权安全测试 / 协议分析。", "yellow")

    if getattr(args, "type_map", None):
        load_type_map(args.type_map)
    registry = DeviceRegistry()
    pcap = _open_pcap(getattr(args, "pcap", None))
    if pcap:
        log(f"pcap 落盘已启用：{c(args.pcap, 'cyan')}", "green")
    live = LiveTable()

    try:
        if args.command in ("scan", "both"):
            local = get_local_ip(getattr(args, "ip", None))
            targets = expand_targets(args.target) if args.target else []
            run_scan(
                targets=targets, bcast=args.bcast, local_ip=local,
                iface=args.iface, timeout=args.timeout,
                interval=getattr(args, "interval", 1.0), count=getattr(args, "count", 1),
                registry=registry, disguise=_parse_disguise(args), pcap=pcap, live=live,
            )

        if args.command == "sniff":
            local = get_local_ip()
            if getattr(args, "fallback", False):
                run_sniff_socket(registry, args.duration, args.iface, pcap, local, live)
            else:
                run_sniff(registry, args.duration, args.iface, pcap, local, live)

        if args.command == "ble":
            run_ble_scan(args.duration, registry, verbose=args.verbose, live=live)

        if args.command == "both":
            log("进入持续被动监听（Ctrl+C 结束）...", "bold")
            local = get_local_ip(getattr(args, "ip", None))
            run_sniff(registry, 0, args.iface, pcap, local, live)
    finally:
        if pcap:
            pcap.close()

    devices = registry.all()
    if not devices:
        log("未发现任何 DSoftBus 设备。", "yellow")
    else:
        coap_n = sum(1 for d in devices if "BLE" not in str(d.get("channel", "")))
        ble_n = len(devices) - coap_n
        tail = f"（CoAP {coap_n} / BLE {ble_n}）" if ble_n else ""
        log(f"完成：共发现 {c(str(len(devices)), 'green')} 台设备{tail}", "bold")
    if getattr(args, "output", None):
        save_json(devices, args.output, args.command)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        log("已退出。", "yellow")
        sys.exit(130)
