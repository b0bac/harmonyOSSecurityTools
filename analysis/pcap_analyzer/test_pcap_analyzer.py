#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_pcap_analyzer.py — pcap_analyzer 单元测试

手工合成合法 pcap / pcapng(含 CoAP device_discover 包), 跑通全链路解析。
    python test_pcap_analyzer.py
"""
import os
import sys
import struct
import socket
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcap_analyzer as pa


# ============ 合成 pcap 辅助 ============
def _enc_val(v):
    if v < 13:
        return v, b""
    if v < 269:
        return 13, bytes([v - 13])
    return 14, struct.pack("!H", v - 269)


def _opt(delta, length):
    d_nib, d_ext = _enc_val(delta)
    l_nib, l_ext = _enc_val(length)
    return bytes([(d_nib << 4) | l_nib]) + d_ext + l_ext


def coap_post(uri_paths, payload=b"", mid=0x1234):
    """合成 CoAP NON POST(Ver1), Uri-Path 用 number=11"""
    b0 = (1 << 6) | (1 << 4) | 0      # ver1 / type=NON / tkl=0
    hdr = bytes([b0, 0x02]) + struct.pack("!H", mid)
    opts = b""
    first = True
    for p in uri_paths:
        d = 11 if first else 0
        first = False
        pb = p.encode()
        opts += _opt(d, len(pb)) + pb
    body = hdr + opts
    if payload:
        body += b"\xff" + payload
    return body


def udp_packet(src_ip, dst_ip, sport, dport, payload):
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    total = 20 + len(udp)
    ip = (bytes([0x45, 0x00]) + struct.pack("!H", total)
          + struct.pack("!HH", 0x1234, 0) + bytes([0x40, 17, 0, 0]) + src + dst)
    eth = b"\x02" * 6 + b"\x03" * 6 + struct.pack("!H", 0x0800)
    return eth + ip + udp


def pcap_file(packets, link_type=1):
    ghdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)
    out = ghdr
    for ts, raw in packets:
        sec = int(ts)
        usec = int((ts - sec) * 1e6)
        out += struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw
    return out


def pcapng_file(packets, link_type=1):
    E = "<"

    def blk(bt, body):
        body = body + b"\x00" * ((4 - len(body) % 4) % 4)
        bl = 12 + len(body)
        return struct.pack(E + "II", bt, bl) + body + struct.pack(E + "I", bl)

    shb = blk(0x0A0D0D0A, struct.pack(E + "I", 0x1A2B3C4D) + struct.pack(E + "HH", 1, 0))
    idb = blk(1, struct.pack(E + "HH", link_type, 0))
    out = shb + idb
    for ts, raw in packets:
        tus = int(ts * 1e6)
        # EPB 头: iface_id / ts_hi / ts_lo / captured_len (规范无 original_len)
        epb = struct.pack(E + "IIII", 0, tus >> 32, tus & 0xFFFFFFFF, len(raw)) + raw
        out += blk(6, epb)
    return out


def _tmp(data, suffix=".pcap"):
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    f.write(data)
    f.close()
    return f.name


# ============ 测试 ============
class CoapParseTest(unittest.TestCase):
    def test_parse_discover_post(self):
        c = coap_post(["softbus", "device_discover"],
                      payload=b'{"deviceId":"abc-123"}')
        p = pa.parse_coap(c)
        self.assertIsNotNone(p)
        self.assertEqual(p["uri_paths"], ["softbus", "device_discover"])
        self.assertEqual(p["payload"], b'{"deviceId":"abc-123"}')

    def test_parse_empty_payload(self):
        c = coap_post(["softbus"], payload=b"")
        p = pa.parse_coap(c)
        self.assertEqual(p["uri_paths"], ["softbus"])
        self.assertEqual(p["payload"], b"")

    def test_non_coap_rejected(self):
        self.assertIsNone(pa.parse_coap(b"\x00\x00\x00\x00"))  # ver=0
        self.assertIsNone(pa.parse_coap(b"abc"))               # len<4
        self.assertIsNone(pa.parse_coap(b""))                  # 空


class DeviceInfoTest(unittest.TestCase):
    def test_json_payload(self):
        info = pa.extract_device_info(
            {"payload": b'{"deviceId":"d1","devicename":"MB","type":"0x0E"}'})
        self.assertEqual(info["deviceId"], "d1")
        self.assertEqual(info["devicename"], "MB")

    def test_fallback_regex(self):
        # 非严格 JSON(缺引号)走正则降级
        info = pa.extract_device_info({"payload": b'{deviceId: "d2", devicename: "X"}'})
        self.assertEqual(info.get("deviceId"), "d2")

    def test_empty(self):
        self.assertIsNone(pa.extract_device_info({"payload": b""}))


class PipelineTest(unittest.TestCase):
    def _discover_pkt(self, payload):
        coap = coap_post(["softbus", "device_discover"], payload=payload)
        return udp_packet("192.168.1.10", "224.0.0.1", 49152, 5683, coap)

    def test_pcap_full_pipeline(self):
        pl = (b'{"deviceId":"d1","devicename":"MateBook",'
              b'"type":"0x0E","softbusVersion":"5.0.2"}')
        data = pcap_file([(1000.0, self._discover_pkt(pl))])
        path = _tmp(data)
        try:
            r = pa.analyze(path)
            self.assertEqual(r["stats"]["total"], 1)
            self.assertEqual(r["stats"]["discovery"], 1)
            self.assertEqual(len(r["devices"]), 1)
            names = [d.get("devicename") for d in r["devices"].values()]
            self.assertIn("MateBook", names)
            fields = [x["field"] for x in r["stats"]["plaintext_fields"]]
            self.assertIn("deviceId", fields)
            self.assertIn("devicename", fields)
        finally:
            os.unlink(path)

    def test_pcapng_pipeline(self):
        pl = b'{"deviceId":"d2","devicename":"Phone","type":"0x11"}'
        data = pcapng_file([(2000.0, self._discover_pkt(pl))])
        path = _tmp(data, ".pcapng")
        try:
            r = pa.analyze(path)
            self.assertEqual(r["stats"]["discovery"], 1)
            names = [d.get("devicename") for d in r["devices"].values()]
            self.assertIn("Phone", names)
        finally:
            os.unlink(path)

    def test_non_coap_port_ignored(self):
        # HTTP on port 80 —— 不应产生设备/发现
        pkt = udp_packet("1.2.3.4", "5.6.7.8", 1234, 80,
                         b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        path = _tmp(pcap_file([(1.0, pkt)]))
        try:
            r = pa.analyze(path)
            self.assertEqual(r["stats"]["discovery"], 0)
            self.assertEqual(len(r["devices"]), 0)
            self.assertEqual(r["stats"]["coap"], 0)
        finally:
            os.unlink(path)

    def test_multi_packet_aggregation(self):
        pl = b'{"deviceId":"d1","devicename":"MB"}'
        pkts = [self._discover_pkt(pl), self._discover_pkt(pl)]
        path = _tmp(pcap_file([(1.0, pkts[0]), (2.0, pkts[1])]))
        try:
            r = pa.analyze(path)
            self.assertEqual(len(r["devices"]), 1)
            dev = list(r["devices"].values())[0]
            self.assertEqual(dev["events"], 2)       # 两包聚合同一设备
            self.assertIn("192.168.1.10", dev["src_ips"])
        finally:
            os.unlink(path)

    def test_bad_magic_raises(self):
        path = _tmp(b"NOTAPCAP" + b"\x00" * 100)
        try:
            with self.assertRaises(Exception):
                pa.analyze(path)
        finally:
            os.unlink(path)


class RenderTest(unittest.TestCase):
    def test_render_json_valid(self):
        pl = b'{"deviceId":"d1","devicename":"MB"}'
        path = _tmp(pcap_file([(1.0, udp_packet("10.0.0.1", "10.0.0.2",
                                                40000, 5683,
                                                coap_post(["softbus", "device_discover"], payload=pl)))]))
        try:
            r = pa.analyze(path)
            import json
            obj = json.loads(pa.render_json(r))   # 必须是合法 JSON
            self.assertIn("devices", obj)
            self.assertIn("stats", obj)
            self.assertEqual(len(obj["devices"]), 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
