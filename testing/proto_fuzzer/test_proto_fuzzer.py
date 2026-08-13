#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_proto_fuzzer.py — proto_fuzzer 单元测试

用本地 UDP echo server(127.0.0.1 回环)模拟目标, 验证探测/分类/授权门控,
不触碰外部网络。
    python test_proto_fuzzer.py
"""
import os
import sys
import socket
import threading
import subprocess
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proto_fuzzer as pf

DIR = os.path.dirname(os.path.abspath(__file__))


def start_echo(behavior="normal"):
    """behavior: normal(回2.05) / silent(不回) / server_error(回5.00)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.settimeout(0.3)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if behavior == "silent":
                continue
            mid = data[2:4] if len(data) >= 4 else b"\x00\x00"
            if behavior == "server_error":
                resp = bytes([0x60, 0xA0]) + mid      # ACK 5.00
            else:
                resp = bytes([0x60, 0x45]) + mid      # ACK 2.05 Content
            try:
                s.sendto(resp, addr)
            except OSError:
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return s, port, stop


class BuildTest(unittest.TestCase):
    def test_normal_packet(self):
        pkt = pf._normal()
        self.assertGreaterEqual(len(pkt), 4)
        self.assertEqual((pkt[0] >> 6) & 0x3, 1)       # ver=1

    def test_all_mutations_valid(self):
        for name, _desc, fn in pf.MUTATIONS:
            pkt = fn()
            self.assertIsInstance(pkt, bytes)
            self.assertGreaterEqual(len(pkt), 4, f"{name} 过短")
            # 不应包含明显的利用特征(纯协议层)
            self.assertLess(len(pkt), 65000)

    def test_reserved_delta_marker(self):
        pkt = pf.build_coap(uri_paths=["softbus"], inject_opt=bytes([0xF0]))
        self.assertIn(b"\xf0", pkt)                    # 注入了 reserved delta


class ProbeTest(unittest.TestCase):
    def test_probe_response(self):
        srv, port, stop = start_echo("normal")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            obs = pf.probe(sock, "127.0.0.1", port, pf._normal(), 1.0)
            sock.close()
            self.assertTrue(obs["responded"])
            self.assertEqual(obs["resp_code"], "2.05")
            self.assertIsNone(obs["send_error"])
        finally:
            stop.set(); srv.close()

    def test_probe_timeout(self):
        srv, port, stop = start_echo("silent")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            t0 = __import__("time").monotonic()
            obs = pf.probe(sock, "127.0.0.1", port, pf._normal(), 0.6)
            elapsed = __import__("time").monotonic() - t0
            sock.close()
            self.assertFalse(obs["responded"])
            self.assertGreaterEqual(elapsed, 0.5)       # 确实等待了超时
        finally:
            stop.set(); srv.close()


class ClassifyTest(unittest.TestCase):
    def _base(self):
        return {"responded": True, "rtt": 0.02, "resp_code": "2.05",
                "resp_len": 10, "send_error": None}

    def test_silent_is_high(self):
        obs = {"responded": False, "rtt": 2, "resp_code": None,
               "resp_len": 0, "send_error": None}
        sevs = [s for s, _ in pf.classify(self._base(), obs)]
        self.assertIn("high", sevs)

    def test_server_error_is_med(self):
        obs = {"responded": True, "rtt": 0.02, "resp_code": "5.0",
               "resp_len": 8, "send_error": None}
        sevs = [s for s, _ in pf.classify(self._base(), obs)]
        self.assertIn("med", sevs)

    def test_client_error_is_low(self):
        obs = {"responded": True, "rtt": 0.02, "resp_code": "4.0",
               "resp_len": 8, "send_error": None}
        sevs = [s for s, _ in pf.classify(self._base(), obs)]
        self.assertIn("low", sevs)

    def test_normal_no_issue(self):
        obs = {"responded": True, "rtt": 0.02, "resp_code": "2.05",
               "resp_len": 10, "send_error": None}
        self.assertEqual(pf.classify(self._base(), obs), [])

    def test_send_error_info(self):
        obs = {"responded": False, "rtt": None, "resp_code": None,
               "resp_len": 0, "send_error": "refused"}
        sevs = [s for s, _ in pf.classify(self._base(), obs)]
        self.assertIn("info", sevs)


class RunTest(unittest.TestCase):
    def test_run_against_echo(self):
        srv, port, stop = start_echo("normal")
        try:
            report = pf.run("127.0.0.1", port, 1.0, 0.0)
            self.assertTrue(report["baseline"]["responded"])
            self.assertEqual(len(report["results"]), len(pf.MUTATIONS))
            # 正常 echo: 无 high(每个畸形都应得到 2.05 响应)
            highs = [r for r in report["results"]
                     if any(s == "high" for s, _ in r["issues"])]
            self.assertEqual(highs, [])
        finally:
            stop.set(); srv.close()

    def test_run_detects_silent(self):
        # server_error 模式下基线(2.05)与畸形都回 5.00; 用 silent 模式测无响应检测
        srv, port, stop = start_echo("silent")
        try:
            report = pf.run("127.0.0.1", port, 0.6, 0.0)
            # 基线也无响应 -> 不会标记 high(因为基线本就无响应); 不应崩溃
            self.assertFalse(report["baseline"]["responded"])
            self.assertEqual(len(report["results"]), len(pf.MUTATIONS))
        finally:
            stop.set(); srv.close()


class AuthGateTest(unittest.TestCase):
    def test_requires_authorization_flag(self):
        r = subprocess.run([sys.executable, "proto_fuzzer.py",
                            "--target", "127.0.0.1"],
                           capture_output=True, cwd=DIR, timeout=10)
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"\xe6\x8e\x88\xe6\x9d\x83", r.stderr)   # "授权" UTF-8

    def test_render_text_handles_no_issues(self):
        report = {"baseline": {"responded": True, "rtt": 0.01,
                               "resp_code": "2.05"},
                  "results": [{"mutation": "x", "desc": "d",
                               "obs": {"responded": True, "rtt": 0.01,
                                       "resp_code": "2.05"},
                               "issues": []}]}
        txt = pf.render_text(report, "127.0.0.1")
        self.assertIn("未观测到异常", txt)


if __name__ == "__main__":
    unittest.main()
