#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proto_fuzzer.py — DSoftBus CoAP 协议健壮性探针(观测型)

向【显式授权的目标】发送畸形/边界 CoAP 报文, 仅【观测】目标响应, 输出健壮性
报告。用于发现协议解析的异常处理缺陷(模糊测试的被动观测面)。

  ✅ 做的事: 发协议层畸形输入 -> 记录 响应/超时/延迟/错误码 -> 报告异常观测
  ❌ 不做的事: 不构造利用链 / 不尝试 RCE 或提权 / 不含 shellcode / 不做 DoS 压测

强授权门控: 必须显式 --target IP 且 --i-am-authorized。默认低速(每包 0.5s 间隔)。

用法:
    python3 proto_fuzzer.py --target 192.168.1.50 --i-am-authorized
    python3 proto_fuzzer.py --target 192.168.1.50 --i-am-authorized --json
    python3 proto_fuzzer.py --target 192.168.1.50 --i-am-authorized --rate 1.0 --timeout 3

仅用于已获书面授权的安全测试。主动发送报文, 使用前请确认授权范围。
"""
import os
import sys
import json
import time
import socket
import struct
import argparse

VERSION = "0.1"
DEFAULT_PORT = 5683
DEFAULT_TIMEOUT = 2.0
DEFAULT_RATE = 0.5     # 每包间隔(秒)—— 保守, 避免对目标造成压力


# ---------------------------------------------------------------------------
# CoAP 构建(支持注入畸形)
# ---------------------------------------------------------------------------
def _enc_nib(v):
    if v < 13:
        return v, b""
    if v < 269:
        return 13, bytes([v - 13])
    return 14, struct.pack("!H", v - 269)


def _opt(delta, length):
    d_n, d_e = _enc_nib(delta)
    l_n, l_e = _enc_nib(length)
    return bytes([(d_n << 4) | l_n]) + d_e + l_e


def build_coap(ver=1, mtype=1, tkl=0, token=b"", code=0x02, mid=1,
               uri_paths=None, payload=b"", inject_opt=None, truncate=0):
    """组装 CoAP 报文。畸形参数: ver/inject_opt/truncate/超长 uri 等"""
    b0 = ((ver & 0x3) << 6) | ((mtype & 0x3) << 4) | (tkl & 0xF)
    out = bytes([b0, code & 0xFF]) + struct.pack("!H", mid & 0xFFFF)
    out += bytes(token)[:tkl]
    if uri_paths:
        first = True
        for p in uri_paths:
            d = 11 if first else 0
            first = False
            pb = p.encode() if isinstance(p, str) else p
            out += _opt(d, len(pb)) + pb
    if inject_opt is not None:          # 手工注入(用于 reserved delta/length)
        out += inject_opt
    if payload:
        out += b"\xff" + payload
    if truncate and len(out) > 4:
        out = out[:max(4, len(out) - truncate)]
    return out


def resp_code_str(data):
    if len(data) >= 2:
        c = data[1]
        return f"{c >> 5}.{c & 0x1F:02d}"    # CoAP 标准记法 class.detail(detail 补零)
    return None


# ---------------------------------------------------------------------------
# 畸形用例集(协议层边界, 不含利用)
# ---------------------------------------------------------------------------
def _normal():
    return build_coap(uri_paths=["softbus", "device_discover"],
                      payload=b'{"deviceId":"fuzz"}')


MUTATIONS = [
    # (名称, 说明, 生成函数)
    ("bad_coap_version",
     "版本号非法(ver=2), 合法实现应丢弃",
     lambda: build_coap(ver=2, uri_paths=["softbus", "device_discover"])),
    ("reserved_option_delta",
     "选项 delta=15(reserved), 合法实现应拒绝解析",
     lambda: build_coap(uri_paths=["softbus", "device_discover"],
                        inject_opt=bytes([0xF0]))),
    ("reserved_option_length",
     "选项 length=15(reserved), 合法实现应拒绝解析",
     lambda: build_coap(uri_paths=["softbus", "device_discover"],
                        inject_opt=bytes([0x0F]))),
    ("oversize_token",
     "Token 达上限(8B)",
     lambda: build_coap(tkl=8, token=b"A" * 8,
                        uri_paths=["softbus", "device_discover"])),
    ("oversize_uri_path",
     "超长 Uri-Path(300B)",
     lambda: build_coap(uri_paths=["softbus", "X" * 300])),
    ("many_uri_options",
     "大量重复 Uri-Path 选项(30 个)",
     lambda: build_coap(uri_paths=["softbus"] + ["device_discover"] * 30)),
    ("truncated_packet",
     "报文截断(末尾 20B 缺失)",
     lambda: build_coap(uri_paths=["softbus", "device_discover"],
                        payload=b'{"deviceId":"x"}', truncate=20)),
    ("empty_payload_discover",
     "device_discover 无 payload",
     lambda: build_coap(uri_paths=["softbus", "device_discover"])),
    ("oversize_payload",
     "超大 payload(2KB)",
     lambda: build_coap(uri_paths=["softbus", "device_discover"],
                        payload=b'{"deviceId":"' + b"A" * 2000 + b'"}')),
    ("dup_uri_path",
     "重复 device_discover 路径段",
     lambda: build_coap(uri_paths=["softbus", "device_discover",
                                   "device_discover"])),
]


# ---------------------------------------------------------------------------
# 探测 + 分类
# ---------------------------------------------------------------------------
def probe(sock, target, port, pkt, timeout):
    """发送一个包, 观测响应。返回观测 dict"""
    t0 = time.monotonic()
    try:
        sock.sendto(pkt, (target, port))
    except OSError as e:
        return {"responded": False, "rtt": None, "resp_code": None,
                "resp_len": 0, "send_error": str(e)}
    sock.settimeout(timeout)
    try:
        data, _addr = sock.recvfrom(4096)
        return {"responded": True, "rtt": round(time.monotonic() - t0, 4),
                "resp_code": resp_code_str(data), "resp_len": len(data),
                "send_error": None}
    except socket.timeout:
        return {"responded": False, "rtt": timeout, "resp_code": None,
                "resp_len": 0, "send_error": None}


def classify(baseline, obs):
    """对比基线, 返回观测到的异常列表(只观测, 不判定可利用性)"""
    issues = []
    if obs.get("send_error"):
        issues.append(("info", f"send_error:{obs['send_error']}"))
        return issues
    # 基线有响应但本包无 -> 可能解析丢弃/崩溃
    if baseline["responded"] and not obs["responded"]:
        issues.append(("high", "silent_no_response (基线有响应, 本包无响应)"))
    # 5.xx 服务器错误
    if obs["resp_code"] and obs["resp_code"].split(".")[0] == "5":
        issues.append(("med", f"server_error {obs['resp_code']}"))
    # 4.xx 是正常拒绝, 仅记录
    if obs["resp_code"] and obs["resp_code"].split(".")[0] == "4":
        issues.append(("low", f"client_error {obs['resp_code']} (正常拒绝)"))
    # 延迟异常
    if (baseline["responded"] and obs["responded"]
            and baseline["rtt"] and obs["rtt"]
            and obs["rtt"] > baseline["rtt"] * 5 + 0.5):
        issues.append(("low", "timing_anomaly (响应延迟显著高于基线)"))
    return issues


def run(target, port, timeout, rate):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    results = []
    try:
        # 基线(正常 discover)
        baseline = probe(sock, target, port, _normal(), timeout)
        time.sleep(rate)
        for name, desc, fn in MUTATIONS:
            obs = probe(sock, target, port, fn(), timeout)
            issues = classify(baseline, obs)
            results.append({"mutation": name, "desc": desc,
                            "obs": obs, "issues": issues})
            time.sleep(rate)
    finally:
        sock.close()
    return {"baseline": baseline, "results": results}


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
def _sev_rank(s):
    return {"high": 0, "med": 1, "low": 2, "info": 3}.get(s, 9)


def render_text(report, target):
    base = report["baseline"]
    lines = [f"[+] DSoftBus CoAP 健壮性探针 v{VERSION}",
             f"[+] 目标 {target}  |  基线响应: "
             f"{'有(' + str(base['resp_code']) + ', ' + str(base.get('rtt')) + 's)' if base['responded'] else '无响应'}"]
    sev_count = {"high": 0, "med": 0, "low": 0, "info": 0}
    for r in report["results"]:
        for sev, _ in r["issues"]:
            sev_count[sev] = sev_count.get(sev, 0) + 1
    lines.append(f"[+] 观测汇总: high={sev_count['high']} "
                 f"med={sev_count['med']} low={sev_count['low']}")
    lines.append("")
    # 按 severity 排序输出异常项
    flagged = [r for r in report["results"] if r["issues"]]
    flagged.sort(key=lambda r: min(_sev_rank(s) for s, _ in r["issues"]))
    if not flagged:
        lines.append("[+] 未观测到异常: 所有畸形输入均被正常拒绝或忽略。")
    else:
        lines.append("[+] 观测到异常的用例(按严重度):")
        for r in flagged:
            top = min((s for s, _ in r["issues"]), key=_sev_rank)
            lines.append(f"    [{top.upper():4}] {r['mutation']}")
            lines.append(f"           {r['desc']}")
            obs = r["obs"]
            lines.append(f"           响应: "
                         f"{'有 ' + str(obs['resp_code']) + ' / ' + str(obs['rtt']) + 's' if obs['responded'] else '无(超时)'}")
            for sev, msg in r["issues"]:
                lines.append(f"           - {sev}: {msg}")
    lines.append("")
    lines.append("说明: 本报告仅记录响应观测, 不判定可利用性。")
    lines.append("      high 项(基线有响应但畸形输入无响应)建议人工抓包深入分析。")
    return "\n".join(lines)


def render_json(report, target):
    return json.dumps({"version": VERSION, "target": target,
                       **report}, ensure_ascii=False, indent=2)


def main():
    ap = argparse.ArgumentParser(
        description="DSoftBus CoAP 协议健壮性探针(观测型, 需授权)")
    ap.add_argument("--target", required=True,
                    help="目标 IP(必须显式指定授权目标)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--rate", type=float, default=DEFAULT_RATE,
                    help="每包间隔秒数(默认 0.5, 保守)")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="确认你对目标拥有书面测试授权(必须)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not args.i_am_authorized:
        sys.stderr.write(
            "拒绝运行: 未确认授权。\n"
            "本工具仅用于对已获书面授权的目标进行协议健壮性测试, 主动发送报文。\n"
            f"请确认你对 {args.target} 拥有测试授权后, 加 --i-am-authorized 运行。\n")
        sys.exit(2)

    sys.stderr.write(
        f"[!] 即将向 {args.target}:{args.port} 发送 {len(MUTATIONS)+1} 个探测包"
        f"(每包间隔 {args.rate}s)。确认目标在授权范围内。\n")
    report = run(args.target, args.port, args.timeout, args.rate)
    if args.json:
        print(render_json(report, args.target))
    else:
        print(render_text(report, args.target))


if __name__ == "__main__":
    main()
