# proto_fuzzer — DSoftBus CoAP 协议健壮性探针(观测型)

向**显式授权的目标**发送畸形/边界 CoAP 报文,**只观测**目标响应,输出健壮性
报告。用于发现软总线协议解析的异常处理缺陷(模糊测试的被动观测面)。

> ⚠ **这不是利用工具。** 仅记录响应观测(返回码 / 超时 / 延迟),不构造利用链、
> 不尝试 RCE/提权、不含 shellcode、不做 DoS 压测。

## 授权要求(硬约束)

- 必须 `--target IP` **显式指定**单个授权目标(无默认、不扫描网段)。
- 必须 `--i-am-authorized` 确认你对目标拥有**书面测试授权**,否则拒绝运行。
- 默认低速:每包间隔 0.5s,报文总数固定(基线 + 10 个畸形用例),不构成压测。
- 使用前请再次确认目标在授权范围内。

## 用法

```bash
# 必须两个旗标同时存在
python3 proto_fuzzer.py --target 192.168.1.50 --i-am-authorized
python3 proto_fuzzer.py --target 192.168.1.50 --i-am-authorized --json
python3 proto_fuzzer.py --target 192.168.1.50 --i-am-authorized --rate 1.0 --timeout 3
```

## 畸形用例集(协议层边界, 非利用)

| 用例 | 说明 |
|------|------|
| `bad_coap_version` | 版本号非法(ver=2) |
| `reserved_option_delta` | 选项 delta=15(reserved) |
| `reserved_option_length` | 选项 length=15(reserved) |
| `oversize_token` | Token 达上限(8B) |
| `oversize_uri_path` | 超长 Uri-Path(300B) |
| `many_uri_options` | 大量重复 Uri-Path(30 个) |
| `truncated_packet` | 报文截断 |
| `empty_payload_discover` | device_discover 无 payload |
| `oversize_payload` | 超大 payload(2KB) |
| `dup_uri_path` | 重复路径段 |

## 输出说明

先发一个正常 `device_discover` 建立**基线**(记录是否响应 / 响应码 / RTT),
再逐个发送畸形用例并对比:

| 严重度 | 观测 | 含义 |
|--------|------|------|
| **HIGH** | 基线有响应、本包无响应 | 可能解析丢弃/崩溃, 建议抓包深入分析 |
| MED | 5.xx 响应 | 服务器内部错误 |
| LOW | 4.xx 响应 / 延迟异常 | 正常拒绝或处理慢 |

报告**只记录观测,不判定可利用性**;HIGH 项是需要人工跟进的线索。

## 测试

```bash
python3 test_proto_fuzzer.py
```

14 项:用本地 UDP echo server(127.0.0.1 回环)模拟目标,覆盖探测、分类、
授权门控、完整 run 流程——**不触碰外部网络**。

## 局限与伦理

- 黑盒观测:无法区分"丢弃"是因解析崩溃还是主动忽略,需结合 `pcap_analyzer`
  抓包或设备侧 `hilog` 进一步判断。
- 仅 CoAP over UDP 5683;未覆盖认证后/加密会话阶段。
- 即便授权,**禁止**对生产系统、第三方设备、或未授权网络运行本工具。

仅用于已获书面授权的安全测试。
