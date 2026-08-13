# pcap_analyzer — DSoftBus(分布式软总线)PCAP 深度分析器

离线解析抓包文件,识别 HarmonyOS 软总线流量并提取明文敏感信息。

## 能力

- **自研 pcap / pcapng 解析器**(纯标准库,不依赖 scapy,Mac/Linux 自带 python3 即可)。
- 链路层支持:Ethernet(1)/ Linux-SLL(113,`tcpdump -i any`)/ Raw-IP(228,101)。
- 识别 **CoAP over UDP 5683/5684** 的设备发现(`device_discover`)流量。
- 从 cJSON payload 提取 `deviceId / devicename / type / mode / hicomname` 等字段。
- 输出:**设备清单**、**发现事件时间线**、**明文敏感字段告警**;若发现版本字段
  (softbusVersion 等)提示联动 `vuln_mapper` 核对受影响 CVE。
- 非盲降噪:非 CoAP 端口上的随机流量(HTTP/DNS 等)不会误报。

## 用法

```bash
# 分析(人类可读报告)
python3 pcap_analyzer.py capture.pcap
python3 pcap_analyzer.py capture.pcapng

# 仅设备清单(tab 分隔, 便于脚本处理)
python3 pcap_analyzer.py capture.pcap --devices

# 机器可读(JSON, 可 jq)
python3 pcap_analyzer.py capture.pcap --json | jq '.devices'
```

## 抓包方法(获取 DSoftBus 流量)

在同网段一台主机上抓软总线设备发现组播:

```bash
# macOS / Linux
sudo tcpdump -i <网卡> -w dsoftbus.pcap 'udp port 5683 or udp port 5684'
# 或在 HarmonyOS 设备上(tcpdump -i any 用 Linux-SLL, 本工具已支持)
```

> 软总线设备发现走 CoAP 组播,抓几分钟即可看到 `device_discover` 报文。

## 输出说明

| 段 | 内容 |
|----|------|
| 设备清单 | devicename / type / deviceId / IP / 事件数 / 首见时间;版本字段联动提示 |
| 明文敏感字段告警 | 设备发现报文中明文暴露的 deviceId/devicename 等 |
| 发现事件时间线 | 每条 discovery 的 src→dst、CoAP code、Uri-Path |

## 测试

```bash
python3 test_pcap_analyzer.py
```

12 项单元测试(含合成 pcap/pcapng 跑通全链路:CoAP 解析、设备聚合、明文提取、
干扰排除、bad magic 拒绝)。

## 局限

- 当前聚焦 **CoAP 设备发现**(device_discover)阶段;传输会话(transbus)阶段
  的密文/动态端口解析未覆盖(后续可扩展)。
- 仅 IPv4/IPv6 + UDP;不支持 TCP 封装的 CoAP(RFC 8323,软总线基本不用)。
- cJSON 字段提取依赖 payload 为文本 JSON 或近 JSON;二进制私有扩展需另抓包对照。

仅用于授权安全测试 / 流量审计。离线分析,不联网。
