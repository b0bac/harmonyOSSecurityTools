# Harmony OS 安全脚本积累
## 目录
[toc]
## DSoftBusScanner 基于DsoftBus的鸿蒙设备识别
**HarmonyOS DSoftBus (分布式软总线) 探测与指纹识别工具**，可以在局域网内发现 HarmonyOS/OpenHarmony 设备，识别设备形态(电视 / PC / 手机 / 平板)，输出带置信度的指纹报告。
+ 技术栈 (全部基于网络协议，纯标准库实现):
  + DSoftBus 发现:  CoAP over UDP 5684, 资源 /.well-known/core
  + UPnP/SSDP:      UDP 1900, 抓 description.xml (识别电视)
  + ICMP/TTL:       区分 Windows(128) vs Linux/HarmonyOS(64)
  + TCP 端口:       SMB(445) / RDP(3389) / adb(5037)
  + 行为时序:       连续监测在线率 (区分常驻/休眠)

+ 用法:
  + python dsoftbus_scanner.py scan                  # 全网扫描 (默认)
  + python dsoftbus_scanner.py scan --subnet 192.168.3.0/24
  + python dsoftbus_scanner.py deep --ip 192.168.3.72
  + python dsoftbus_scanner.py monitor --rounds 10 --interval 12
  + python dsoftbus_scanner.py multicast
  + python dsoftbus_scanner.py linktest --ip 192.168.3.72
  + python dsoftbus_scanner.py export --format json
 

<img width="1835" height="502" alt="image" src="https://github.com/user-attachments/assets/73a75d82-29f1-4e37-bf4b-70bd9b8949c7" />

## dsoftbus_probe — DSoftBus 设备发现探测与被动嗅探
**HarmonyOS NEXT (PC) DSoftBus 设备发现探测工具**，支持主动探测与被动监听，覆盖 CoAP(LAN) 与 BLE 两个发现通道，输出实时流式设备表格。详细手册见 `dsoftbus_probe_使用说明.md`。

+ 技术栈 (纯标准库，可选 scapy/bleak 增强):
  + CoAP 发现: UDP 5684, POST `device_discover`, NON 广播 / ACK 单播
  + BLE 发现:  软总线 TLV 固定头解析 + 华为 company id(`0x01D6`) 识别
  + 主动 scan: 广播/定向探测, 支持 `-n 0` 主动雷达(可发现息屏设备)
  + 被动 sniff: scapy 深度嗅探 / socket 降级双模式
  + 设备伪装: 自定义 `--device-name/--device-type/--capability` 等字段
  + pcap 落盘: 合成 Ether+IP+UDP 帧, Wireshark 可直接打开
  + 类型判断: 设备名启发式(准) > type/typeEx 映射, 带 `✓`/`※` 置信标记

+ 用法:
  + `python dsoftbus_probe.py selftest`                         # 自检
  + `python dsoftbus_probe.py scan`                             # 广播探测整网
  + `python dsoftbus_probe.py scan -n 0 --interval 5`           # 主动雷达(覆盖息屏设备)
  + `python dsoftbus_probe.py scan -t 192.168.1.0/24 -o r.json` # CIDR 定向 + JSON 落盘
  + `sudo python dsoftbus_probe.py sniff --pcap cap.pcap`       # 被动嗅探 + pcap
  + `python dsoftbus_probe.py ble -d 30`                        # BLE 通道扫描

### DSoftBusScanner 与 dsoftbus_probe 定位对比
| 工具 | 侧重 |
|------|------|
| DSoftBusScanner | 多协议指纹(SSDP/ICMP/TCP端口/时序)综合识别设备形态 |
| dsoftbus_probe  | 聚焦 CoAP/BLE 发现协议本身：主动探测 + 被动嗅探 + 伪装 + pcap |

> 协议依据均来自 OpenHarmony `communication_dsoftbus` 源码（coap_app.h / coap_discover.c / json_payload.h / disc_ble_constant_struct.h）。仅用于授权安全测试。

