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

