# DSoftBus Probe 使用说明

> HarmonyOS NEXT (PC) 分布式软总线（DSoftBus）设备发现探测工具
> 文件：`dsoftbus_probe.py` ｜ 语言：Python 3.7+ ｜ 用途：授权安全测试 / 协议分析

---

## 一、工具简介

`dsoftbus_probe.py` 用于对 HarmonyOS NEXT（PC / 手机 / 平板等）的 DSoftBus 设备发现协议进行**主动探测**与**被动监听**，帮助安全研究人员：

- 主动发现局域网内的 HarmonyOS 设备并采集设备画像（设备名 / 类型 / deviceId / IP / 能力位图等）
- 被动嗅探设备间的发现报文（信息泄露面分析）
- 通过 BLE 通道被动扫描周边 HarmonyOS 设备
- 将抓包导出为 pcap 供 Wireshark 深入分析

**仅做发现探测与被动监听，不发送任何攻击性载荷。** 请勿用于未授权网络。

---

## 二、协议背景（源码依据）

HarmonyOS 分布式软总线的设备发现基于两个通道：

| 通道 | 协议 | 端口/标识 | 依据 |
|------|------|-----------|------|
| **LAN 发现** | CoAP over UDP | **UDP/5684** | `coap_app.h` → `COAP_SRV_DEFAULT_PORT` |
| **BLE 发现** | BLE 广播 + 自定义 TLV | service data / 华为 company id `0x01D6` | `disc_ble_constant_struct.h` / 蓝牙 SIG |

- **LAN 发现报文**：`CoAP POST`，URI-Path = `device_discover`，广播用 `NON`、单播响应用 `ACK`，payload 为 cJSON。
- **BLE 广播 payload**：固定头 7 字节 `[version=4, business, businessExt, userIdHash×2, capability, capabilityExt]` + TLV（`type<<4|len`），TLV 含 `deviceIdHash/deviceType/deviceName/brMac`。

---

## 三、环境与依赖

### 基础运行（零依赖）
Python 3.7+ 标准库即可运行 `scan`（socket 模式）和 `sniff`（socket 降级模式）。

### 可选增强依赖

| 功能 | 依赖 | 安装 | 说明 |
|------|------|------|------|
| 深度被动嗅探（抓单播响应） | `scapy` | `pip install scapy` | 需 `sudo`/管理员 |
| BLE 通道扫描 | `bleak` | `pip install bleak` | 需蓝牙硬件；macOS 需授蓝牙权限 |

> 不安装可选依赖也能用，工具会自动降级并在终端提示。

### 平台支持

| 平台 | scan | sniff(socket) | sniff(scapy) | BLE |
|------|------|---------------|--------------|-----|
| macOS | ✅ | ✅ | ✅(sudo) | ✅(bleak，需授权) |
| Linux | ✅ | ✅ | ✅(sudo) | ✅(bleak/bluez) |
| Windows | ✅ | ✅ | ⚠️ | ✅(bleak) |

---

## 四、快速开始

```bash
# 0. 自检（验证 CoAP 编解码 / BLE 解析 / pcap 逻辑）
python3 dsoftbus_probe.py selftest

# 1. 主动探测整网（广播 device_discover，收响应）
python3 dsoftbus_probe.py scan

# 2. 被动嗅探（需 sudo 用 scapy 抓全部流量，含单播响应）
sudo python3 dsoftbus_probe.py sniff

# 3. BLE 扫描周边 HarmonyOS 设备
pip install bleak
python3 dsoftbus_probe.py ble -d 30

# 4. 抓包导出 pcap，用 Wireshark 分析
sudo python3 dsoftbus_probe.py sniff --pcap cap.pcap
```

---

## 五、命令详解

### 5.1 `selftest` — 内置自检

```bash
python3 dsoftbus_probe.py selftest
```
验证 CoAP 报文编解码、伪装字段、BLE TLV 解析、pcap 写入等核心逻辑（共 18 项），**不接触网络**。部署到新环境建议先跑一次。

---

### 5.2 `scan` — 主动探测

构造 `device_discover` 探测报文，向广播地址 / 定向目标发送，收集对端单播回的设备画像。

```bash
python3 dsoftbus_probe.py scan [选项]
```

| 选项 | 默认 | 说明 |
|------|------|------|
| `-t, --target` | （无） | 定向目标：支持 `IP` / `CIDR`(192.168.1.0/24) / `范围`(192.168.1.1-20) / `逗号列表` |
| `-b, --bcast` | `255.255.255.255` | 广播地址（受限广播；可改子网广播如 `192.168.1.255`） |
| `--ip` | 自动 | 指定本机出口 IP |
| `-i, --iface` | （无） | 绑定网卡（Linux `SO_BINDTODEVICE`） |
| `--timeout` | `3.0` | 发送后继续监听响应时长（秒） |
| `--interval` | `1.0` | 每轮探测间隔（秒） |
| `-n, --count` | `1` | 探测轮数 |
| `-o, --output` | （无） | 结果落盘 JSON 路径 |
| `--pcap` | （无） | pcap 落盘路径 |
| `-v, --verbose` | 关 | 详细调试输出 |
| **伪装参数** | | 见 5.2.1 |

**示例：**

```bash
# 广播探测 + 定向探测混合，结果存 JSON
python3 dsoftbus_probe.py scan -t 192.168.1.0/24 -o result.json

# 多轮探测（提高发现率）
python3 dsoftbus_probe.py scan -n 3 --interval 2

# 持续轮询「主动雷达」——可发现息屏/空闲设备（对端 5684 服务常驻即响应）
python3 dsoftbus_probe.py scan -n 0 --interval 5

# 伪装成手机发起探测
python3 dsoftbus_probe.py scan --device-name "MyPhone" --device-type 0 --capability 1
```

#### 5.2.1 伪装字段（可选）

自定义探测报文中「本机设备」的画像字段，用于测试对端对特定设备类型的响应差异：

| 选项 | 对应 payload 字段 | 说明 |
|------|-------------------|------|
| `--device-name` | `devicename` | 设备名 |
| `--device-type` | `type` / `typeEx` | 设备类型（数字，见下表） |
| `--capability` | `capabilityBitmap` | 能力位图，逗号分隔（如 `0,1,2`） |
| `--device-id` | `deviceId` | 设备 ID（不指定则随机） |
| `--service-data` | `serviceData` | 业务数据字符串 |
| `--mode` | `mode` | 发布模式 |

**设备类型说明（重要）：**

OpenHarmony 开源版 `DeviceType` 枚举（`softbus_common.h`）：

| 值 | 含义 | 值 | 含义 |
|----|------|----|------|
| 0 | 智能音箱 Speaker | 5 | 手表 Watch |
| 1 | 台式机 Desktop | 6 | 车机 Car |
| 2 | 笔记本 Laptop | 7 | 儿童手表 KidsWatch |
| 3 | 手机 Phone | 8 | 智慧屏 TV |
| 4 | 平板 Pad | | |

> ⚠️ **HarmonyOS NEXT 商用版的 type 枚举与开源版不同**（实测：MateBook=0、Mate X5=14、MatePad Air=17，与上表冲突）。因此工具的**类型判断优先用设备名启发式**（识别 MateBook/MatePad/Mate X/Pura/Mate60 等型号），type 字段仅作参考。输出表格中：
> - `✓` = 设备名启发式判定（高置信，推荐参考）
> - `※` = 基于 type/typeEx 字段映射（商用版可能不准）

如需用实测值校准 type 映射，用 `--type-map` 加载自定义 JSON：
```bash
# type_map.json 内容示例： {"14":"手机(Phone)","0":"笔记本(Laptop)","17":"平板(Pad)"}
python3 dsoftbus_probe.py scan --type-map type_map.json
```

---

### 5.3 `sniff` — 被动监听

监听 UDP/5684 的 DSoftBus 报文并解析。默认**优先 scapy 深度嗅探**（抓全部流量含设备间单播响应），无 scapy 或无权限时**自动降级为 socket 绑定 5684**（仅收广播/发给本机的报文）。

```bash
python3 dsoftbus_probe.py sniff [选项]
```

| 选项 | 默认 | 说明 |
|------|------|------|
| `-d, --duration` | `0` | 监听时长秒（`0` = 持续至 Ctrl+C） |
| `-i, --iface` | （无） | 监听网卡（scapy 模式） |
| `--fallback` | 关 | 强制使用 socket 降级模式（不调 scapy） |
| `-o, --output` | （无） | 结果 JSON 路径 |
| `--pcap` | （无） | pcap 落盘路径 |
| `-v, --verbose` | 关 | 打印所有 CoAP 报文（含非 DSoftBus 的） |

**示例：**

```bash
# 深度嗅探 60 秒（需 sudo）
sudo python3 dsoftbus_probe.py sniff -d 60 --pcap cap.pcap

# 无 sudo 也能跑（socket 模式，只收广播）
python3 dsoftbus_probe.py sniff --fallback

# 持续监听
sudo python3 dsoftbus_probe.py sniff
```

> **两种模式差异**：
> - **scapy 模式**：能抓到局域网内**所有**设备间的发现报文（含 A 给 B 的单播响应），信息最全，需 root。
> - **socket 模式**：只抓到**广播报文**和**发给本机**的报文，抓不到他人之间的单播；普通权限即可。

---

### 5.4 `ble` — BLE 通道被动扫描

用 `bleak` 监听 BLE 广播，按 HarmonyOS 软总线 TLV 格式 + 华为 company id `0x01D6` 识别并解析设备。

```bash
python3 dsoftbus_probe.py ble [选项]
```

| 选项 | 默认 | 说明 |
|------|------|------|
| `-d, --duration` | `15` | 扫描时长秒 |
| `-o, --output` | （无） | 结果 JSON 路径 |
| `-v, --verbose` | 关 | 打印所有 BLE 广播（含非 HarmonyOS） |

**示例：**

```bash
python3 dsoftbus_probe.py ble -d 30 -o ble.json -v
```

**识别逻辑：**
1. 优先解析 service data 为软总线 TLV（version 合理 + 能解出 deviceIdHash/type/name）→ 标记 `[软总线]`
2. service data 不符但 manufacturer data 含华为 company id `0x01D6` → 标记 `[华为设备(疑似)]`

> ⚠️ **限制**：BLE **主动广播**（伪装成 HarmonyOS 设备让别的设备主动发现你）在 PC 上跨平台库支持不稳定，本工具**仅做被动扫描**。如需主动端，建议用 HarmonyOS 真机。

---

### 5.5 `nan` — WiFi Aware 通道评估

```bash
python3 dsoftbus_probe.py nan
```
输出 WiFi Aware (NAN) 通道在 PC 上的可行性评估。结论：**PC 上不可行**（无成熟跨平台库 + 需 NAN 硬件驱动），建议 NAN 测试用真机。

---

### 5.6 `both` — 探测 + 持续监听

先执行一次 `scan`，然后进入持续 `sniff`。

```bash
python3 dsoftbus_probe.py both [选项]
```
支持 `scan` 的目标 / 广播 / 伪装 / pcap 等参数。

---

## 六、输出说明

### 6.1 终端输出（实时流式表格）

扫描过程**实时增量显示**：开始打印一次表头，每识别到一台**新设备**就追加一行；**重复设备和普通数据包静默不输出**，过程安静。结束后打印统计行。

```
23:18:28  scan 主动探测中（识别到新设备即追加一行，重复设备静默；Ctrl+C 结束）
  #  通道         IP/BLE-addr       设备名                      类型  [✓=名称启发(准) / ※=type字段(参考)]
----------------------------------------------------------------------------------------------------
  1  CoAP/5684  192.168.1.50      Mate X5                手机(Phone) ✓  matex5
  2  CoAP/5684  192.168.1.20      MateBook 14            笔记本/PC ✓   book
  3  CoAP/5684  192.168.1.30      MatePad Air            平板(Pad) ✓   pad

23:18:30  完成：共发现 3 台设备
```

| 列 | 含义 |
|----|------|
| 通道 | `CoAP/5684`（LAN）或 `BLE` |
| IP/BLE-addr | 设备 IP（CoAP）或蓝牙 MAC（BLE） |
| 设备名 | `devicename` |
| 类型 | 设备类型，带置信标记：`✓`=设备名启发式判定（准确）；`※ [type=N/typeEx=M]`=基于 type 字段映射（商用版仅供参考） |
| 末列 | deviceId（CoAP）或 deviceHash（BLE） |

> 需要看**每个收发包**的调试详情，加 `-v / --verbose`。

### 6.2 JSON 落盘（`-o`）

```json
{
  "tool": "dsoftbus_probe",
  "mode": "scan",
  "generated_at": "2026-08-12 22:56:12",
  "device_count": 2,
  "devices": [ { ...完整设备字段... } ]
}
```

### 6.3 pcap 落盘（`--pcap`）

libpcap 格式（magic `0xA1B2C3D4`），每个 UDP/5684 报文合成为 `Ethernet + IPv4 + UDP` 帧。用 Wireshark 打开后可直接看到 CoAP 层：

```
Frame: ... 
  Ethernet + IPv4 + UDP (src:5684 -> dst:5684)
    CoAP: POST, MID=0x1234, URI-Path=device_discover
      JSON: {"deviceId":"...","devicename":"...","type":3,...}
```

---

## 七、典型场景

### 场景 1：测绘局域网内的 HarmonyOS 设备
```bash
python3 dsoftbus_probe.py scan -t 192.168.1.0/24 -o devices.json
```

### 场景 2：被动嗅探设备发现行为（信息泄露分析）
```bash
sudo python3 dsoftbus_probe.py sniff --pcap discovery.pcap
# 用 Wireshark 打开 discovery.pcap 分析设备画像字段是否过度暴露
```

### 场景 3：测试对端对不同设备类型的响应差异
```bash
python3 dsoftbus_probe.py scan --device-type 0 --device-name "AttackerPhone"   # 伪装手机
python3 dsoftbus_probe.py scan --device-type 3 --device-name "AttackerPC"      # 伪装 PC
```

### 场景 4：BLE 近场设备盘点
```bash
python3 dsoftbus_probe.py ble -d 30 -o ble.json -v
```

### 场景 5：长期部署被动监听
```bash
sudo python3 dsoftbus_probe.py sniff -o nightly_$(date +%F).json --pcap nightly_$(date +%F).pcap
```

---

## 八、工作原理简述

```
[主动 scan]
  本机构造 CoAP POST device_discover (NON, payload=本机设备JSON)
        │ UDP 广播 / 定向
        ▼
  HarmonyOS 设备(5684监听) ──解析探测包──> 记录我方设备
        │ CoAP ACK 单播 (payload=对方设备JSON)
        ▼
  本机接收 ──解析──> 提取 deviceId/名/类型/IP/能力 ──> 设备登记表(去重)

[被动 sniff]
  scapy/socket 监听 UDP/5684 ──> 解析每个 CoAP 报文的 JSON payload ──> 设备登记表 + pcap

[BLE scan]
  bleak 监听 BLE 广播 ──> service data 解析软总线TLV / 匹配华为0x01D6 ──> 设备登记表
```

---

## 九、故障排查（FAQ）

| 现象 | 原因 / 解决 |
|------|-------------|
| `selftest` 有 FAIL | 环境异常，先把 selftest 跑绿再上线 |
| scan 没发现设备 | ① 不在同一二层广播域；② 对端防火墙挡 5684；③ 试 `-n 3` 多轮、或换子网广播 `-b 192.168.1.255` |
| **被动 sniff 只能发现刚亮屏的设备** | 这是 DSoftBus 设计：发现受屏幕状态驱动（`SetScreenStatus`）、有限次广播（`advCount/advDuration`），息屏/空闲时静默不广播。**测绘设备请用主动 scan**：`scan -n 0 --interval 5` 无限轮询可覆盖息屏设备；被动 sniff 适合做「用户发现行为画像」 |
| sniff 抓不到他人单播响应 | socket 模式局限；装 scapy 后 `sudo` 运行 |
| `无法绑定 0.0.0.0:5684` | 端口被占用（本机可能已运行软总线）或需 root；用 `sudo` 或加 `--fallback` 配合已有监听 |
| scapy `PermissionError` | 需 `sudo`/管理员权限（原始套接字） |
| `BLE 扫描需要 bleak 库` | `pip install bleak` |
| macOS BLE 无结果 | 系统设置 → 隐私 → 蓝牙，授予终端权限；确认蓝牙开启 |
| 设备类型带 `※` 或判断不准 | HarmonyOS NEXT 商用版 type 枚举与开源版不同，type 字段仅供参考；带 `✓` 的为**设备名启发式判定（准确）**。可用 `--type-map type_map.json` 用实测值校准 |
| pcap 用 Wireshark 打开报错 | 确认文件未被截断（Ctrl+C 中断时 pcap 仍可读，无需封尾） |

---

## 十、安全与合规声明

- 本工具**仅发送设备发现探测报文（device_discover）**，不包含任何攻击 / 漏洞利用 / 凭证窃取载荷。
- 被动模式仅**监听**，不主动注入。
- **仅限在已获授权的网络 / 设备上使用**（自有测试环境、授权渗透测试、安全研究）。未经授权对他人网络进行探测可能违反相关法律法规。
- 使用者需自行承担合规责任。

---

## 十一、附录：关键常量

| 常量 | 值 | 来源 |
|------|----|------|
| CoAP 服务端口 | UDP **5684** | `COAP_SRV_DEFAULT_PORT` |
| 发现 URI | `device_discover` | `COAP_DEVICE_DISCOVER_URI` |
| CoAP 方法 | POST（`0x02`） | `coap_discover.c` |
| CoAP 消息类型 | 广播 `NON`(1) / 响应 `ACK`(2) | RFC 7252 |
| BLE 协议版本 | 4 | `BLE_VERSION` |
| BLE TLV 类型 | deviceIdHash=0x01, deviceType=0x02, deviceName=0x03, brMac=0x05 | `disc_ble_constant_struct.h` |
| 华为蓝牙 company id | `0x01D6` (470) | 蓝牙 SIG |

---

*文档与工具基于 OpenHarmony `communication_dsoftbus` 源码分析编写，适用于 HarmonyOS NEXT PC 及同源设备的安全研究。*
