# HarmonyOS / OpenHarmony DSoftBus 安全研究工具集

围绕**分布式软总线(DSoftBus)**的一套安全研究工具,覆盖完整链路:

**资产发现 → 流量/漏洞分析 → 协议健壮性测试 → 设备取证 / 信任拓扑测绘**

> ⚠ 双用途工具集。**仅用于已获书面授权**的安全测试 / 取证 / 防御研究。
> 主动型工具(proto_fuzzer、vuln_mapper scan)与设备取证工具(sensitive_collector)有**强授权门控**。
> 协议依据均来自 OpenHarmony `communication_dsoftbus` 源码(coap_app.h / coap_discover.c / json_payload.h 等)。

---

## 工具矩阵(速查)

| 工具 | 定位 | 目录 | 运行位置 | 主动发包 | 授权门控 | 自检 |
|------|------|------|----------|:--------:|:--------:|:----:|
| **DSoftBusScanner** | 多协议指纹综合识别设备形态 | `discovery/` | 主机(同网段) | 是(scan) | ❌ | selftest |
| **dsoftbus_probe** | CoAP/BLE 发现协议探测+被动嗅探 | `discovery/` | 主机(同网段) | 是 | ❌ | selftest |
| **pcap_analyzer** | 离线解析 DSoftBus 抓包 | `analysis/` | 主机 | ❌ | ❌ | 12 项 |
| **vuln_mapper** | CVE 知识库查询 / 设备-CVE 映射 | `analysis/` | 主机(scan 主动) | scan 是 | ❌ | ✓ |
| **proto_fuzzer** | CoAP 协议健壮性探测(观测型) | `testing/` | 主机(同网段) | ✅ | ✅ | 14 项 |
| **recon_layout** | 设备数据布局探测(诊断/校准) | `forensics/` | **设备** | ❌ | ❌ | - |
| **sandbox_forensics** | 应用沙箱只读取证 | `forensics/` | **设备** | ❌ | ❌ | `--root` |
| **sensitive_collector** | 全设备敏感信息/明文凭据收集 | `forensics/` | **设备** | ❌ | ✅ | 15 项 |
| **trust_mapper** | 设备间信任拓扑测绘 | `forensics/` | 设备/主机 | ❌ | ❌ | 9 项 |
| **sandbox_escape** | 应用沙箱逃逸攻击面审计(A/B/C 三层,14 工具) | `sandbox_escape/` | 主机+设备 | ❌ | ❌ | 详见子 README |

---

## 目录结构

```
harmonyOSSecurityTools/
├── README.md                 ← 本文件(整合使用指南)
├── LICENSE
├── docs/                     ← 矩阵 / 资料文档
│   └── HarmonyOS_PC_攻击面杀伤链矩阵.xlsx
├── discovery/                ← 阶段 1:资产 / 设备发现
│   ├── DSoftBusScanner.py
│   ├── dsoftbus_probe.py
│   └── dsoftbus_probe_使用说明.md
├── analysis/                 ← 阶段 2:流量 / 漏洞分析
│   ├── pcap_analyzer/
│   └── vuln_mapper/
├── testing/                  ← 阶段 3:主动协议测试
│   └── proto_fuzzer/
├── forensics/                ← 阶段 4:设备取证 + 信任测绘
│   ├── recon_layout.py
│   ├── sandbox_forensics/
│   ├── sensitive_collector/
│   └── trust_mapper/
└── sandbox_escape/           ← 专题:应用沙箱逃逸攻击面审计
    ├── analysis/  testing/  common/
    └── README.md  MANUAL.md  requirements.txt
    # 评估报告(md/pdf)不入库,留本地
```

---

## 一、运行环境

**分析主机(Mac)**:Python 3.7+,**全标准库、无第三方依赖**(无需 pip install;dsoftbus_probe 可选 scapy/bleak 增强)。

**HarmonyOS PC(设备)**:Python 3 + sqlite3(系统自带或可装)。设备端需拷上去的工具:`forensics/`(整目录)。建议放 `/data/local/tmp/`。

---

## 二、研究链路(按阶段)

### 阶段 1 · 资产 / 设备发现(`discovery/`)

#### DSoftBusScanner — 多协议指纹综合识别
局域网内发现 HarmonyOS/OpenHarmony 设备,识别设备形态(电视/PC/手机/平板),输出带置信度的指纹报告。
- 技术栈(纯标准库):DSoftBus 发现(CoAP UDP 5684)、UPnP/SSDP(UDP 1900)、ICMP/TTL(区分 Windows 128 vs Linux/HarmonyOS 64)、TCP 端口(SMB/RDP/adb)、行为时序(在线率区分常驻/休眠)。

```bash
cd discovery
python DSoftBusScanner.py scan                       # 全网扫描(默认)
python DSoftBusScanner.py scan --subnet 192.168.1.0/24
python DSoftBusScanner.py deep --ip 192.168.1.50     # 单 IP 全协议深探
python DSoftBusScanner.py monitor --rounds 10 --interval 12
python DSoftBusScanner.py linktest --ip 192.168.1.50  # 亮灭屏关联
```

#### dsoftbus_probe — 发现协议探测 + 被动嗅探
聚焦 CoAP/BLE 发现协议本身:主动探测 + 被动监听 + 设备伪装 + pcap 落盘,实时流式设备表格。详细手册见 `discovery/dsoftbus_probe_使用说明.md`。

```bash
cd discovery
python dsoftbus_probe.py selftest                    # 自检
python dsoftbus_probe.py scan                        # 广播探测整网
python dsoftbus_probe.py scan -n 0 --interval 5      # 主动雷达(覆盖息屏设备)
python dsoftbus_probe.py scan -t 192.168.1.0/24 -o r.json   # CIDR 定向 + JSON
sudo python dsoftbus_probe.py sniff --pcap cap.pcap  # 被动嗅探 + pcap
python dsoftbus_probe.py ble -d 30                   # BLE 通道扫描
```

> **DSoftBusScanner vs dsoftbus_probe**:前者用多协议指纹(SSDP/ICMP/TCP/时序)综合判设备形态;后者聚焦 CoAP/BLE 发现协议本身(主动+被动+伪装+pcap)。互补。

---

### 阶段 2 · 流量 / 漏洞分析(`analysis/`)

#### pcap_analyzer — 离线抓包解析
解析 Wireshark/tcpdump 抓的 DSoftBus 流量,提取设备信息与事件。

```bash
cd analysis/pcap_analyzer
python pcap_analyzer.py /path/to/capture.pcap        # 文本报告
python pcap_analyzer.py capture.pcap --json          # JSON(可 | jq)
# 自动识别 pcap/pcapng
```
**自检**:`python test_pcap_analyzer.py` → 12 项 OK。

#### vuln_mapper — CVE 知识库 / 设备-CVE 映射
内置 CVE 知识库与设备联动,产出"资产—疑似受影响 CVE"报告。

```bash
cd analysis/vuln_mapper
python dsoftbus_vuln_mapper.py query --list                                # 列全部 CVE
python dsoftbus_vuln_mapper.py query --version "OpenHarmony v5.0.2-Release"
python dsoftbus_vuln_mapper.py query --cve CVE-2025-23409                  # 单 CVE 详情
python dsoftbus_vuln_mapper.py map --input devices.json                    # 离线映射
python dsoftbus_vuln_mapper.py scan --subnet 255.255.255.255 --timeout 3   # 主动发现+映射(默认 5684)
```
**自检**:`python test_mapper.py` → OK。

---

### 阶段 3 · 主动协议测试(`testing/`)

#### proto_fuzzer — CoAP 协议健壮性探测(观测型 · 授权门控)
向**显式授权的单个目标**发送畸形 CoAP 报文,**只观测**响应(返回码/超时/延迟),输出健壮性报告。**非利用工具**——不构造利用链、不做 DoS 压测。

```bash
cd testing/proto_fuzzer
python proto_fuzzer.py --target 192.168.1.50 --i-am-authorized            # 默认 5683
python proto_fuzzer.py --target 192.168.1.50 --port 5684 --i-am-authorized
python proto_fuzzer.py --target 192.168.1.50 --i-am-authorized --json
```
**自检**:`python test_proto_fuzzer.py` → 14 项 OK(本地 UDP echo 模拟,不触外网)。
**门控**:必须同时有 `--target` 与 `--i-am-authorized`,否则退出码 2。

---

### 阶段 4 · 设备取证 + 信任测绘(`forensics/`)

> **首次部署必做**:PC 版 HarmonyOS 的 `/data` 布局与手机/嵌入式不同,先探测再校准。
> ```bash
> # 设备上(scp 拉取 forensics/ 后)。recon 会自动 chmod +x *.sh
> sudo python3 recon_layout.py
> ```

#### recon_layout — 设备数据布局探测(诊断)
探测本机真实的应用沙箱 / 信任数据 / 软总线状态路径,作为校准各工具 `DEFAULT_ROOTS` / `TRUST_ROOTS` 的依据。只读,不收集凭据。

#### sandbox_forensics — 应用沙箱只读取证
扫描应用沙箱,原地解析 sqlite(mode=ro),定位敏感表/列。`scan` 探测+解析;`pack` 打包回传。

```bash
cd /data/local/tmp/forensics   # 设备上
python3 sandbox_forensics.py scan          # 默认扫设备沙箱
python3 sandbox_forensics.py scan --json
python3 sandbox_forensics.py pack          # 打包回传
```

#### sensitive_collector — 敏感信息 / 明文凭据收集(授权门控)
参照 Linux 取证 checklist,全设备收集敏感信息与明文凭据。**三层互补**覆盖:① 系统级固定路径(`/etc/shadow`、`ssh_host_*_key` 等)② 家目录展开(`~/.ssh/id_*`、`~/.aws`、`~/.kube`、`~/.bash_history` 等)③ walk 兜底 + `/proc/<pid>/environ` + 历史命令。私钥靠文件名(id_rsa/id_ed25519/…)与**内容**(PEM 头)双重识别。

```bash
python3 sensitive_collector.py --i-am-authorized                       # 默认扫描根
python3 sensitive_collector.py --i-am-authorized --json
python3 sensitive_collector.py --i-am-authorized --out /data/local/tmp/recon
```
**自检**:`python test_sensitive_collector.py` → 15 项。
**凭据策略**:提取【明文】凭据;【加密】的(HUKS/系统凭据)只标注存在性,不解密。

#### trust_mapper — 设备间信任拓扑测绘
从设备信任数据(account/device_auth 等)提取已绑定设备与信任关系,构建拓扑。

```bash
# 设备端
python3 trust_mapper.py scan                          # 默认扫信任存储
python3 trust_mapper.py scan --json
python3 trust_mapper.py graph > trust.dot             # Graphviz dot
# dot -Tsvg trust.dot -o trust.svg
```
**自检**:`python test_trust_mapper.py` → 9 项 OK。

---

### 专题 · 应用沙箱逃逸攻击面审计(`sandbox_escape/`)

独立于 DSoftBus 链路的横向专题:HarmonyOS 应用沙箱的越界能力评估,覆盖 A(文件/数据面
三闸判定)、B(SELinux 域转移三条件复核)、C(IPC 服务接口校验审计)三层,14 个工具
(T1~T11 + 设备侧一键脚本)+ 操作手册 + 已脱敏评估报告。**全部离线/只读分析**,
无主动发包。

工具矩阵与快速上手见 `sandbox_escape/README.md`,操作纪律(通道工程/三闸判定法/
坑速查)见 `sandbox_escape/MANUAL.md`。

---

## 三、推荐测试顺序(按风险递增)

1. `pcap_analyzer` — 解析现成抓包(零风险)
2. `vuln_mapper query` — 离线查 CVE 库(零风险)
3. `trust_mapper` — 解析导出的信任数据(零风险)
4. `DSoftBusScanner` / `dsoftbus_probe` — 同网段被动/低扰发现
5. `sandbox_forensics` / `sensitive_collector` — 设备端只读取证(后者授权门控)
6. `vuln_mapper scan` — 主动发现同网段设备
7. `proto_fuzzer` — 主动协议健壮性探测(授权门控,**最后做**)

---

## 四、协议 / 端口速查

| 项 | 值 |
|----|----|
| 传输 | CoAP over UDP |
| **5683** | 明文 CoAP(标准端口)— proto_fuzzer 默认目标 |
| **5684** | CoAP over DTLS(加密)— vuln_mapper scan / dsoftbus_probe 默认 |
| 发现 Uri-Path | `/softbus/device_discover`、`/.well-known/core` |
| 发现 payload | cJSON:`deviceId` / `devicename` / `type` / `mode` / `hwAccountHash` … |
| 沙箱路径 | `/data/storage/el2/<userId>/<bundle>/base/{files,databases,…}`(PC 版布局用 recon_layout 探测) |
| 信任数据 | `/data/storage/el2/{database,auth_groups}`、device_auth(用 recon_layout 校准) |
| 密钥库 | HUKS — 加密,仅查存在性 |

> 设备发现走 5683 还是 5684 因版本/配置而异。不通时用 `--port` 换另一个端口试。

---

## 五、安全红线(务必遵守)

1. **授权门控工具**(sensitive_collector、proto_fuzzer):仅在持有目标书面测试授权时运行;结果**仅写本地、不外发**。
2. **proto_fuzzer / vuln_mapper scan / DSoftBusScanner**:即便授权,**禁止**对生产系统、第三方设备、未授权网络运行。
3. **取证结果含敏感数据**:sensitive_collector / sandbox_forensics 的输出(`result.txt`、`report.json`、`report.txt`、`*.pcap`)**严禁提交 VCS 或外发**(已在 `.gitignore` 排除)。
4. **入库卫生**:`__pycache__/`、`*.pyc`、`.venv/`、`.claude/`、`.DS_Store` **不得入库**(已排除)。

---

## 六、故障排查

| 现象 | 排查 |
|------|------|
| 扫描结果空 | 非 root 受限于可读路径——属正常边界;root 可全扫 |
| scan/proto_fuzzer 无响应 | ① 不在同网段 ② 防火墙挡 UDP ③ 端口不对(5683↔5684 换试)④ 目标未开 DSoftBus |
| 设备端工具返回 0 命中 | PC 版 `/data` 布局与标准不同,先跑 `recon_layout.py` 校准 `--root` |
| `ModuleNotFoundError: sqlite3` | 设备装 sqlite3;sandbox_forensics/trust_mapper 解析 db 依赖它 |
| trust_mapper 识别不到字段 | 信任库 schema 因版本而异,`--json` 看原始提取结果再校准正则 |

---

仅用于已获书面授权的安全测试 / 取证 / 防御研究。
