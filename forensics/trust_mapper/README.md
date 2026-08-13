# trust_mapper — DSoftBus 信任拓扑测绘(设备端)

在 HarmonyOS PC 本地扫描分布式软总线的设备认证/信任存储,提取已绑定设备与
信任关系,构建信任拓扑图。

## 能力

- 扫描设备认证/账号相关存储(account / group / cred / device_auth 等)。
- 通用启发式解析 sqlite + json/文本,按列名(udid / peerUdid / peerName /
  groupType…)与 UDID 特征(40+ 位 hex)提取设备标识与关系。
- 输出:**信任设备清单**、**设备间信任关系边**、**数据源溯源**。
- 支持 `--json` 与 `--dot`(Graphviz,回传 Mac 后渲染拓扑图)。
- 纯标准库,只读,自适应 root/非root。

## 用法

```sh
# 设备端扫描(人类可读)
python3 trust_mapper.py scan
python3 trust_mapper.py scan --root /data/service/el2          # 路径校准
python3 trust_mapper.py scan --json                            # 机器可读

# 输出 Graphviz dot, 回传 Mac 后画拓扑:
python3 trust_mapper.py graph > trust.dot
# Mac 上(需 brew install graphviz):
dot -Tpng trust.dot -o trust.png && open trust.png
```

## 路径候选(需真机校准)

工具默认探测以下信任存储根(基于 OpenHarmony 标准系统):

| 路径 | 内容 |
|------|------|
| `/data/service/el2/<userId>/` | account / hmdfs 分布式账号 |
| `/data/service/el1/public/device_auth/` | 设备认证数据 |
| `/data/service/el1/public/huks/` | 密钥库(凭据密钥,通常加密) |
| `/data/misc/softbus/` | 软总线运行数据 |

⚠ 不同 OpenHarmony 版本路径/表结构差异大。真机上用 `--root` 指向实际路径,
或把 `scan` 打印的数据源反馈开发者调整 `TRUST_ROOTS` 与启发式。

## 启发式说明(局限)

- **关系推断**:同一行记录里出现 ≥2 个不同设备标识(如 localUdid + peerUdid)
  即建立一条信任边,边的类型取 groupType/bindType 等列。
- **设备名归属**:设备名(peerName/deviceName)只挂到对端设备;若数据无
  peer 前缀列无法区分本端/对端,则挂到该行所有节点。
- **加密数据**:HUKS 等密钥库内容是加密的,本工具只能发现其存在,无法解密。
- 信任数据多为系统级,通常需要 **root** 才可读。

## 测试

```bash
python3 test_trust_mapper.py
```

9 项(含合成 group 表验证设备提取、关系边、JSON/dot 输出、空目录降级)。

## 与其他工具联动

发现的设备若含版本字段,可对照 `vuln_mapper query --version <版本>` 核对
受影响 CVE;信任拓扑结合 `pcap_analyzer` 的发现流量,可还原软总线组网全貌。

仅用于授权安全测试 / 取证。
