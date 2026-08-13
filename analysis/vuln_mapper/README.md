# vuln_mapper — DSoftBus 脆弱性映射器

把 DSoftBus 相关 CVE 知识库与现场设备联动,产出「资产 — 疑似受影响 CVE」报告。
CVE 数据来自 OpenHarmony 官方公告(gitee)/ 华为消费者公告 / NVD,已订正
`CVE-2024-37030`(实为方舟 eTS,非 DSoftBus)。

## 文件

| 文件 | 说明 |
|------|------|
| `cve_db.py` | CVE 结构化数据库 + 查询函数(可独立运行速览) |
| `dsoftbus_vuln_mapper.py` | 主程序(query / map / scan) |
| `test_mapper.py` | 单元测试 |

## 用法

```bash
# 1) 离线查询(不需网络/设备)
python dsoftbus_vuln_mapper.py query --list
python dsoftbus_vuln_mapper.py query --version "OpenHarmony v5.0.2-Release"
python dsoftbus_vuln_mapper.py query --cve CVE-2025-23409

# 2) 读 probe/scanner 的设备 JSON 做映射
python dsoftbus_vuln_mapper.py map --input devices.json

# 3) 轻量 CoAP 发现 + 映射(需与设备同网段)
python dsoftbus_vuln_mapper.py scan --timeout 3

# 所有命令加 --json 输出机器可读格式
python dsoftbus_vuln_mapper.py query --list --json
```

## 测试

```bash
python test_mapper.py
```

## 局限(重要)

- host 侧通常**拿不到设备的精确 OpenHarmony 版本**(CoAP 响应一般无版本字段)。
  因此 `scan`/`map` 输出的是「DSoftBus CVE 全集 + 影响版本范围」,**最终是否受影响
  需人工对照设备实际版本**(可用 `query --version` 精确确认)。
- `scan` 的 CoAP 发现为精简实现,不同 OH 版本响应字段可能不同,真机若无响应需
  结合 `dsoftbus_probe.py` 抓包对照调整 payload。

## 与其他工具协作

`map` 模式直接消费 `dsoftbus_probe.py scan -o r.json` 或 `DSoftBusScanner export`
的设备 JSON,无需重复发现:
```bash
python ../../discovery/dsoftbus_probe.py scan -o r.json
python dsoftbus_vuln_mapper.py map --input r.json
```

仅用于授权安全测试 / 资产盘点。
