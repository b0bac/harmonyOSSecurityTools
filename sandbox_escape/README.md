# sandbox_escape — HarmonyOS 沙箱逃逸攻击面测试工具集

> **授权声明**：本目录所有工具仅用于**已授权**的鸿蒙设备安全测试与攻击面研究。
> 依据《HarmonyOS 应用沙箱逃逸技术文档 v1.1》第 8.1 节工具矩阵研发，
> 已内置该文档 E1–E12 全部勘误的修正。

## 工具矩阵

| 工具 | 路径 | 攻击面 | 运行位置 | 设备依赖 |
|------|------|--------|----------|----------|
| T1 `transition_mapper` | `analysis/transition_mapper.py` | B1 SELinux domain transition 攻击链 | 主机（离线） | 设备 dump 的 policy.bin |
| T1.5 `cil2rules` | `analysis/cil2rules.py` | B1 前置：CIL 策略 → sesearch 规则文本 | 主机（离线） | 设备 /system/etc/selinux/*.cil |
| T1.6 `entrypoint_checker` | `analysis/entrypoint_checker.py` | B1 深化：三条件完整可达复核（TE 图 ≠ 可利用） | 主机（离线） | file 类规则 + file_contexts + typetransition |
| T2 `sandbox_config_analyzer` | `analysis/sandbox_config_analyzer.py` | A1-b 沙箱越界映射 | 主机（离线） | 设备 dump 的 appdata-sandbox.json |
| T3 `sa_enumerator` | `analysis/sa_enumerator.py` | C1 SA 攻击面清单 | 主机(hdc) / 设备 | 授权真机 |
| T3.4 `binder_surface` | `analysis/binder_surface.py` | C/D 层前置：binder IPC 攻击面量化与选靶 | 主机（离线） | 设备 grep 的 binder 规则 + service_contexts |
| T4 `interface_auditor` | `analysis/interface_auditor.py` | C1 无校验特权接口 | 主机（离线） | 反编译导出产物 |
| T5 `symlink_canary` | `testing/symlink_canary.py` | A1-c symlink 代理缺陷 | 设备 / 主机(hdc) | 授权真机 |
| T7 `data_probe` | `testing/data_probe.sh` | 目标 1 实测：沙箱外文件读写三闸终验（DAC） | 应用沙箱内 | 已授权真机 + 应用上下文 |
| T8 `log_tamper` | `testing/log_tamper.sh` | A 层残存能力验证：data_log 系日志清理/污染/伪造（反取证） | 应用沙箱内（需对应权限） | 已授权真机 + 权限持有应用 |
| T9 `revshell` | `testing/revshell.sh` | 主机侧反弹 shell 通道驱动：建立/命令/双向传文件（md5 校验） | 主机（macOS） | 授权设备反弹途径 |
| T10 `perm_holder_scan` | `testing/perm_holder_scan.sh` | 挂载闸钥匙排查：权限持有者=挂载持有者判定 | 设备（任意 root 域） | 已授权真机 |
| T11 `svc_interface_audit` | `analysis/svc_interface_audit.py` | C 层服务端 so 命令级校验覆盖审计（r2 驱动，免反编译产物） | 主机（离线） | radare2 + 服务端 .so |
| — `harmony_pc_test` | `testing/harmony_pc_test.sh` | 设备侧一键测试（环境探测/取数打包/可选 canary） | 设备（hishell） | 已授权真机 |

## 快速上手

### 设备数据 dump（T1/T2 的输入）

```bash
# sepolicy（需 root/调试权限的授权设备）
hdc shell "cat /sys/fs/selinux/policy" > policy.bin
# 沙箱配置
hdc shell "cat /etc/sandbox/appdata-sandbox.json" > appdata-sandbox.json
```

### T1 — transition 攻击链（B1，最优先）

```bash
pip install setools    # 或 brew install setools；离线模式可不装
python3 analysis/transition_mapper.py policy.bin -o b1_report
# 无 setools4 环境先导出规则文本再拷走分析：
#   sesearch --allow -c process -p transition    policy.bin >  rules.txt
#   sesearch --allow -c process -p dyntransition policy.bin >> rules.txt
#   sesearch --allow -c process -p setcurrent    policy.bin >> rules.txt
python3 analysis/transition_mapper.py --rules-file rules.txt -o b1_report
```

输出：`b1_report.json`（可达域 + 多跳攻击链 + 风险分级）、`b1_report.dot`
（攻击面拓扑，`dot -Tsvg` 渲染）。含 dyntransition 双条件判定（E4）与
EXPECTED 基线外置（`--baseline expected.json`，E11）。

### T1.6 — entrypoint 完整可达复核（B1 深化）

T1 只看 process 层 `allow A B:process transition`，会高估攻击面（本机实测：
normal_hap TE 层可达 15 域，实际 0 域可进——file 层从未给 hap 域授 entrypoint）。
T1.6 按文档 §4.1.2 三条件模型复核并防两类假阳性（目标域自身 entrypoint 循环
伪证、不可达源域的循环前提）：

```bash
python3 analysis/entrypoint_checker.py --start normal_hap \
  --process-rules rules.txt \
  --entrypoint-rules file_entry_rules.cil --target-file-rules tgt_file_rules.cil \
  --typetransitions type_trans.cil --typeattrs typeattrs.cil \
  --file-contexts file_contexts -o ep_report.json
```

### T2 — 沙箱越界映射（A1-b）

```bash
python3 analysis/sandbox_config_analyzer.py appdata-sandbox.json --bundle com.example.app
```

`--bundle` 指定审计应用后启用跨应用数据目录判定（E6）；缺省只报确定性问题。

### T3 — SA 攻击面枚举（C1 前置）

```bash
python3 analysis/sa_enumerator.py -o sa_list --dump-all
# 工具已在设备上时（无 hdc）自动切本地模式，或强制：HARMONY_EXEC=local
```

`--dump-all` 逐个 `hidumper -s <id>` 深挖，产物在 `sa_list_details/`，
供 T4/T5 选靶。

### T3.4 — binder IPC 攻击面量化（C/D 层前置）

```bash
# 设备侧取数：grep -h '(binder' /system/etc/selinux/*.cil | gzip > binder.cil.gz
python3 analysis/binder_surface.py --domain normal_hap \
  --binder-rules binder_rules.cil --typeattrs typeattrs.cil \
  --service-contexts service_contexts -o binder_surface.json
```

输出各域 binder 可达清单 + 高价值目标（samgr/huks/useriam 等 19 个）标注，
并揭示「进程域级宽授权 vs sa_* 对象标签收紧」双轨差异（静态证据链已收口：
sa_* 收紧轨道为生效轨道，宽授权判为纸面，中高置信——判定法见 `MANUAL.md` §4）。

### T4 — 无校验特权接口挖掘（C1）

```bash
# 反编译导出：目录内每接口一个文件 <sa名>.<接口名>.txt
python3 analysis/interface_auditor.py decompiled/ -o c1_report.json
# 或单文件内用 "### sa名.接口名" 分隔各接口
python3 analysis/interface_auditor.py decompiled.txt
```

校验分 STRONG / WEAK / NONE 三级（E12）：`GetCallingUid` 等取值调用不算
已校验，标 WEAK 需人工复核比较逻辑。

### T5 — symlink 代理缺陷探测（A1-c，设备侧）

```bash
python3 testing/symlink_canary.py --label sys_probe --monitor 30 --log-source hilog
python3 testing/symlink_canary.py --cleanup   # 手动回收残留投饵
```

AVC 日志通道可配置（hilog/dmesg/kmsg，E3），投饵会话结束自动回收。

### T7 — 目标 1 实测探针（应用上下文内）

纯 POSIX sh，零依赖。在第 4 轮 policy 层判定（挂载✓ SELinux✓）的基础上验证最后一闸
DAC：data_log 系（UserView/xpower/bbox）读写、el1 for-all-app 写建、跨应用数据、
faultlogger（阴性对照，第 6 轮实测已判双重关闭）与 /proc 信息泄露探测。
报告为 PROBE_BEGIN/END 之间的文本。

```bash
# 将 data_probe.sh 放入测试应用可执行位置（如应用沙箱内可写目录）后：
sh data_probe.sh          # 应用上下文内执行，回传 PROBE_BEGIN..END 之间的输出
```

### T8 — 日志清理/污染工具（A 层残存能力，条件可达）

第 6 轮判定：data_log 系（bbox/UserView/xpower）SELinux 链完整但挂载闸为权限制
（ACCESS_BBOX_DIR / ACCESS_HIVIEWX / READ_DFX_XPOWER）。本工具在持有权限的应用
上下文内验证完整性攻击能力：status（侦察+写探测）/ clean（备份后反取证清理）/
pollute（畸形负载污染，兼作 hiview 解析器探针）/ forge（仿格式假事件注入）/
restore（回滚）。faultlogger/hilog/内核日志按策略不可碰，不在目标内。

```bash
sh log_tamper.sh status    # 先侦察：确认目标挂载与写权限
sh log_tamper.sh clean     # 清理（自动备份到 <目录>/.lt_bak/）
sh log_tamper.sh restore   # 回滚
LOG_DIRS=/tmp/x sh log_tamper.sh status   # 本地联调覆盖
```

### T9 — 反弹 shell 通道驱动（主机侧）

固化真机测试的通道工程：fifo 保活、字节偏移增量取输出（防历史缓冲污染）、
gzip+base64 双向传文件（双端 md5 校验）。已回环验证 cmd/get/put/stop 全过。
详见 `MANUAL.md` §1。

### T10 — 权限持有者排查（设备侧）

三闸模型挂载闸侧的钥匙审计：全进程 mountinfo 扫描 + 预装 hap requestPermissions
扫描 → 判定权限制路径在本机构建上有无现役可达者。

### T11 — 服务端接口校验覆盖审计（C 层，r2 驱动）

免反编译产物的 C1 审计：权限字符串 + 校验类导入 PLT 全量 xref → 有校验函数集，
与服务方法全集做规范化差集，疑点方法 `--check` 逐个复核（内置内联/虚表/Common
助手三种假阴性的规避）。已在 libaccountmgr.z.so（2.1MB，9 分发器 81 命令）上验证。

```bash
python3 analysis/svc_interface_audit.py <svc.so> -o c1_audit.json
python3 analysis/svc_interface_audit.py <svc.so> --class OsAccountManagerService
python3 analysis/svc_interface_audit.py <svc.so> --check 0x000e0098
```

操作手册（通道/取数/三闸判定/审计纪律/坑速查）见 **`MANUAL.md`**。

## 运行环境

- Python 3.8+，除 T1 实时 sesearch 模式需 setools4 外零三方依赖
- T3/T5 支持「主机(hdc) / 设备本地」双模式，自动检测（`HARMONY_EXEC` 可强制），
  多设备时 `HDC_SERIAL` 指定目标

## 迁移说明

本目录**自包含**：不引用仓库内其他模块，整体拷贝到任何位置（含目标设备）即可运行。
已并入 `harmonyOSSecurityTools/sandbox_escape/`；测试过程记录与设备产物
（策略快照、服务端二进制等）留在本地工作区不入库。

## 已知边界（真机验证 TODO）

- T1 正则按 setools4 标准输出编写，若厂商策略工具输出格式差异需现场适配
- T3 hidumper 输出格式依版本而异，解析失败时看 `sa_list.raw` 手动核对
- T5 监测信号依赖设备内核日志通道可用性（部分量产机 dmesg/hilog 受限）
