# sandbox_escape 操作手册

> **授权边界**：本手册全部流程仅用于已授权的 HarmonyOS 设备安全测试。通道日志
> （`/tmp/revshell_*.out`）与会话产物可能含敏感信息，严禁入库或外发。
> 适用环境：HarmonyOS PC（HongMeng Kernel，aarch64）+ macOS 主机 + radare2。

## 0. 总体工作流（十轮实测沉淀）

```
建立通道(T9) → 取数(策略cil/沙箱json/服务so/日志上下文)
  → 离线分析(B层T1系 / A层T2 / C层T11) → 真机探针(T7/T8/T10)
  → 三闸判定(挂载×SELinux×DAC) → 固化(test_log + 报告)
```

## 1. 通道建立与驱动（T9 revshell.sh）

设备侧需先具备任意反弹途径（授权前提下），主机侧全程用工具驱动：

```bash
testing/revshell.sh start 9377        # 建立监听，等设备回连
testing/revshell.sh status            # 确认 ESTABLISHED
testing/revshell.sh cmd 'id; getenforce'
testing/revshell.sh get /system/etc/selinux/xxx.cil ./xxx.cil   # 拉文件(md5自动校验)
testing/revshell.sh put ./data_probe.sh /storage/Users/currentUser/data_probe.sh
testing/revshell.sh stop
```

**通道工程要点**（均已固化进工具，排查时知其所以然）：
- fifo 需 holder 进程常驻，否则命令一结束 stdin EOF 连接即断
- `cmd` 用**字节偏移增量法**取输出——直接 tail 会吃到历史缓冲（第 9 轮踩坑）
- 传文件统一 `gzip | base64`；HMDFS 目标禁 `>>` 追加时分块多文件后 `cat` 合并
- 双端 md5 校验缺一不可；macOS 的 base64 解码用 `-D -i in -o out` 语法，
  设备端（toybox）解码统一 `base64 -d < file` 的 stdin 重定向形式（跨构建兼容）
- zsh 里 `echo ===` 会触发 `=cmd` 路径展开报错，标记文本避免 `=` 开头

## 2. 取数清单（设备 → 主机）

| 数据 | 设备路径 | 用途 | 消费工具 |
|------|----------|------|----------|
| SELinux 策略源 | `/system/etc/selinux/*.cil` | B 层全部分析 | T1/T1.5/T1.6/T3.4 |
| 文件标签 | `/system/file_contexts` | A 层标签核对 | T1.6 |
| SA 注册表 | `.../service_contexts` | C 层选靶 | T3/T3.4 |
| 沙箱配置 | `/etc/sandbox/appdata-sandbox.json` | A1-b 越界映射 | T2 |
| binder 规则 | `grep -h '(binder' *.cil` | C/D 层量化 | T3.4 |
| 服务端 so | `/system/lib64/lib*.so` | C1 接口审计 | T11 |
| 服务二进制 | `/system/bin/*` | 身份核验 | r2 |

**边界预期**（hishell/sudo_execv_label 域，实测）：`/sys/fs/selinux`、`/system/profile`、
`/system/bin/atm`、`/proc/<pid>/{cmdline,exe,root}`、`bm/hidumper` 均被拒——这不是故障，
是策略对 root-but-wrong-domain 的正确防御；遇到即换取数路径，不要反复撞。

## 3. 三闸判定法（目标 1：读写沙箱外文件）

任何「应用能否碰路径 P」的判定拆成三闸，**全过才算通**：

1. **挂载闸**：P 是否在应用沙箱的 mount 命名空间里？→ 查 appdata-sandbox.json
   的 permission 段（权限制路径）；真机用 T10 扫谁持有权限（挂载=钥匙）
2. **SELinux 闸**：拉出 P 的**实际标签**（`ls -Z`，勿用路径前缀推——file_contexts
   具体正则优先于兜底正则，第 4→6 轮教训），再拼「open+read/write」组合权限；
   孤立位（无 open 的 write、无 remove_name 的 unlink）判死
3. **DAC 闸**：uid/gid/目录 mode（真机 T7 探针实测）

## 4. C 层接口审计法（T11 svc_interface_audit.py）

```bash
# 设备拉服务端 so（service_contexts 查 SA 编号选靶）
testing/revshell.sh get /system/lib64/libaccountmgr.z.so ./libaccountmgr.z.so
# 覆盖矩阵 + 差集
python3 analysis/svc_interface_audit.py libaccountmgr.z.so -o c1_audit.json
python3 analysis/svc_interface_audit.py libaccountmgr.z.so --class OsAccountManagerService
# 疑点逐个复核（防内联/虚表/Common 助手三种假阴性）
python3 analysis/svc_interface_audit.py libaccountmgr.z.so --check 0x000e0098
```

**判定纪律**：
- 差集≠无校验。三个假阴性来源：LLVM 内联（PermissionCheck 零调用者但校验在）、
  C++ 虚表间接调用（bl 图失效，用权限字符串 xref 反查）、薄壳+尾调用进 Common 助手
- WEAK 级（GetCallingUid 等）只证明取身份不证明做判定（T4/E12）
- 攻击面清单条目必须**二进制级验证身份**（native_daemon 实为 memtools 的教训）

**binder 双轨语义判定法（第 10 轮收口，无应用上下文时的替代路径）**：
进程域宽授权（`allow hap_domain X binder call`）与 sa_* 对象标签双轨并存时，
判定运行时哪轨生效的静态证据链：
1. 全库 grep `service_contexts`——可读二进制零命中说明打标者在受专标签保护的
   samgr/sa_main 内（被机密性保护本身即打标代码存在的反证）；
2. 机制背书：samgr 继承 AOSP servicemanager setsecurityctx 模型；
3. 策略自洽：sa_* 逐服务精细规则真实存在，轨道失效则规则无意义。
结论口径写「中高置信」，运行时终验法（调一个进程域可达、sa_* 不可达的 SA 观察
是否被拒）留待有应用上下文时一次完成。

## 5. 真机探针使用（T7/T8/T10）

```bash
# 权限持有者排查（判定挂载闸有无钥匙）——hishell 域即可跑
sh testing/perm_holder_scan.sh
# 应用上下文探针（需测试应用/开发者模式提供 normal_hap 上下文）
sh data_probe.sh          # 目标1 三闸终验
sh log_tamper.sh status   # 先侦察；clean/pollute/forge 自动备份可回滚
```

## 6. 决策与悬置记录（2026-08-15 项目收尾拍板）

重启项目时先读这里，避免重复决策：

| 事项 | 决策 | 理由 |
|------|------|------|
| C 双轨语义 | 静态收口（sa_* 生效，306 宽授权纸面，中高置信），不深挖 | 证据链三条互证；终验只需应用上下文一次实测 |
| A 层 F-03 钥匙生态验证 | 悬置 | T10 真机复扫持有者=0；构造 DFX 权限测试应用成本高 |
| hiview 解析器审计 | 放弃 | 前置条件同 F-03，当前不可达 |
| 18 个高价值服务逐接口审计 | 放弃 | T11 方法已固化，需要时可随时重启 |
| hnp 信任模型审计 | **单独立项** | PC 形态供应链面，独立项目走 |

## 7. 产物归档约定

```
sandbox_escape/
  README.md                 工具矩阵与用法
  MANUAL.md                 本手册
  analysis/                 离线分析工具（T1系/T2/T3系/T4/T11）
  testing/                  设备侧/主机侧工具（T5/T7/T8/T9/T10）
  results_pc_YYYYMMDD/      每轮产物：test_log.md + 各类 json/cil/so
  reports/                  两份交付报告（脱敏技术 / 本轮测试）
```

- test_log.md 每轮必写：操作序列 / 推理与决策（含踩坑修正）/ 结论表
- 敏感数据（凭据文件、设备地址）不入 results 与 reports 正文

## 8. 已知坑速查（轮次→教训）

| 坑 | 轮次 | 规避 |
|----|------|------|
| TE 图当结论 | 2 | 三条件模型（transition+entrypoint+file_contexts），防自环/循环前提两类假阳性 |
| 路径前缀推标签 | 4→6 | `ls -Z` 取实际标签；具体正则优先 |
| 孤立权限位 | 4 | open/read/write/remove_name 组合判定 |
| hap 字面 grep 查不到授权 | 4 | 授权走属性，先做属性展开 |
| HIGH_VALUE 条目名字误导 | 9 | 二进制级验证身份（NEEDED 库+字符串） |
| 直调图假阴性 | 9 | 权限字符串 xref 反查 + 差集传递复核 |
| 历史缓冲污染 | 9 | 偏移增量取输出 |
| rm -f 语义掩盖失败 | 5 | unlink 仅在 create 成功后探测 |
| `#!/bin/sh` 下用 `<( )` 进程替换 | 10 | 改管道形式；跨平台 base64 解码用 stdin 重定向 `base64 -d < f` |
