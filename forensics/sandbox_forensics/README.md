# sandbox_forensics — 鸿蒙应用沙箱取证

设备端采集 + 主机端解析。设备具备 **Python3** 时优先用 `.py`(能就地解析
sqlite 内容,无需回传);无 Python 时用 `.sh` 兜底(只采集,回传主机解析)。

| 文件 | 运行位置 | 作用 |
|------|---------|------|
| `sandbox_forensics.py` | HarmonyOS PC 本地(**Python3, 主力**) | 探测沙箱 + **就地解析 sqlite** + 清单 + 可选打包 |
| `sandbox_forensics.sh` | HarmonyOS PC 本地(纯 sh, **兜底**) | 无 Python 时:探测 + 列清单 + 打包 |
| `analyze_dump.py` | 主机(Mac,Python3) | 解析 pack 回传的数据库/凭据文件(深度分析) |

## 设备端(主力):Python

把 `sandbox_forensics.py` 传到 HarmonyOS PC:

```sh
python3 sandbox_forensics.py scan                        # 探测沙箱 + 就地解析数据库
python3 sandbox_forensics.py scan --root /data/app/el2   # 指定沙箱根(真机路径校准)
python3 sandbox_forensics.py scan --json                 # 机器可读(JSON)
python3 sandbox_forensics.py pack --out /data/local/tmp  # 打包回传做深度分析
```

- scan 会**直接读出**每个数据库的表、行数、列,并对疑似敏感列
  (token/session/auth/account/password/secret/key)打印少量样本。
- **root**:遍历全部应用沙箱;**非 root**:通常仅本应用沙箱(namespace 隔离)。
- 数据库只读打开(`mode=ro`),不修改原始文件。

## 设备端(兜底):Shell

设备无 Python 时用 `.sh`(只采集,不解析):

```sh
sh sandbox_forensics.sh scan                 # 探测 + 列清单
sh sandbox_forensics.sh pack                 # 打包成 tar.gz 供回传
sh sandbox_forensics.sh all                  # scan + pack
```

## 主机端:解析回传包

把 pack 产生的 `forensic_*.tar.gz` 回传到 Mac 后:

```bash
python3 analyze_dump.py forensic_20260813_120000.tar.gz
# 或直接给目录:
python3 analyze_dump.py ./解包目录/
```

## 路径校准(重要)

脚本基于 OpenHarmony 标准沙箱路径 `/data/app/el2/<userId>/<bundleName>/`
(EL2 = 解锁后可访问的加密层)。HarmonyOS PC 真机若路径不同:

```sh
ls -la /data/app/             # 看沙箱根实际结构
ls -la /data/app/el2/100/     # 看应用列表(userId 常为 100)
```

把实际根路径通过 `--root` 传入,或反馈给开发者调整 `DEFAULT_ROOTS`。

## 关键命令速查(设备端)

```sh
id                          # 看是否 root
ls -la /data/app/           # 看沙箱根实际结构
ls -la /data/service/       # 分布式/服务数据
```

仅用于授权安全测试 / 取证。
