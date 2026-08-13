# sensitive_collector — HarmonyOS 设备敏感信息 / 凭据收集器(device-side)

在设备 shell(hishell / hdc shell / 本地终端)中运行,**全设备范围**收集敏感信息与
明文凭据,用于授权安全测试的信息收集(looting)与取证。

> ⚠ **强授权门控**:未带 `--i-am-authorized` 直接拒绝运行(退出码 2)。工具**只读**,
> 结果**仅写本地文件、不外发**。仅用于已获书面授权的安全测试 / 取证。

## 收集类别

| 类别 | 内容 | 处理方式 |
|------|------|----------|
| 设备身份 | UDID / OS 版本目录 / 主机名 / IP | 读取系统文件 |
| 网络 | hosts / wpa_supplicant(WiFi PSK) | 读取可读配置 |
| 凭据特征文件 | `.pem/.crt/.key/.p12/.env/id_rsa/.git-credentials/credentials.db` 等 | 标注路径 + 大小 |
| 明文敏感字段 | `password / psk / token / api_key / secret / private_key` | **提取明文值**(兼容 JSON / ini / env 语法) |
| 日志敏感行 | `.log / .hilog` 中含敏感关键字的行 | 截取行(限长) |
| 密钥库 | HUKS / device_auth / keystore 目录 | **仅标注存在性**(内容加密,不解密) |

**凭据策略**:提取【明文】存储的凭据;【加密】的(HUKS / 系统凭据)只标注路径。
区分明文与加密——不做暴力解密。

## 自适应权限

- **root**:全扫描(`os.geteuid()==0`)
- **非 root**:扫描受限于可读路径,自动跳过权限不足的目录并报告边界

## 扫描边界(防爆 + 稳健)

- 扫描根白名单:`/data/app/el2`、`/data/app/el1`、`/data/service/el{1,2}`、`/data/misc`、`/data/local`、`/data/log`
- 深度上限 `MAXDEPTH=6`:覆盖 `el2/<uid>/<bundle>/base/databases/*.db` 等深沙箱路径
- 单文件读取上限 512KB,内容仅扫前 64KB;二进制(含 NUL 字节)自动跳过

## 用法

```bash
# 必须确认授权
python3 sensitive_collector.py --i-am-authorized
python3 sensitive_collector.py --i-am-authorized --root /data/app/el2
python3 sensitive_collector.py --i-am-authorized --out /data/local/tmp/recon   # 写报告文件
python3 sensitive_collector.py --i-am-authorized --json                        # stdout 纯 JSON(可管道 jq)
```

## 输出说明

- **文本模式**:`render_text()` 渲染人类可读报告,**明文值轻度脱敏**(仅显示前缀 + 长度)
- **JSON 模式**:`--json` 输出完整结构化数据(含凭据完整明文值),供后续处理
- **--out**:`report.json`(完整)+ `report.txt`(脱敏摘要)写入指定目录

JSON 顶层结构:
```json
{
  "version": "0.1", "is_root": true, "roots_scanned": [...],
  "device": {...}, "network": {...},
  "keystores": [...],                  // 仅存在性
  "credentials": {
    "credential_files": [...],         // 凭据特征文件
    "inline_secrets": [{"file","field","value"}, ...]   // 提取的明文
  },
  "log_secrets": [...]
}
```

## 测试

```bash
python3 test_sensitive_collector.py
```

11 项:凭据扩展名/文件名匹配、明文提取(JSON token / env password / api_key)、
二进制跳过、大文件不读、日志敏感行、密钥库存在性、可序列化、文本渲染、授权门控——
全部基于临时目录,**不触碰真实设备路径**。

## 局限与伦理

- 提取的是**明文**凭据;HUKS / 系统加密凭据无法解密,仅标注。
- 正则匹配有误报/漏报可能(如代码中的测试用 password 字符串),需人工复核。
- 即便授权,**禁止**对非自有/未授权设备运行;结果含敏感数据,**严禁提交 VCS 或外发**。

仅用于已获书面授权的安全测试 / 取证。
