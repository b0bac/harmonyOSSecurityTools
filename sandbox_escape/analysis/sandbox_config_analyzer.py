#!/usr/bin/env python3
# sandbox_config_analyzer.py  [T2 / 路径 A1-b]
# 功能：解析 /etc/sandbox/appdata-sandbox.json，挖掘越界路径映射（攻击面）
# 定位：sandbox_escape / analysis / A1-b 沙箱配置审计
# 授权：仅用于已授权设备 dump 出的沙箱配置分析，离线静态运行
#
# 修正项（对应技术文档 v1.1 勘误编号）：
#   E6  /data/app/el2 本身不是敏感前缀——应用自身的 el2/<user>/<bundle> 是合法物理源；
#       越界判定 = src 在 el2 下但不属于 --bundle 指定的本应用目录（跨应用数据暴露）
#   E7  绝对路径不是穿越特征（物理路径全是绝对路径，原来会全量误报）；
#       穿越仅认路径组件中的 ".."
#
# 用法：
#   python3 sandbox_config_analyzer.py appdata-sandbox.json
#   python3 sandbox_config_analyzer.py appdata-sandbox.json --bundle com.example.app
#   python3 sandbox_config_analyzer.py appdata-sandbox.json --ro-fonts  # 把已知只读映射降级

import argparse
import json
import sys
from pathlib import PurePosixPath

# 系统敏感目录前缀——出现在映射任一侧即判越界风险
# 注意（E6）：不含 /data/app/el2，跨应用目录单独判定
# 注意（PC 实测）：只读系统分区（/system /vendor 等）映射进沙箱属标准基线，
# 单独降级为 INFO，不再制造噪音
SENSITIVE_PREFIXES = (
    "/data/system", "/data/local", "/root", "/etc", "/proc", "/sys",
)

# 只读系统分区前缀（HarmonyOS 标准沙箱基线：应用可见系统只读目录）
READONLY_PARTITION_PREFIXES = (
    "/system", "/vendor", "/chip_prod", "/sys_prod",
)

# 应用沙箱应有的合法可见根
EXPECTED_SANDBOX_ROOT = "/data/storage/"

# 已知合法的只读系统目录映射前缀（字体/资源等），命中降级为 INFO 而非 HIGH（E6 附注）
DEFAULT_READ_ONLY_OK = ("/system/etc/fonts", "/system/fonts")


def load_sandbox_config(path: str) -> dict:
    """加载 dump 出的 appdata-sandbox.json"""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _prefix_match(path: str, prefix: str) -> bool:
    """按路径段边界匹配前缀（避免 /sys 误吃 /system）"""
    if not path:
        return False
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _is_traversal(segment: str) -> bool:
    """穿越特征：路径组件中出现 ..（E7：绝对路径本身不是穿越）"""
    return ".." in PurePosixPath(segment).parts


def _is_cross_app(src_path: str, bundle: str = None) -> bool:
    """src 在 el2 数据区下、且不属于本应用 bundle 目录（E6）"""
    if not _prefix_match(src_path, "/data/app/el2/"):
        return False
    if not bundle:
        # 未指定 bundle 时无法判定归属，不误报（交由人工确认）
        return False
    return bundle not in src_path


def analyze_mapping(src_path: str, dst_path: str, bundle: str = None,
                    ro_ok: tuple = ()) -> list:
    """
    分析单条映射：src（物理/源）-> dst（沙箱/目标）
    返回风险项列表
    """
    findings = []

    # 风险1：跨应用数据目录暴露（E6：按 bundleName 判定，而非 el2 根前缀）
    if bundle and _is_cross_app(src_path, bundle):
        findings.append({
            "type": "CROSS_APP_DATA_EXPOSED",
            "severity": "HIGH",
            "detail": f"物理源指向非本应用({bundle})的数据目录: {src_path}",
        })

    # 风险2：敏感系统目录被映射进沙箱（排除已知只读合法项）
    for prefix in SENSITIVE_PREFIXES:
        hit = _prefix_match(src_path, prefix) or _prefix_match(dst_path, prefix)
        if not hit:
            continue
        if any(src_path.startswith(p) for p in ro_ok):
            findings.append({
                "type": "READONLY_SYSTEM_DIR_MAPPED",
                "severity": "INFO",
                "detail": f"已知只读系统目录映射（通常无害，建议核实挂载只读）: "
                          f"{src_path} -> {dst_path}",
            })
        else:
            findings.append({
                "type": "SENSITIVE_DIR_EXPOSED",
                "severity": "HIGH",
                "detail": f"敏感目录出现在映射中: {src_path} -> {dst_path}",
            })
        break

    # 风险2b：只读系统分区映射（PC 实测：标准基线，仅提示不告警）
    if not any(f["type"] == "SENSITIVE_DIR_EXPOSED" for f in findings):
        for prefix in READONLY_PARTITION_PREFIXES:
            if _prefix_match(src_path, prefix) or _prefix_match(dst_path, prefix):
                findings.append({
                    "type": "READONLY_PARTITION_MAPPED",
                    "severity": "INFO",
                    "detail": f"只读系统分区映射（标准沙箱基线）: "
                              f"{src_path} -> {dst_path}",
                })
                break

    # 风险3：路径穿越特征（E7：仅认 .. 组件）
    for seg in (src_path, dst_path):
        if _is_traversal(seg):
            findings.append({
                "type": "PATH_TRAVERSAL_PATTERN",
                "severity": "MEDIUM",
                "detail": f"路径含 .. 穿越组件: {seg}",
            })

    # 风险4：沙箱目标不在预期根下（可能绕过沙箱约束）
    if dst_path and not dst_path.startswith(EXPECTED_SANDBOX_ROOT):
        findings.append({
            "type": "UNEXPECTED_SANDBOX_TARGET",
            "severity": "LOW",
            "detail": f"沙箱目标不在预期根下: {dst_path}",
        })

    return findings


def iter_mappings(config: dict):
    """
    兼容多种配置结构（含 HarmonyOS PC 实测格式）：
    - 顶层 sandbox-map / mappings 列表或 dict
    - PC 格式：common[].app-base[].mount-paths[].{src-path, sandbox-path} 等
      任意嵌套深度——递归收集所有同时含 src-path/src 与 sandbox-path/dst 的 dict
    """
    def _extract(m: dict):
        src = m.get("src", m.get("source-path", m.get("src-path", "")))
        dst = m.get("dst", m.get("sandbox-path", m.get("dst-path", "")))
        if src or dst:
            yield src, dst

    def _walk(node):
        if isinstance(node, dict):
            has_map = any(k in node for k in
                          ("src", "source-path", "src-path")) and \
                      any(k in node for k in ("dst", "sandbox-path", "dst-path"))
            if has_map:
                yield from _extract(node)
            for v in node.values():
                yield from _walk(v)
        elif isinstance(node, list):
            for item in node:
                yield from _walk(item)

    mappings = config.get("sandbox-map", config.get("mappings", None))
    if mappings is None:
        yield from _walk(config)
        return
    if isinstance(mappings, dict):
        mappings = [{"src": k, "dst": v} for k, v in mappings.items()]
    for m in mappings:
        if isinstance(m, dict):
            yield from _extract(m)


def audit(config: dict, bundle: str = None, ro_ok: tuple = DEFAULT_READ_ONLY_OK) -> list:
    """对全量映射做审计，返回按严重度排序的风险报告"""
    report = []
    for src, dst in iter_mappings(config):
        for finding in analyze_mapping(src, dst, bundle, ro_ok):
            finding["mapping"] = f"{src} -> {dst}"
            report.append(finding)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    report.sort(key=lambda x: order.get(x["severity"], 9))
    return report


def main():
    ap = argparse.ArgumentParser(description="A1-b 沙箱越界映射挖掘")
    ap.add_argument("config", help="dump 出的 appdata-sandbox.json 路径")
    ap.add_argument("--bundle", help="当前审计应用的 bundleName（用于跨应用判定，E6）")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="以 JSON 输出报告")
    args = ap.parse_args()

    cfg = load_sandbox_config(args.config)
    results = audit(cfg, args.bundle)

    high = sum(1 for r in results if r["severity"] == "HIGH")
    print(f"[+] 审计完成，发现 {len(results)} 项风险（HIGH={high}）")
    if args.as_json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for r in results:
            print(f" [{r['severity']}] {r['type']}: {r['detail']}")
            print(f"        mapping: {r['mapping']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
