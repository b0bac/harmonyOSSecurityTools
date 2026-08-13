#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cve_db.py — HarmonyOS / OpenHarmony DSoftBus 相关 CVE 结构化数据库

数据来源:OpenHarmony 官方安全公告(gitee)、华为消费者安全公告、NVD
核对日期:2026-08-13

设计说明:
  host 侧无法可靠读取设备的精确 OpenHarmony 版本(CoAP 响应通常不含版本字段),
  因此本库提供"按版本查询"与"全集清单"两种用法,供 vuln_mapper 做资产-CVE 联动,
  最终版本研判留给人工(对照 affected 字段)。
"""
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class CVEEntry:
    cve: str
    component: str            # 受影响组件 / 仓库
    title: str                # 漏洞类型简述
    vector: str               # 官方攻击向量(本地 / 远程·受限场景)
    cvss: Optional[float]     # 官方 CVSS 3.x
    cvss_source: str          # 评分来源
    affected: List[str]       # 受影响版本
    fixed: str                # 修复版本 / 分支
    bulletin: str             # 公告来源
    desc: str                 # 说明
    related_dsoftbus: bool    # 是否真正属于 DSoftBus 组件(37030 经订正为 False)


DSOFTBUS_CVES: List[CVEEntry] = [
    CVEEntry(
        cve="CVE-2025-23409",
        component="communication_dsoftbus",
        title="DSoftBus UAF",
        vector="本地·受限场景",
        cvss=3.8, cvss_source="OpenHarmony 官方公告",
        affected=["OpenHarmony v4.1-Release", "OpenHarmony v5.0.2-Release"],
        fixed="5.0.2.x / 4.1.x (2025-03, PR #8945/#8942)",
        bulletin="OpenHarmony 2025-03",
        desc="communication_dsoftbus UAF,本地攻击者可在受限场景造成任意代码执行",
        related_dsoftbus=True,
    ),
    CVEEntry(
        cve="CVE-2025-20091",
        component="communication_dsoftbus",
        title="DSoftBus UAF",
        vector="本地·受限场景",
        cvss=3.8, cvss_source="OpenHarmony 官方公告",
        affected=["OpenHarmony v4.1-Release", "OpenHarmony v5.0.2-Release"],
        fixed="5.0.2.x / 4.1.x (2025-03, PR #8945/#8942)",
        bulletin="OpenHarmony 2025-03",
        desc="communication_dsoftbus UAF,与 CVE-2025-23409 同批修复",
        related_dsoftbus=True,
    ),
    CVEEntry(
        cve="CVE-2025-24298",
        component="DSoftBus 模块(华为商业版)",
        title="DSoftBus 反序列化不匹配",
        vector="本地",
        cvss=None, cvss_source="华为公告(未给分)",
        affected=["HarmonyOS 设备(华为商业版)"],
        fixed="华为 2025-04 安全补丁",
        bulletin="华为消费者 2025-04",
        desc="DSoftBus 模块反序列化不匹配,影响服务完整性",
        related_dsoftbus=True,
    ),
    CVEEntry(
        cve="CVE-2024-37030",
        component="arkcompiler_ets_frontend(方舟eTS,非DSoftBus)",
        title="方舟eTS UAF",
        vector="远程(AV:N)",
        cvss=8.2, cvss_source="OpenHarmony 官方公告(NVD 误标 9.8)",
        affected=["OpenHarmony v4.0-Release"],
        fixed="4.0.x (2024-07)",
        bulletin="OpenHarmony 2024-07",
        desc="订正:此 CVE 属方舟eTS运行时,非 DSoftBus,常被误归类。远程可在任意应用执行代码。",
        related_dsoftbus=False,
    ),
]


def all_dsoftbus_cves() -> List[CVEEntry]:
    """返回所有真正属于 DSoftBus 组件的 CVE。"""
    return [e for e in DSOFTBUS_CVES if e.related_dsoftbus]


def cves_for_version(version: str, only_dsoftbus: bool = True) -> List[CVEEntry]:
    """根据 OpenHarmony 版本名精确匹配受影响的 CVE。"""
    out = []
    for e in DSOFTBUS_CVES:
        if only_dsoftbus and not e.related_dsoftbus:
            continue
        if version in e.affected:
            out.append(e)
    return out


def get_cve(cve_id: str) -> Optional[CVEEntry]:
    """按 CVE 编号查详情。"""
    cve_id = cve_id.upper()
    for e in DSOFTBUS_CVES:
        if e.cve.upper() == cve_id:
            return e
    return None


def to_jsonable(entries: List[CVEEntry]) -> List[dict]:
    return [asdict(e) for e in entries]


if __name__ == "__main__":
    # 自测 / 速览
    print(f"库内 CVE 总数: {len(DSOFTBUS_CVES)} | DSoftBus 相关: {len(all_dsoftbus_cves())}")
    print("=" * 70)
    for e in DSOFTBUS_CVES:
        tag = "✓DSoftBus" if e.related_dsoftbus else "✗订正(非DSoftBus)"
        print(f"[{tag}] {e.cve}  CVSS={e.cvss} ({e.vector})")
        print(f"    组件: {e.component}")
        print(f"    影响: {', '.join(e.affected)}")
        print(f"    修复: {e.fixed}  |  {e.bulletin}")
        print()
