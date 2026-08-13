#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_mapper.py — vuln_mapper 单元测试

运行:
    python test_mapper.py
    或 python -m unittest test_mapper
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cve_db


class CVEDBTest(unittest.TestCase):
    def test_dsoftbus_count(self):
        # 4 条总数中,3 条真正属于 DSoftBus
        self.assertEqual(len(cve_db.all_dsoftbus_cves()), 3)

    def test_37030_marked_not_dsoftbus(self):
        e = cve_db.get_cve("CVE-2024-37030")
        self.assertIsNotNone(e)
        self.assertFalse(e.related_dsoftbus)  # 订正为方舟eTS

    def test_version_match_v502(self):
        hit = {e.cve for e in cve_db.cves_for_version("OpenHarmony v5.0.2-Release")}
        self.assertIn("CVE-2025-23409", hit)
        self.assertIn("CVE-2025-20091", hit)

    def test_version_match_v41(self):
        hit = {e.cve for e in cve_db.cves_for_version("OpenHarmony v4.1-Release")}
        self.assertIn("CVE-2025-23409", hit)

    def test_fixed_branch_no_match(self):
        # 5.0.3 是修复分支,不应命中
        self.assertEqual(cve_db.cves_for_version("OpenHarmony v5.0.3-Release"), [])

    def test_only_dsoftbus_filter(self):
        # only_dsoftbus=False 时 37030 应可被 v4.0 命中
        hit = {e.cve for e in cve_db.cves_for_version("OpenHarmony v4.0-Release", only_dsoftbus=False)}
        self.assertIn("CVE-2024-37030", hit)

    def test_get_cve_case_insensitive(self):
        self.assertIsNotNone(cve_db.get_cve("cve-2025-24298"))

    def test_get_cve_unknown(self):
        self.assertIsNone(cve_db.get_cve("CVE-9999-0000"))

    def test_to_jsonable_structure(self):
        arr = cve_db.to_jsonable(cve_db.all_dsoftbus_cves())
        self.assertTrue(all("cve" in x and "affected" in x for x in arr))


if __name__ == "__main__":
    unittest.main()
