#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_trust_mapper.py — trust_mapper 单元测试
    python test_trust_mapper.py
"""
import os
import sys
import json
import sqlite3
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trust_mapper as tm

LOCAL = "A" * 40
PEER1 = "B" * 40
PEER2 = "C" * 40


def make_trust_db(path):
    """模拟设备认证 group 表: 本地设备与两个对端设备的绑定关系"""
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE group_data (
        groupId TEXT, localUdid TEXT, peerUdid TEXT,
        peerName TEXT, groupType TEXT)""")
    con.execute("INSERT INTO group_data VALUES (?,?,?,?,?)",
                ("g1", LOCAL, PEER1, "MateBook", "PEER_TO_PEER"))
    con.execute("INSERT INTO group_data VALUES (?,?,?,?,?)",
                ("g2", LOCAL, PEER2, "Phone", "SAME_ACCOUNT"))
    con.commit()
    con.close()


class TrustDbTest(unittest.TestCase):
    def test_extract_devices_and_edges(self):
        d = tempfile.mkdtemp()
        dbp = os.path.join(d, "account.db")
        make_trust_db(dbp)
        state = tm.scan([d])
        # 3 个设备: 本地 + 2 对端
        self.assertEqual(len(state["devices"]), 3)
        self.assertIn(LOCAL, state["devices"])
        self.assertIn(PEER1, state["devices"])
        self.assertIn(PEER2, state["devices"])
        # 对端设备名被提取
        names_b = state["devices"][PEER1]["names"]
        self.assertIn("MateBook", names_b)
        # 信任关系边: LOCAL<->PEER1, LOCAL<->PEER2
        edges = set(state["edges"].keys())
        self.assertTrue(any(a == LOCAL and b == PEER1 for a, b, _ in edges))
        self.assertTrue(any(a == LOCAL and b == PEER2 for a, b, _ in edges))
        # 关系类型
        self.assertTrue(any(t == "PEER_TO_PEER" for _, _, t in edges))

    def test_table_hint_filter(self):
        # 无关表名不应被扫描
        d = tempfile.mkdtemp()
        dbp = os.path.join(d, "account.db")
        con = sqlite3.connect(dbp)
        con.execute("CREATE TABLE random_cache (udid TEXT)")
        con.execute("INSERT INTO random_cache VALUES (?)", (LOCAL,))
        con.commit(); con.close()
        state = tm.scan([d])
        self.assertNotIn(LOCAL, state["devices"])


class JsonExtractTest(unittest.TestCase):
    def test_json_payload(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "device_info.json"), "w") as f:
            json.dump({"deviceId": "D" * 40, "deviceName": "Tab",
                       "groupId": "g3"}, f)
        state = tm.scan([d])
        self.assertIn("D" * 40, state["devices"])
        names = state["devices"]["D" * 40]["names"]
        self.assertIn("Tab", names)

    def test_udid_regex(self):
        self.assertTrue(tm.UDID_RE.fullmatch("A" * 40))
        self.assertFalse(tm.UDID_RE.fullmatch("short"))


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        make_trust_db(os.path.join(self.d, "account.db"))
        self.state = tm.scan([self.d])

    def test_render_text(self):
        txt = tm.render_text(self.state)
        self.assertIn("信任设备 3", txt)
        self.assertIn("信任关系 2", txt)
        self.assertIn("MateBook", txt)

    def test_render_json_valid(self):
        obj = json.loads(tm.render_json(self.state))
        self.assertEqual(len(obj["devices"]), 3)
        self.assertEqual(len(obj["edges"]), 2)
        self.assertIn("sources", obj)

    def test_render_dot_valid(self):
        dot = tm.render_dot(self.state)
        self.assertTrue(dot.startswith("graph dsoftbus_trust {"))
        self.assertIn(" -- ", dot)          # 至少一条边
        self.assertTrue(dot.rstrip().endswith("}"))   # 闭合
        # 简单语法: 引号配对
        self.assertEqual(dot.count('"') % 2, 0)


class EmptyTest(unittest.TestCase):
    def test_empty_root_no_crash(self):
        d = tempfile.mkdtemp()
        state = tm.scan([d])
        self.assertEqual(len(state["devices"]), 0)
        self.assertEqual(len(state["sources"]), 0)
        txt = tm.render_text(state)        # 不应抛异常
        self.assertIn("未发现信任数据", txt)

    def test_nonexistent_root(self):
        state = tm.scan(["/tmp/__definitely_not_existing__"])
        self.assertEqual(len(state["devices"]), 0)


if __name__ == "__main__":
    unittest.main()
