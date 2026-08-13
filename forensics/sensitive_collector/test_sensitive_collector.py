#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_sensitive_collector.py — sensitive_collector 单元测试
造模拟文件系统结构, 用 --root 指向测试目录, 验证凭据/敏感提取。
    python test_sensitive_collector.py
"""
import os
import sys
import json
import tempfile
import subprocess
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sensitive_collector as sc

DIR = os.path.dirname(os.path.abspath(__file__))


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


class CredFileTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        base = os.path.join(self.d, "100/com.t/files")   # 模拟 /data/app/el2 根下
        _write(os.path.join(base, "cert.pem"), "-----BEGIN CERTIFICATE-----\n...")
        _write(os.path.join(base, ".env"), "API_KEY=sk-1234567890abcdef\nDB_PASSWORD=hunter2\n")
        _write(os.path.join(base, "id_rsa"), "-----BEGIN PRIVATE KEY-----\n...")
        _write(os.path.join(base, "config.json"),
               '{"token": "tok-abcdefghijklmnop", "name": "x"}')

    def test_collect_by_extension(self):
        r = sc.collect_credential_files([self.d])
        files = {os.path.basename(c["file"]) for c in r["files"]}
        self.assertIn("cert.pem", files)
        self.assertIn(".env", files)

    def test_collect_by_name(self):
        r = sc.collect_credential_files([self.d])
        files = {os.path.basename(c["file"]) for c in r["files"]}
        self.assertIn("id_rsa", files)

    def test_inline_secret_extraction(self):
        r = sc.collect_credential_files([self.d])
        vals = [s["value"] for s in r["secrets"]]
        self.assertIn("hunter2", vals)                      # DB_PASSWORD
        self.assertIn("sk-1234567890abcdef", vals)          # API_KEY
        self.assertIn("tok-abcdefghijklmnop", vals)         # token

    def test_binary_file_skipped(self):
        binp = os.path.join(self.d, "100/com.t/files/blob.bin")
        with open(binp, "wb") as f:
            f.write(b"\x00\x01\x02password=secret_should_not_match\x00")
        r = sc.collect_credential_files([self.d])
        vals = [s["value"] for s in r["secrets"]]
        self.assertNotIn("secret_should_not_match", vals)

    def test_large_file_content_not_read(self):
        big = os.path.join(self.d, "big.log")
        with open(big, "w") as f:
            f.write("password= leak\n" * 60000)   # > 512KB
        # 不应因大文件崩溃; 是否提取取决于 _read_text 返回 None(跳过内容)
        r = sc.collect_credential_files([self.d])
        self.assertIsInstance(r["secrets"], list)


class PrivateKeyContentTest(unittest.TestCase):
    """验证任意命名的私钥文件靠【内容】PEM 头识别(不依赖文件名 id_rsa)"""

    def test_detects_arbitrary_named_key(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "random_notes.txt"),     # 名字不在 CRED_NAMES/EXTS
               "-----BEGIN OPENSSH PRIVATE KEY-----\n")
        r = sc.collect_credential_files([d])
        hit = [c for c in r["files"] if c["file"].endswith("random_notes.txt")]
        self.assertEqual(len(hit), 1)
        self.assertTrue(hit[0]["private_key"])

    def test_is_private_key_variants(self):
        for hdr in ("-----BEGIN RSA PRIVATE KEY-----",
                    "-----BEGIN EC PRIVATE KEY-----",
                    "-----BEGIN OPENSSH PRIVATE KEY-----",
                    "-----BEGIN PRIVATE KEY-----",
                    "-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            self.assertTrue(sc.is_private_key(hdr), f"应识别 {hdr}")
        self.assertFalse(sc.is_private_key("just some config text"))
        self.assertFalse(sc.is_private_key(None))


class HistoryTest(unittest.TestCase):
    """历史命令中的明文凭据(URL 嵌入 / -pPASS / -u user:pass)"""

    def test_history_secrets(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, ".bash_history"),
               "ls -la\n"
               "mysql -h db.local -u root -pS3cr3t123 widgets\n"
               "git clone https://bob:hunter2@git.example.com/repo.git\n")
        hits = sc.collect_history_secrets([d])
        blob = " ".join(h["line"] for h in hits)
        self.assertIn("S3cr3t123", blob)     # -p 紧跟密码
        self.assertIn("hunter2", blob)        # URL 内 user:pass

    def test_password_equals_form(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "deploy.history"),
               "psql --password=TopSecret999 -U admin\n")
        hits = sc.collect_history_secrets([d])
        self.assertTrue(any("TopSecret999" in h["line"] for h in hits))


class LogTest(unittest.TestCase):
    def test_log_secret_line(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "app.log"),
               "normal line\ntoken=abc123AUTHORIZED here\nanother\n")
        hits = sc.collect_log_secrets([d])
        self.assertTrue(any("token" in h["line"].lower() for h in hits))


class KeystoreTest(unittest.TestCase):
    def test_presence_dir(self):
        d = tempfile.mkdtemp()
        ks = os.path.join(d, "huks")
        os.makedirs(ks)
        found = sc.collect_keystore_presence([ks])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["type"], "dir")

    def test_absent(self):
        self.assertEqual(sc.collect_keystore_presence(["/tmp/__nope__"]), [])


class CollectAllTest(unittest.TestCase):
    def test_structure_and_serializable(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "data/x/.env"), "PASSWORD=mypwd123\n")
        r = sc.collect_all([d])
        for key in ("version", "is_root", "device", "network", "keystores",
                    "walk_credentials", "system_credentials", "home_credentials",
                    "inline_secrets", "proc_env", "history_secrets", "log_secrets"):
            self.assertIn(key, r)
        # 必须可 JSON 序列化(三层收集器结果 + 进程/历史/日志)
        json.loads(json.dumps(r, ensure_ascii=False))

    def test_render_text(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "data/x/.env"), "API_KEY=key1234567890\n")
        r = sc.collect_all([d])
        txt = sc.render_text(r)
        self.assertIn("敏感信息收集", txt)
        self.assertIn("明文凭据", txt)             # inline_secrets 区块标题
        self.assertIn("key1234567890"[:6], txt)   # 明文片段(脱敏前缀)


class GateTest(unittest.TestCase):
    def test_requires_authorization(self):
        r = subprocess.run([sys.executable, "sensitive_collector.py"],
                           capture_output=True, cwd=DIR, timeout=10)
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"\xe6\x8e\x88\xe6\x9d\x83", r.stderr)   # "授权"


if __name__ == "__main__":
    unittest.main()
