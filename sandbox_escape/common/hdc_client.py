#!/usr/bin/env python3
# common/hdc_client.py
# 功能：hdc / 设备本地 双模式命令执行统一封装
# 定位：sandbox_escape / common 共享库（自包含，迁移零改动）
# 授权：仅用于已授权设备的安全测试
#
# 两种运行形态：
#   1. 主机模式：主机装了 hdc，通过 `hdc [-t <serial>] shell <cmd>` 操作设备（默认，检测到 hdc 即启用）
#   2. 设备模式：工具被直接拷到鸿蒙真机/开发板上本地执行（无 hdc 时自动回退，也可强制指定）
# 环境变量：
#   HARMONY_EXEC = "hdc" | "local"     强制指定执行模式
#   HDC_SERIAL                      指定 hdc 目标设备序列号（多设备时）

import os
import shutil
import subprocess


class ExecutorError(RuntimeError):
    """命令执行失败（非零退出码或命令不可用）"""


class Executor:
    """统一的 shell 执行器：屏蔽「在主机上走 hdc / 在设备上直接跑」的差异"""

    def __init__(self, mode: str = None, hdc_serial: str = None):
        self.hdc_serial = hdc_serial or os.environ.get("HDC_SERIAL")
        forced = mode or os.environ.get("HARMONY_EXEC")
        if forced in ("hdc", "local"):
            self.mode = forced
        else:
            # 自动检测：有 hdc 就走主机模式，否则认为工具就在设备上
            self.mode = "hdc" if shutil.which("hdc") else "local"
        self._hdc_base = ["hdc"]
        if self.hdc_serial:
            self._hdc_base += ["-t", self.hdc_serial]

    # ---------- 基础接口 ----------

    def shell(self, cmd: str, timeout: int = 30) -> str:
        """执行 shell 命令并返回 stdout；非零退出码抛 ExecutorError"""
        full_cmd = self._wrap(cmd)
        try:
            proc = subprocess.run(full_cmd, capture_output=True, text=True,
                                  timeout=timeout)
        except FileNotFoundError as e:
            raise ExecutorError(f"命令不可用: {e}") from e
        except subprocess.TimeoutExpired as e:
            raise ExecutorError(f"命令超时({timeout}s): {cmd}") from e
        if proc.returncode != 0:
            raise ExecutorError(
                f"命令失败({proc.returncode}): {cmd}\nstderr: {proc.stderr.strip()}")
        return proc.stdout

    def shell_ok(self, cmd: str, timeout: int = 30) -> tuple:
        """执行命令，返回 (success: bool, stdout)。失败不抛异常（用于探测类命令）"""
        try:
            return True, self.shell(cmd, timeout)
        except ExecutorError as e:
            return False, str(e)

    # ---------- 内部 ----------

    def _wrap(self, cmd: str) -> list:
        if self.mode == "hdc":
            return self._hdc_base + ["shell", cmd]
        return ["sh", "-c", cmd]

    # ---------- 便捷方法 ----------

    def read_file(self, remote_path: str) -> str:
        """读取设备端文件内容"""
        return self.shell(f"cat '{remote_path}'")

    def path_exists(self, path: str) -> bool:
        ok, _ = self.shell_ok(f"test -e '{path}'")
        return ok

    def list_dir(self, path: str) -> list:
        ok, out = self.shell_ok(f"ls -1 '{path}'")
        return out.split() if ok else []


if __name__ == "__main__":
    ex = Executor()
    print(f"[*] 执行模式: {ex.mode}")
    ok, out = ex.shell_ok("echo hello_from_device && uname -a")
    print(f"[*] 探测: success={ok}")
    print(out)
