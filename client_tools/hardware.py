# client_tools/hardware.py
"""
OnAuth 双轨制融合鉴权平台 - 客户端硬件指纹高对抗抓取组件
本脚本用于客户端（如 Flet, PyQt, Electron 包装等）提取本地机器唯一特征，
并将生成的 64 位不可逆 SHA-256 特征码作为 [X-Device-ID] 请求头安全传输至中台中枢。
"""

import subprocess
import hashlib
import os
import sys

# 仅在 Windows 平台下导入注册表库，保障多平台跨端分发时脚本不崩溃
if sys.platform == "win32":
    import winreg
else:
    winreg = None


def get_windows_device_id() -> str:
    """
    工业级多级降级硬件特征穿透算法

    梯队流：
    1. Cryptography MachineGuid (注册表级别，高速且无 wmic 依赖)
    2. PowerShell CIM-Instance (现代 Win11 纯净版官方标准方案)
    3. Legacy WMIC (向下兼容老旧 Win7/Win10 环境)
    4. 绝境环境多重环境变量弱特征组合兜底
    """
    hardware_seeds = []

    # 1. 第一梯队：读取系统物理主板 MachineGuid
    if winreg:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                if machine_guid and len(machine_guid) > 10:
                    hardware_seeds.append(machine_guid.strip())
        except Exception:
            pass

    # 2. 第二梯队：PowerShell 现代指令提取 CPU 与主板特征 (适配无 WMIC 境遇)
    if len(hardware_seeds) < 1:
        try:
            ps_cpu = 'powershell -Command "(Get-CimInstance Win32_Processor).ProcessorId"'
            cpu_id = subprocess.check_output(ps_cpu, shell=True, stdin=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL).decode().strip()

            ps_uuid = 'powershell -Command "(Get-CimInstance Win32_ComputerSystemProduct).UUID"'
            board_uuid = subprocess.check_output(ps_uuid, shell=True, stdin=subprocess.DEVNULL,
                                                 stderr=subprocess.DEVNULL).decode().strip()

            if cpu_id: hardware_seeds.append(cpu_id)
            if board_uuid: hardware_seeds.append(board_uuid)
        except Exception:
            pass

    # 3. 第三梯队：传统 WMIC 指令（老系统底层兼容）
    if len(hardware_seeds) < 1:
        try:
            cpu_id = subprocess.check_output("wmic cpu get processorid", shell=True, stdin=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL).decode().split("\n")[1].strip()
            board_uuid = subprocess.check_output("wmic csproduct get uuid", shell=True, stdin=subprocess.DEVNULL,
                                                 stderr=subprocess.DEVNULL).decode().split("\n")[1].strip()

            if cpu_id: hardware_seeds.append(cpu_id)
            if board_uuid: hardware_seeds.append(board_uuid)
        except Exception:
            pass

    # 4. 第四梯队：极端环境弱特征组合兜底防线
    if not hardware_seeds:
        fallback_str = f"Fallback_{os.getenv('COMPUTERNAME', 'UNKNOWN')}_{os.getenv('NUMBER_OF_PROCESSORS', '1')}_{os.getenv('PROCESSOR_IDENTIFIER', 'GENERIC')}"
        hardware_seeds.append(fallback_str)

    # 5. 高强度哈希收敛
    raw_fingerprint = f"OnAuth_Secure_Salt_{'_'.join(hardware_seeds)}"
    return hashlib.sha256(raw_fingerprint.encode()).hexdigest()


if __name__ == "__main__":
    # 留一个极简的本地运行预览
    print("--- OnAuth Client Device Identity Scanner ---")
    device_id = get_windows_device_id()
    print(f"Generated Device ID (SHA-256): {device_id}")