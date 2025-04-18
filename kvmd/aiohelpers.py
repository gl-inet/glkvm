# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2024  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
#    This program is distributed in the hope that it will be useful,         #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#    GNU General Public License for more details.                            #
#                                                                            #
#    You should have received a copy of the GNU General Public License       #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                            #
# ========================================================================== #


import subprocess

from .logging import get_logger

from . import tools
from . import aioproc
import os

# =====
async def remount(name: str, base_cmd: list[str], rw: bool) -> bool:
    logger = get_logger(1)
    mode = ("rw" if rw else "ro")
    cmd = [
        part.format(mode=mode)
        for part in base_cmd
    ]
    logger.info("Remounting %s storage to %s: %s ...", name, mode.upper(), tools.cmdfmt(cmd))
    try:
        proc = await aioproc.log_process(cmd, logger)
        if proc.returncode != 0:
            assert proc.returncode is not None
            raise subprocess.CalledProcessError(proc.returncode, cmd)
    except Exception as ex:
        logger.error("Can't remount %s storage: %s", name, tools.efmt(ex))
        return False
    return True

async def mount(device: str, mount_point: str, options: str = "",cmd = ["mount"]) -> bool:
    """挂载设备到指定挂载点

    Args:
        device: 设备路径
        mount_point: 挂载点路径
        options: 挂载选项

    Returns:
        bool: 挂载是否成功
    """
    logger = get_logger(1)
    if options:
        cmd.extend(["-o", options])
    cmd.extend([device, mount_point])

    logger.info("Mounting %s to %s ...", device, mount_point)
    try:
        proc = await aioproc.log_process(cmd, logger)
        if proc.returncode != 0:
            assert proc.returncode is not None
            raise subprocess.CalledProcessError(proc.returncode, cmd)
    except Exception as ex:
        logger.error("Can't mount %s: %s", device, tools.efmt(ex))
        return False
    return True

async def get_mount_points(device: str) -> list[str]:
    """获取设备的所有挂载点

    Args:
        device: 设备路径

    Returns:
        list[str]: 挂载点列表
    """
    try:
        with open("/proc/mounts", "r") as f:
            device_realpath = os.path.realpath(device)
            mount_points = []
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and ( parts[0] == device or parts[0] == device_realpath or os.path.realpath(parts[0]) == device_realpath):
                    mount_points.append(parts[1])
            return mount_points
    except Exception:
        return []

async def umount(device: str) -> bool:
    """卸载设备的所有挂载点

    Args:
        device: 设备路径

    Returns:
        bool: 是否所有挂载点都成功卸载
    """
    logger = get_logger(1)
    mount_points = await get_mount_points(device)
    if not mount_points:
        logger.info("Device %s is not mounted", device)
        return True

    success = True
    for mount_point in mount_points:
        logger.info("Unmounting %s from %s ...", device, mount_point)
        try:
            proc = await aioproc.log_process(["umount", mount_point], logger)
            if proc.returncode != 0:
                assert proc.returncode is not None
                raise subprocess.CalledProcessError(proc.returncode, ["umount", mount_point])
        except Exception as ex:
            logger.error("Can't unmount from %s: %s", mount_point, tools.efmt(ex))
            success = False

    return success
