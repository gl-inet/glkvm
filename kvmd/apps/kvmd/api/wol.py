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


import os
import re
import asyncio
import aiofiles
import json
from typing import List, Dict
import subprocess

from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger

logger = get_logger()

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def _valid_mac(mac: str) -> str:
    """Validate and normalize a MAC address to prevent command injection."""
    mac = mac.strip()
    if not _MAC_RE.match(mac):
        raise BadRequestError("Invalid MAC address format")
    return mac


class WolApi:
    def __init__(self) -> None:
        self._logger = logger
        self._wol_list_path = "/etc/kvmd/user/wol_list.json"

    async def _run_command_exec(self, cmd: list) -> str:
        """Run command using exec (argument list) to avoid shell injection."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                self._logger.error(f"Command failed: {stderr.decode()}")
                raise BadRequestError()
            return stdout.decode().strip()
        except BadRequestError:
            raise
        except Exception as e:
            self._logger.error(f"Error executing command: {e}")
            raise BadRequestError()

    @exposed_http("GET", "/wol/scan")
    async def _arp_scan_handler(self, _: Request) -> Response:
        """并行化ARP扫描处理器"""
        try:
            devices_dict = {}
            # 动态检测所有物理接口
            interfaces = ["default"] + [
                iface for iface in os.listdir('/sys/class/net')
                if iface.startswith(('wlan0'))
            ]
            
            # 创建并行扫描任务
            scan_tasks = [
                self._parallel_scan(iface, devices_dict)
                for iface in interfaces
            ]
            
            # 并行执行所有扫描
            await asyncio.gather(*scan_tasks)
            
            return make_json_response({"devices": list(devices_dict.values())})
    
        except Exception as e:
            self._logger.error(f"Error during ARP scan: {str(e)}", exc_info=True)
            return make_json_exception(BadRequestError(), 500)

    async def _parallel_scan(self, interface: str, devices: dict):
        """并行扫描执行器"""
        try:
            # 构建扫描命令
            cmd = ["gl-arp-scan"]
            if interface != "default":
                cmd += ["-i", interface]

            # 执行并解析
            output = await self._run_command_exec(cmd)
            self._parse_arp_output(output, devices)

        except Exception as e:
            self._logger.error(f"Interface {interface} scan fail: {str(e)}")

    def _parse_arp_output(self, output: str, devices: dict):
        """通用解析方法"""
        for line in output.split("\n"):
            if line.strip():
                ip, mac = line.strip().split()
                # 生成设备名称：device-后4位MAC地址
                device_name = f"device-{mac.replace(':', '')[-4:]}"
                devices[mac] = {
                    "ip": ip,
                    "mac": mac,
                    "name": device_name
                }
    
    @exposed_http("GET", "/wol/list")
    async def _get_list_handler(self, _: Request) -> Response:
        try:
            async with aiofiles.open(self._wol_list_path, "r") as f:
                content = await f.read()
                data = json.loads(content)
                return make_json_response(data)
        except FileNotFoundError:
            return make_json_response({"devices": []})
        except Exception as e:
            self._logger.error(f"Error reading WOL list: {e}")
            return make_json_exception(BadRequestError(), 502)

    async def _send_wol_to_interface(self, mac: str, interface: str) -> bool:
        """Send WOL packet to a specific interface, ignoring errors."""
        try:
            cmd = ["ether-wake", "-i", interface, mac]
            await self._run_command_exec(cmd)
            self._logger.debug(f"WOL packet sent to {mac} via {interface}")
            return True
        except Exception as e:
            self._logger.debug(f"Failed to send WOL to {interface}: {e}")
            return False

    def _get_available_interfaces(self) -> list:
        """Get list of available network interfaces for WOL."""
        interfaces = ["eth0"]
        if os.path.exists("/sys/class/net/wlan0"):
            interfaces.append("wlan0")
        return interfaces

    @exposed_http("POST", "/wol/wake")
    async def _send_handler(self, request: Request) -> Response:
        try:
            mac = request.query.get("mac")
            if not mac:
                raise BadRequestError("MAC address is required")
            mac = _valid_mac(mac)

            # Send WOL packets to all available interfaces
            interfaces = self._get_available_interfaces()
            await asyncio.gather(
                *[self._send_wol_to_interface(mac, iface) for iface in interfaces]
            )

            return make_json_response({"result": f"WOL packet sent to {mac}"})

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error sending WOL packet: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/wol/add")
    async def _add_device_handler(self, request: Request) -> Response:
        try:
            # 检查必需的MAC地址参数
            mac = request.query.get("mac")
            if not mac:
                raise BadRequestError("MAC address is required")
            mac = _valid_mac(mac)

            # 获取可选参数
            ip = request.query.get("ip", "")
            name = request.query.get("name")

            # 如果name为空，则自动生成
            if not name:
                name = f"device-{mac.replace(':', '')[-4:]}"

            # 读取现有设备列表
            try:
                async with aiofiles.open(self._wol_list_path, "r") as f:
                    content = await f.read()
                    data = json.loads(content)
            except FileNotFoundError:
                data = {"devices": []}
            except json.JSONDecodeError:
                data = {"devices": []}

            # 创建新设备信息
            new_device = {
                "ip": ip,
                "mac": mac,
                "name": name
            }

            # 检查MAC地址是否已存在，如果存在则更新
            found = False
            for i, device in enumerate(data["devices"]):
                if device["mac"] == mac:
                    data["devices"][i] = new_device
                    found = True
                    break

            # 如果不存在则添加新设备
            if not found:
                data["devices"].append(new_device)

            # 保存到文件
            async with aiofiles.open(self._wol_list_path, "w") as f:
                await f.write(json.dumps(data, indent=4))

            return make_json_response({
                "ok": True,
                "device": new_device,
                "action": "updated" if found else "added"
            })

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error adding WOL device: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/wol/remove")
    async def _remove_device_handler(self, request: Request) -> Response:
        try:
            # 检查必需的MAC地址参数
            mac = request.query.get("mac")
            if not mac:
                raise BadRequestError("MAC address is required")

            # 读取现有设备列表
            try:
                async with aiofiles.open(self._wol_list_path, "r") as f:
                    content = await f.read()
                    data = json.loads(content)
            except FileNotFoundError:
                return make_json_response({
                    "ok": False,
                    "error": "Device list not found"
                }, status=404)
            except json.JSONDecodeError:
                return make_json_response({
                    "ok": False,
                    "error": "Invalid device list format"
                }, status=500)

            # 查找并删除指定MAC地址的设备
            original_length = len(data["devices"])
            data["devices"] = [device for device in data["devices"] if device["mac"] != mac]

            # 检查是否找到并删除了设备
            if len(data["devices"]) == original_length:
                return make_json_response({
                    "ok": False,
                    "error": "Device not found"
                }, status=404)

            # 保存更新后的列表
            async with aiofiles.open(self._wol_list_path, "w") as f:
                await f.write(json.dumps(data, indent=4))

            return make_json_response({
                "ok": True,
                "message": f"Device with MAC {mac} has been removed"
            })

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error removing WOL device: {e}")
            return make_json_exception(BadRequestError(), 502)
