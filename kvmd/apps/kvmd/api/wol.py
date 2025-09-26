





















import os
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


class WolApi:
    def __init__(self) -> None:
        self._logger = logger
        self._wol_list_path = "/etc/kvmd/user/wol_list.json"

    async def _run_command(self, cmd: str) -> str:
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                self._logger.error(f"Command failed: {stderr.decode()}")
                raise BadRequestError()
            return stdout.decode().strip()
        except Exception as e:
            self._logger.error(f"Error executing command: {e}")
            raise BadRequestError()

    @exposed_http("GET", "/wol/scan")
    async def _arp_scan_handler(self, _: Request) -> Response:
        """并行化ARP扫描处理器"""
        try:
            devices_dict = {}

            interfaces = ["default"] + [
                iface for iface in os.listdir('/sys/class/net')
                if iface.startswith(('wlan0'))
            ]


            scan_tasks = [
                self._parallel_scan(iface, devices_dict)
                for iface in interfaces
            ]


            await asyncio.gather(*scan_tasks)

            return make_json_response({"devices": list(devices_dict.values())})

        except Exception as e:
            self._logger.error(f"Error during ARP scan: {str(e)}", exc_info=True)
            return make_json_exception(BadRequestError(), 500)

    async def _parallel_scan(self, interface: str, devices: dict):
        """并行扫描执行器"""
        try:

            cmd = ["gl-arp-scan"]
            if interface != "default":
                cmd += ["-i", interface]


            output = await self._run_command(" ".join(cmd))
            self._parse_arp_output(output, devices)

        except Exception as e:
            self._logger.error(f"Interface {interface} scan fail: {str(e)}")

    def _parse_arp_output(self, output: str, devices: dict):
        """通用解析方法"""
        for line in output.split("\n"):
            if line.strip():
                ip, mac = line.strip().split()

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

    @exposed_http("POST", "/wol/wake")
    async def _send_handler(self, request: Request) -> Response:
        try:
            if not request.query.get("mac"):
                raise BadRequestError("MAC address is required")

            mac = request.query["mac"]
            cmd = f"ether-wake -i eth0 {mac}"
            await self._run_command(cmd)
            if os.path.exists(f'/sys/class/net/wlan0'):
                cmd = f"ether-wake -i wlan0 {mac}"
                await self._run_command(cmd)

            return make_json_response({"result": f"WOL packet sent to {mac}"})
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error sending WOL packet: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/wol/add")
    async def _add_device_handler(self, request: Request) -> Response:
        try:

            mac = request.query.get("mac")
            if not mac:
                raise BadRequestError("MAC address is required")


            ip = request.query.get("ip", "")
            name = request.query.get("name")


            if not name:
                name = f"device-{mac.replace(':', '')[-4:]}"


            try:
                async with aiofiles.open(self._wol_list_path, "r") as f:
                    content = await f.read()
                    data = json.loads(content)
            except FileNotFoundError:
                data = {"devices": []}
            except json.JSONDecodeError:
                data = {"devices": []}


            new_device = {
                "ip": ip,
                "mac": mac,
                "name": name
            }


            found = False
            for i, device in enumerate(data["devices"]):
                if device["mac"] == mac:
                    data["devices"][i] = new_device
                    found = True
                    break


            if not found:
                data["devices"].append(new_device)


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

            mac = request.query.get("mac")
            if not mac:
                raise BadRequestError("MAC address is required")


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


            original_length = len(data["devices"])
            data["devices"] = [device for device in data["devices"] if device["mac"] != mac]


            if len(data["devices"]) == original_length:
                return make_json_response({
                    "ok": False,
                    "error": "Device not found"
                }, status=404)


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
