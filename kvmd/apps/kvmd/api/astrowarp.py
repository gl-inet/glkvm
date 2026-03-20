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



import json
import subprocess
from aiohttp.web import Request
from aiohttp.web import Response

import os 
import asyncio
from ....htserver import ForbiddenError
from ....htserver import NotFoundError
from ....htserver import BadGatewayError
from ....htserver import BadRequestError
from ....htserver import exposed_http
from ....htserver import make_json_response
from ....htserver import make_json_exception
from ....logging import get_logger

logger = get_logger()

ASTROWARP_STATUS_PATH = "/var/run/cloud/bindinfo"
ASTROWARP_INIT_PATH = "/etc/init.d/S99gl-cloud"
ASTROWARP_CONFIG_PATH = "/etc/glinet/gl-cloud.conf"
CLOUD_BIND_LINK_PATH = "/var/run/cloud/bindlink"
RTTY_INIT_PATH = "/etc/init.d/S99rtty"
CLOUD_DYNAMIC_CODE_PATH = "/var/run/cloud/dynamic_code"
CLOUD_DYNAMIC_CODE_ERR_PATH = "/var/run/cloud/dynamic_code_err"


class AstrowarpApi:
    MAC_PATH = "/proc/gl-hw-info/device_mac"
    SN_PATH = "/proc/gl-hw-info/device_sn"
    DDNS_PATH = "/proc/gl-hw-info/device_ddns"
    def __init__(self) -> None:
        self._logger = logger
        pass

    # =====

    # 读取astrowarp状态
    @exposed_http("GET", "/astrowarp/status")
    async def __status_handler(self, req: Request) -> Response:
        with open(ASTROWARP_CONFIG_PATH, "r") as file:
            config = file.read()
            config_json = json.loads(config)
            enabled = config_json["enable"]
        try:
            with open(ASTROWARP_STATUS_PATH, "r") as file:
                # 文件内容类似{"bindtime":"1735891254","email":"jie.yang@gl-inet.com","username":"yangj"}
                status_str = file.read().strip()
                status = json.loads(status_str)
                # 如果bindtime为空，则返回失败
                if "bindtime" not in status or status["bindtime"] == "":
                    raise Exception("bindtime not found")
                if "username" not in status or "username" == "":
                    raise Exception("username not found")
            return make_json_response({"result": "success","status": status,"enabled": enabled})
        except Exception:
            return make_json_response({"result": "failed","enabled": enabled})

    @exposed_http("GET", "/astrowarp/show")
    async def __show_handler(self, req: Request) -> Response:
        try:
            with open(self.MAC_PATH, "r") as file:
                mac = file.read().strip()
            with open(self.SN_PATH, "r") as file:
                sn = file.read().strip()
            with open(self.DDNS_PATH, "r") as file:
                ddns = file.read().strip()
            return make_json_response({"url":f"{mac},{sn},{ddns}"})
        except Exception:
            return make_json_exception(NotFoundError(),404)
    
    @exposed_http("GET", "/astrowarp/enable")
    async def __enable_handler(self, req: Request) -> Response:
        enable = req.query.get("enable", "")

        # 修改配置文件
        with open(ASTROWARP_CONFIG_PATH, "r+") as file:
            config = file.read()
            config_json = json.loads(config)
            config_json["enable"] = True if enable == "true" else False
            file.seek(0)
            file.write(json.dumps(config_json))
            file.truncate()

        if enable == "true":
            process = await asyncio.create_subprocess_exec(ASTROWARP_INIT_PATH, "restart")
            await process.wait()
        else:
            process = await asyncio.create_subprocess_exec(ASTROWARP_INIT_PATH, "stop")
            await process.wait()
            process = await asyncio.create_subprocess_exec(RTTY_INIT_PATH, "stop")
            await process.wait()
        return make_json_response()

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
        
    @exposed_http("POST", "/astrowarp/unbind")
    async def __unbind_handler(self, req: Request) -> Response:
        try:
            # 执行unbind命令
            result = await self._run_command("ubus call gl-cloud unbind")
            return make_json_response({"result": "success"})
        except Exception as e:
            self._logger.error(f"Error executing command: {e}")
            return make_json_exception(BadGatewayError(),502)

    @exposed_http("GET", "/astrowarp/get_bind_link")
    async def __get_bind_link(self, req: Request) -> Response:
        try:
            await self._run_command("/usr/bin/eco /usr/bin/get_bindlink bindlink")
            with open(CLOUD_BIND_LINK_PATH, "r") as file:
                link_info = file.read()
                link_info_json = json.loads(link_info)
                return make_json_response(link_info_json)
        except Exception as e:
            self._logger.error(e)
            return make_json_exception(NotFoundError(), 404)

    @exposed_http("GET", "/astrowarp/get_dynamic_code")
    async def __get_dynamic_code(self, req: Request) -> Response:
        try:
            await self._run_command("/usr/bin/eco /usr/bin/get_bindlink dynamic_code")

            if os.path.exists(CLOUD_DYNAMIC_CODE_PATH):
                with open(CLOUD_DYNAMIC_CODE_PATH, "r") as file:
                    dynamic_code_info = file.read()
                    dynamic_code_info_json = json.loads(dynamic_code_info)
                    return make_json_response(dynamic_code_info_json)
            elif os.path.exists(CLOUD_DYNAMIC_CODE_ERR_PATH):
                with open(CLOUD_DYNAMIC_CODE_PATH, "r") as file:
                    dynamic_code_info = file.read()
                    dynamic_code_info_json = json.loads(dynamic_code_info)
                    return make_json_response(dynamic_code_info_json)
            else:
                return make_json_exception(NotFoundError(), 404)
        except Exception as e:
            self._logger.error(e)
            return make_json_exception(NotFoundError(), 404)
