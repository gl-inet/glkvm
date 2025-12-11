from typing import Optional
from typing import AsyncGenerator
from asyncio import create_subprocess_exec, sleep
import subprocess
import os
import zipfile
import json
import shutil
import chardet
from aiohttp.web import Request, Response
from .... import aiotools

from ....htserver import (
    BadGatewayError,
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger

logger = get_logger()

MODEL_PATH = "/proc/gl-hw-info/model"

async def ubus_call_async(service, method, args={}):
    cmd = ["ubus", "call", service, method, json.dumps(args)]
    process = await create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, cmd, output=stdout, stderr=stderr)

    encoding = chardet.detect(stdout)['encoding'] or 'utf-8'
    decoded_output = stdout.decode(encoding, errors='replace')

    try:
        return json.loads(stdout)
    except Exception as e:
        logger.error(f"Error encoding: {encoding}")
        return json.loads(decoded_output)

class RepeaterApi:

    def __init__(self) -> None:
        self._logger = logger
        self.__need_update = False

        try:
            with open(MODEL_PATH, "r") as f:
                self.model = f.read().strip()
        except Exception as e:
            get_logger(0).warning(f"Failed to read model info, using default value rm10: {str(e)}")
            self.model = "rm10"

    @exposed_http("GET", "/repeater/get_saved_ap_list")
    async def __get_saved_ap_list_handler(self, _: Request) -> Response:
        try:
            res = await ubus_call_async("repeater", "get_saved_ap_list")

            return make_json_response({"ap_list": res['ap_list']})
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get saved ap list:{e}"), 502)

    @exposed_http("GET", "/repeater/scan")
    async def __get_ap_list_handler(self, _: Request) -> Response:
        try:
            res = await ubus_call_async("repeater", "scan")

            return make_json_response(res)
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get ap list:{e}"), 502)

    @exposed_http("POST", "/repeater/connect")
    async def __connect_wifi_handler(self, req: Request) -> Response:

        data = await req.json()

        if not isinstance(data, dict):
            raise BadRequestError("Configuration data must be in JSON object format")

        ssid = data.get("ssid")
        key = data.get("key")

        try:
            if not ssid:
                return make_json_exception(BadRequestError("Missing SSID"), 400)

            res = await ubus_call_async("repeater", "connect", data)

            if res["err_code"] != 0:
                return make_json_response({"result": "failed"})

            return make_json_response({"result": "success"})
        except Exception as e:
            self._logger.error(f"Error executing repeater connect")
            return make_json_exception(BadRequestError(f"Failed to connect wifi:{e}"), 502)

    @exposed_http("POST", "/repeater/disconnect")
    async def __disconnect_handler(self, req: Request) -> Response:
        try:
            res = await ubus_call_async("repeater", "disable")

            if res["err_code"] != 0:
                return make_json_response({"result": "failed"})

            return make_json_response({"result": "success"})
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to disconnect wifi:{e}"), 502)

    @exposed_http("POST", "/repeater/remove_saved_ap")
    async def __forget_wifi_handler(self, req: Request) -> Response:

        data = await req.json()

        if not isinstance(data, dict):
            raise BadRequestError("Configuration data must be in JSON object format")

        ssid = data.get("ssid")

        try:
            if not ssid:
                return make_json_exception(BadRequestError("Missing SSID"), 400)

            res = await ubus_call_async("repeater", "remove_saved_ap", {"ssid": ssid})

            if res["err_code"] != 0:
                return make_json_response({"result": "failed"})

            return make_json_response({"result": "success"})
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to forget wifi:{e}"), 502)

    @exposed_http("GET", "/repeater/get_status")
    async def __get_ap_status_handler(self, _: Request) -> Response:
        try:
            res = await ubus_call_async("repeater", "status")

            return make_json_response(res)
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get ap list:{e}"), 502)

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        """轮询Repeater状态并在状态变化时生成事件"""
        if self.model == "rm1":
            while True:
                await sleep(3)
        else:
            old_res = {}
            while True:
                try:
                    res = await ubus_call_async("repeater", "status")
                    if json.dumps(res, sort_keys=True) != json.dumps(old_res, sort_keys=True):
                        old_res = res
                        self.__need_update = True
                    if self.__need_update:
                        yield res
                        self.__need_update = False
                except Exception as e:
                    self._logger.error(f"repeater service not found: {e}")
                await sleep(3)


    async def trigger_state(self) -> None:
        self.__need_update = True