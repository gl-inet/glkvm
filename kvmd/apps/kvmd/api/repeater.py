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

def ubus_call(service, method, args={}):
    cmd = ["ubus", "call", service, method, json.dumps(args)]
    result = subprocess.run(cmd, capture_output=True, check=True)

    encoding = chardet.detect(result.stdout)['encoding'] or 'utf-8'
    decoded_output = result.stdout.decode(encoding, errors='replace')

    return json.loads(decoded_output)

class RepeaterApi:

    def __init__(self) -> None:
        self._logger = logger

    @exposed_http("GET", "/repeater/get_saved_ap_list")
    async def __get_saved_ap_list_handler(self, _: Request) -> Response:
        try:
            res = ubus_call("repeater", "get_saved_ap_list")

            return make_json_response({"ap_list": res['ap_list']})
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get saved ap list:{e}"), 502)

    @exposed_http("GET", "/repeater/scan")
    async def __get_ap_list_handler(self, _: Request) -> Response:
        try:
            res = ubus_call("repeater", "scan")

            return make_json_response({"ap_list": res['ap_list']})
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get ap list:{e}"), 502)

    @exposed_http("POST", "/repeater/connect")
    async def __connect_wifi_handler(self, req: Request) -> Response:
        ssid = req.query.get("ssid")
        key = req.query.get("key")

        try:
            if not ssid:
                return make_json_exception(BadRequestError("Missing SSID"), 400)

            res = ubus_call("repeater", "connect", {"ssid": ssid, "key": key})

            if res["err_code"] != 0:
                return make_json_response({"result": "failed"})

            return make_json_response({"result": "success"})
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to connect wifi:{e}"), 502)

    @exposed_http("POST", "/repeater/disable")
    async def __disconnect_handler(self, req: Request) -> Response:
        try:
            res = ubus_call("repeater", "disable")

            if res["err_code"] != 0:
                return make_json_response({"result": "failed"})

            return make_json_response({"result": "success"})
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to disconnect wifi:{e}"), 502)

    @exposed_http("POST", "/repeater/remove_saved_ap")
    async def __forget_wifi_handler(self, req: Request) -> Response:
        ssid = req.query.get("ssid")

        try:
            if not ssid:
                return make_json_exception(BadRequestError("Missing SSID"), 400)

            res = ubus_call("repeater", "remove_saved_ap", {"ssid": ssid})

            if res["err_code"] != 0:
                return make_json_response({"result": "failed"})

            return make_json_response({"result": "success"})
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to forget wifi:{e}"), 502)

    @exposed_http("GET", "/repeater/get_status")
    async def __get_ap_status_handler(self, _: Request) -> Response:
        try:
            res = ubus_call("repeater", "status")

            return make_json_response(res)
        except Exception as e:
            self._logger.error(f"Error executing repeater command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get ap list:{e}"), 502)

