from typing import Optional
from typing import AsyncGenerator
from asyncio import create_subprocess_exec, sleep
import asyncio
import subprocess
import os
import zipfile
import json
import shutil
import chardet
import re
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

class ApApi:

    def __init__(self) -> None:
        self._logger = logger
        self.__need_update = False
        # 读取model信息并更新URL
        try:
            with open(MODEL_PATH, "r") as f:
                self.model = f.read().strip()
        except Exception as e:
            get_logger(0).warning(f"Failed to read model info, using default value rm10: {str(e)}")
            self.model = "rm10"

    @exposed_http("GET", "/ap/status")
    async def __get_state_handler(self, _: Request) -> Response:
        try:
            res = await ubus_call_async("ap", "status")

            return make_json_response(res)
        except Exception as e:
            self._logger.error(f"Error executing ap command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get ap status:{e}"), 502)

    @exposed_http("POST", "/ap/enable")
    async def __ap_start_handler(self, req: Request) -> Response:
        try:
            enable = req.query.get("enable")
            ssid = req.query.get("ssid")
            key = req.query.get("key")

            if enable == "true":
                ubus_params = {
                    "ssid": ssid,
                    "key": key
                }
                res = await ubus_call_async("ap", "start", ubus_params)
            else :
                res = await ubus_call_async("ap", "stop")

            if res["err_code"] == 0:
                return make_json_response({"status": "success", "message": "executed successfully"}, status=200)
            else:
                return make_json_response(
                    {"status": "error", "message": res.get("error", "Unknown ubus error")},
                    status=500
                )

        except (ValueError, TypeError) as e:
            self._logger.error(f"Invalid parameter type in query: {e}")
            return make_json_exception(BadRequestError(f"Invalid parameter type in query: {e}"), status=400)
        except Exception as e:
            self._logger.error(f"Error enable ap: {e}")
            return make_json_exception(InternalServerError(f"Failed to enable ap: {e}"), status=500)

    @exposed_http("POST", "/ap/open_last_mode")
    async def __open_last_mode_handler(self, req: Request) -> Response:
        try:
            res = await ubus_call_async("ap", "open_last_mode")

            if res["err_code"] == 0:
                return make_json_response({"status": "success", "message": "Open last wifi mode successfully"}, status=200)
            else:
                return make_json_response(
                    {"status": "error", "message": res.get("error", "Unknown ubus error")},
                    status=500
                )

        except (ValueError, TypeError) as e:
            self._logger.error(f"Invalid parameter type in query: {e}")
            return make_json_exception(BadRequestError(f"Invalid parameter type in query: {e}"), status=400)
        except Exception as e:
            self._logger.error(f"Error open last wifi mode: {e}")
            return make_json_exception(InternalServerError(f"Failed to open last wifi mode: {e}"), status=500)

    @exposed_http("POST", "/ap/close_all_mode")
    async def __close_all_mode_handler(self, req: Request) -> Response:
        try:
            res = await ubus_call_async("ap", "close_all_mode")

            if res["err_code"] == 0:
                return make_json_response({"status": "success", "message": "Close all wifi mode successfully"}, status=200)
            else:
                return make_json_response(
                    {"status": "error", "message": res.get("error", "Unknown ubus error")},
                    status=500
                )

        except (ValueError, TypeError) as e:
            self._logger.error(f"Invalid parameter type in query: {e}")
            return make_json_exception(BadRequestError(f"Invalid parameter type in query: {e}"), status=400)
        except Exception as e:
            self._logger.error(f"Error close all wifi mode: {e}")
            return make_json_exception(InternalServerError(f"Failed to close all wifi mode: {e}"), status=500)

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        if self.model != "rm10rc":
            while True:
                await sleep(3)
        else:
            _last_status = {}
            while True:
                try:
                    res = await ubus_call_async("ap", "status")

                    if json.dumps(res, sort_keys=True) != json.dumps(_last_status, sort_keys=True):
                        _last_status = res
                        self.__need_update = True

                    if self.__need_update:
                        yield res
                        self.__need_update = False
                except Exception as e:
                    self._logger.error(f"ap service not found: {e}")
                await sleep(3)

    async def trigger_state(self) -> None:
        self.__need_update = True
