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

class ModemApi:

    def __init__(self) -> None:
        self._logger = logger
        self.__need_update = False

        try:
            with open(MODEL_PATH, "r") as f:
                self.model = f.read().strip()
        except Exception as e:
            get_logger(0).warning(f"Failed to read model info, using default value rm10: {str(e)}")
            self.model = "rm10"

    @exposed_http("GET", "/modem/get_status")
    async def __get_state_handler(self, _: Request) -> Response:
        try:
            res = await ubus_call_async("modem", "status")

            return make_json_response(res)
        except Exception as e:
            self._logger.error(f"Error executing modem command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get modem status:{e}"), 502)

    @exposed_http("POST", "/modem/enable")
    async def __enable_handler(self, req: Request) -> Response:
        try:
            enable = req.query.get("enable")

            if enable is not None and enable.lower() in ("1", "true", "yes", "on"):
                res = await ubus_call_async("modem", "enable", {"enable": True})
            else:
                res = await ubus_call_async("modem", "disable", {"enable": False})

            return make_json_response(res)
        except Exception as e:
            self._logger.error(f"Error executing modem command: {e}")
            return make_json_exception(BadRequestError(f"Failed to set modem enable:{e}"), 502)

    @exposed_http("POST", "/modem/input_pin_code")
    async def __input_pin_code_handler(self, request: Request) -> Response:
        try:
            pin_code = request.query.get("pin")

            if not pin_code or not pin_code.isdigit() or not (4 <= len(pin_code) <= 8):
                return make_json_response({"error": "Invalid PIN code"}, status=400)

            res = await ubus_call_async("modem", "set_pincode", {"pin": pin_code})

            return make_json_response(res, status=200)

        except Exception as e:
            self._logger.error(f"Error executing modem set_pincode: {e}")
            return make_json_exception(BadRequestError(f"Failed to set PIN code: {e}"), 502)

    @exposed_http("POST", "/modem/at")
    async def __at_command_handler(self, request: Request) -> Response:
        try:
            at_cmd = request.query.get("AT")

            if not at_cmd or not isinstance(at_cmd, str) or at_cmd.strip() == "":
                return make_json_response(
                    {"error": "Invalid AT command, must be non-empty string"},
                    status=400
                )

            res = await ubus_call_async("modem", "at", {"AT": at_cmd})

            output = res.get("output", "")
            return make_json_response({"output": output}, status=200)

        except Exception as e:
            self._logger.error(f"Error executing AT command: {e}")
            return make_json_exception(
                BadRequestError(f"Failed to execute AT command: {e}"),
                502
            )

    @exposed_http("GET", "/modem/sim_setting")
    async def __sim_setting_handler(self, request: Request) -> Response:
        try:
            res = await ubus_call_async("modem", "get_sim_setting")

            return make_json_response(res)
        except Exception as e:
            self._logger.error(f"Error executing modem command: {e}")
            return make_json_exception(BadRequestError(f"Failed to get modem status:{e}"), 502)

    @exposed_http("POST", "/modem/sim_setting")
    async def __set_sim_setting_handler(self, request: Request) -> Response:
        try:
            params = request.query

            required_params = ["con_id", "con_type", "apn", "username", "password", "authentication", "mtu"]
            if not all(p in params for p in required_params):
                return make_json_response(
                    {"error": "Missing required query parameters"},
                    status=400
                )

            ubus_params = {
                "con_id": int(params.get("con_id")),
                "con_type": int(params.get("con_type")),
                "apn": params.get("apn"),
                "username": params.get("username"),
                "password": params.get("password"),
                "authentication": params.get("authentication"),
                "mtu": int(params.get("mtu"))
            }

            res = await ubus_call_async("modem", "set_sim_setting", ubus_params)

            if res.get("success"):
                return make_json_response({"status": "success", "message": "SIM settings updated successfully"}, status=200)
            else:
                return make_json_response(
                    {"status": "error", "message": res.get("error", "Unknown ubus error")},
                    status=500
                )

        except (ValueError, TypeError) as e:
            self._logger.error(f"Invalid parameter type in query: {e}")
            return make_json_exception(BadRequestError(f"Invalid parameter type in query: {e}"), status=400)
        except Exception as e:
            self._logger.error(f"Error setting SIM settings: {e}")
            return make_json_exception(InternalServerError(f"Failed to set SIM settings: {e}"), status=500)

    def _safe_get(self, d: dict, path: list, default=None):
        cur = d
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                return default
            cur = cur[key]
        return cur

    def _extract_relevant_fields(self, status: dict) -> dict:
        return {
            "enable": status.get("enable"),
            "pdp": status.get("pdp"),
            "iccid": status.get("iccid"),
            "state": status.get("state"),
            "apn": status.get("apn"),
            "register": status.get("register"),
            "sim_present": status.get("sim_present"),
            "msisdn": status.get("msisdn"),
            "ip_address": status.get("ip_address"),
            "operator": status.get("operator"),
            "imei": status.get("imei"),
            "signal_level": {
                "tech": self._safe_get(status, ["signal_level", "tech"]),
                "level": self._safe_get(status, ["signal_level", "level"]),
                "metric": self._safe_get(status, ["signal_level", "metric"]),

            },
        }

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        if self.model != "rm10rc":
            while True:
                await sleep(3)
        else:
            _last_status = {}
            while True:
                try:
                    res = await ubus_call_async("modem", "status")
                    relevant = self._extract_relevant_fields(res)

                    if relevant != _last_status:
                        _last_status = relevant
                        self.__need_update = True

                    if self.__need_update:
                        yield res
                        self.__need_update = False
                except Exception as e:
                    self._logger.error(f"modem service not found: {e}")
                await sleep(3)

    async def trigger_state(self) -> None:
        self.__need_update = True
