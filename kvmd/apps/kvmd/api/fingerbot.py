






















from typing import Optional
from typing import AsyncGenerator
from asyncio import create_subprocess_exec, sleep
import subprocess
import os
import zipfile
import json
import shutil
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

class FingerbotApi:
    _device_path = "/sys/class/bluetooth/hci0"
    DEVICE_NAME = "FGB01-Dongle"
    MIN_PRESS_TIME = 100
    MAX_PRESS_TIME = 60 * 1000
    PULL_TIME_OFFSET = 3
    LOW_ANGLE_PUSH_TIME = 800
    LOW_ANGLE_PULL_TIME = LOW_ANGLE_PUSH_TIME + PULL_TIME_OFFSET
    HIGH_ANGLE_PUSH_TIME = 1000
    HIGH_ANGLE_PULL_TIME = HIGH_ANGLE_PUSH_TIME + PULL_TIME_OFFSET
    angle_enum_dict = {

        1: (LOW_ANGLE_PUSH_TIME, LOW_ANGLE_PULL_TIME),
        2: (HIGH_ANGLE_PUSH_TIME, HIGH_ANGLE_PULL_TIME)
    }

    def __init__(self) -> None:
        self._logger = logger
        self._battery_cache: Optional[int] = None
        self._version_cache: Optional[str] = None

    def get_dongle_hci_path(self, target_product_name: str) -> Optional[str]:
        base_path = '/sys/class/bluetooth/'
        for hci in os.listdir(base_path):
            hci_path = os.path.join(base_path, hci)
            device_link = os.path.join(hci_path, 'device')

            if os.path.islink(device_link):
                real_device_path = os.path.realpath(device_link)
                cur_path = real_device_path
                while cur_path != '/':
                    product_file = os.path.join(cur_path, 'product')
                    try:
                        with open(product_file, 'r') as f:
                            product_name = f.read().strip()
                        if product_name == target_product_name:
                            return hci_path
                    except FileNotFoundError:
                        pass
                    cur_path = os.path.dirname(cur_path)
        return None

    async def get_state(self) -> dict:
        if self._device_path:
            return {"exist": os.path.exists(self._device_path)}
        else:
            return {"exist": False}

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        """轮询蓝牙设备状态并在状态变化时生成事件"""
        prev_exist = None
        while True:
            FingerbotApi._device_path = self.get_dongle_hci_path(self.DEVICE_NAME)
            if FingerbotApi._device_path:
                exist = os.path.exists(FingerbotApi._device_path)
            else:
                exist = False
            if prev_exist != exist:
                yield {"exist": exist}
                prev_exist = exist

                if exist:
                    self._logger.info("Fingerbot device connected, reading battery and version info")
                    await sleep(1)
                    await self._read_version()
                    await self._read_battery()
            await sleep(1)

    @staticmethod
    def _is_press_time_valid(press_time: int) -> bool:
        return FingerbotApi.MIN_PRESS_TIME <= press_time <= FingerbotApi.MAX_PRESS_TIME

    @staticmethod
    def _is_angle_enum_valid(angle_enum: int) -> bool:
        return angle_enum in FingerbotApi.angle_enum_dict

    def _parse_battery_from_output(self, output: str) -> Optional[int]:
        try:
            for line in output.split('\n'):
                if 'battery level:' in line:
                    return int(line.split(':')[1].strip().replace('%', ''))
            return None
        except Exception as e:
            self._logger.error(f"Error parsing battery level: {e}")
            return None

    def _parse_version_from_output(self, output: str) -> Optional[str]:
        try:
            for line in output.split('\n'):
                if 'version:' in line:
                    return line.split(':')[1].strip()
            return None
        except Exception as e:
            self._logger.error(f"Error parsing version: {e}")
            return None

    async def _read_battery(self) -> Optional[int]:
        try:
            process = await create_subprocess_exec(
                "fingerbot",
                "read",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                self._logger.error(f"Fingerbot read command failed: {stderr.decode()}")
                return None

            battery_level = self._parse_battery_from_output(stdout.decode())
            if battery_level is not None:
                self._battery_cache = battery_level
            return battery_level
        except Exception as e:
            self._logger.error(f"Error executing fingerbot read command: {e}")
            return None

    async def _read_version(self) -> Optional[str]:
        try:
            process = await create_subprocess_exec(
                "fingerbot",
                "image-version",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                self._logger.error(f"Fingerbot image-list command failed: {stderr.decode()}")
                return None

            local_version = self._parse_version_from_output(stdout.decode())
            if local_version is not None:
                self._version_cache = local_version
            return local_version
        except Exception as e:
            self._logger.error(f"Error executing fingerbot image-list command: {e}")
            return None

    @exposed_http("GET", "/fingerbot/battery")
    async def _battery_handler(self, _: Request) -> Response:

        battery_level = await self._read_battery()
        if battery_level is None:
            return make_json_exception(BadRequestError("Failed to read battery"), 502)
        return make_json_response({"battery": self._battery_cache})

    @exposed_http("GET", "/fingerbot/local_version")
    async def _version_handler(self, _: Request) -> Response:
        version = await self._read_version()
        if version is None:
            return make_json_exception(BadRequestError("Failed to read version"), 502)
        return make_json_response({"version": version})

    @exposed_http("GET", "/fingerbot/exist")
    async def _check_device(self, _: Request) -> Response:
        return make_json_response(self.get_state())

    @exposed_http("GET", "/fingerbot/click")
    async def _click_handler(self, request: Request) -> Response:
        try:
            press_time = int(request.query.get("press_time", ""))
            angle_enum = int(request.query.get("angle_enum", ""))
        except (ValueError, TypeError):
            return make_json_exception(BadRequestError(f"press time is not a number"), 400)

        if not self._is_press_time_valid(press_time):
            return make_json_exception(BadRequestError("press time is not in range"), 400)

        if not self._is_angle_enum_valid(angle_enum):
            return make_json_exception(BadRequestError("angle_enum is not a number or not in range"), 400)

        push_time, pull_time = FingerbotApi.angle_enum_dict[angle_enum]

        try:
            process = await create_subprocess_exec(
                "/usr/sbin/fingerbot",
                "set-action",
                str(push_time),
                str(press_time),
                str(pull_time),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                self._logger.error(f"Fingerbot command failed: {stderr.decode()}")
                return make_json_exception(BadRequestError(f"Failed to click:{e}"), 502)


            await self._read_battery()
            return make_json_response({"result": "success"})
        except Exception as e:
            self._logger.error(f"Error executing fingerbot command: {e}")
            return make_json_exception(BadRequestError(f"Failed to click:{e}"), 502)

    @exposed_http("GET", "/fingerbot/push")
    async def _push_handler(self, request: Request) -> Response:
        angle_enum = int(request.query.get("angle_enum", ""))
        if not self._is_angle_enum_valid(angle_enum):
            return make_json_exception(BadRequestError("angle_enum is not a number or not in range"), 400)

        push_time, pull_time = FingerbotApi.angle_enum_dict[angle_enum]
        press_time = 0
        pull_time = 0

        try:
            process = await create_subprocess_exec(
                "/usr/sbin/fingerbot",
                "set-action",
                str(push_time),
                str(press_time),
                str(pull_time),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                self._logger.error(f"Fingerbot command failed: {stderr.decode()}")
                return make_json_exception(BadRequestError(f"Failed to push:{e}"), 502)


            await self._read_battery()
            return make_json_response({"result": "success"})

        except Exception as e:
            self._logger.error(f"Error execute fingerbot command: {e}")
            return make_json_exception(BadGatewayError("Failed to push:{e}"), 502)

    @exposed_http("GET", "/fingerbot/pull")
    async def _pull_handler(self, request: Request) -> Response:
        angle_enum = int(request.query.get("angle_enum", ""))
        if not self._is_angle_enum_valid(angle_enum):
            return make_json_exception(BadRequestError("angle_enum is not a number or not in range"), 400)

        push_time, pull_time = FingerbotApi.angle_enum_dict[angle_enum]
        press_time = 0
        push_time = 0

        try:
            process = await create_subprocess_exec(
                "/usr/sbin/fingerbot",
                "set-action",
                str(push_time),
                str(press_time),
                str(pull_time),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                self._logger.error(f"Fingerbot command failed: {stderr.decode()}")
                return make_json_exception(BadRequestError(f"Failed to pull:{e}"), 502)


            await self._read_battery()
            return make_json_response({"result": "success"})

        except Exception as e:
            self._logger.error(f"Error execute fingerbot command: {e}")
            return make_json_exception(BadGatewayError("Failed to pull:{e}"), 502)

    @exposed_http("POST", "/fingerbot/upload")
    async def _upload_handler(self, request: Request) -> Response:
        try:
            reader = await request.multipart()
            field = await reader.next()

            if field is None or field.name != "file":
                return make_json_exception(BadRequestError("No file uploaded or invalid field name"), 400)

            filename = field.filename
            size = 0


            if not filename.endswith(".zip"):
                return make_json_exception(BadRequestError("Only .zip files are allowed"), 400)

            zip_file_path = "/tmp/fingerbot.zip"
            with open(zip_file_path, "wb") as f:
                while True:
                    chunk = await field.read_chunk()
                    if not chunk:
                        break
                    size += len(chunk)
                    f.write(chunk)

            try:
                extract_dir = "/tmp/fgb_image/"
                if os.path.exists(extract_dir):
                    shutil.rmtree(extract_dir)
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)

                manifest_path = os.path.join(extract_dir, "manifest.json")
                if not os.path.exists(manifest_path):
                    return make_json_exception(BadRequestError("manifest.json not found in zip archive"), 400)

                with open(manifest_path, "r") as manifest_file:
                    manifest_data = json.load(manifest_file)

                expected_soc = "nrf54l15"
                expected_size = None
                found_soc = None
                for file_entry in manifest_data.get("files", []):
                    if file_entry.get("file") == "finger_robot.signed.bin":
                        expected_size = file_entry.get("size")
                        found_soc = file_entry.get("soc")
                        break


                if expected_size is None:
                    return make_json_exception(BadRequestError("finger_robot.signed.bin not listed in manifest.json"), 400)

                if found_soc is None or found_soc != expected_soc:
                    return make_json_exception(BadRequestError(f"Invalid SOC: expected '{expected_soc}', got '{found_soc}'"), 400)


                bin_file_path = os.path.join(extract_dir, "finger_robot.signed.bin")
                if not os.path.exists(bin_file_path):
                    return make_json_exception(BadRequestError("finger_robot.signed.bin not found in zip archive"), 400)


                actual_size = os.path.getsize(bin_file_path)
                if actual_size != expected_size:
                    return make_json_exception(BadRequestError(f"File size mismatch: expected {expected_size}, got {actual_size}"), 400)

            except:
                return make_json_exception(BadRequestError("No file uploaded or invalid field name"), 400)

            return make_json_response({
                "filename": filename,
                "size": size,
                "result": "success"
            })

        except Exception as e:
            self._logger.error(f"Error in upload process: {e}")
            return make_json_exception(BadRequestError(f"Failed to upload firmware:{e}"), 502)

    @exposed_http("POST", "/fingerbot/upgrade")
    async def _upgrade_handler(self, request: Request) -> Response:
        try:
            if not os.path.exists("/tmp/fgb_image/finger_robot.signed.bin"):
                return make_json_exception(BadRequestError("No firmware file found, please upload first"), 400)

            process = await create_subprocess_exec(
                "/usr/sbin/fingerbot",
                "image-upgrade",
                "/tmp/fgb_image/finger_robot.signed.bin",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error = process.stderr.strip() if process.stderr else "Unknown error"
                get_logger(0).error(f"stdout: {process.stdout}")
                return make_json_exception(BadGatewayError("Failed to upgrade firmware"), 502)


            return make_json_response({"result": "success"})

        except Exception as e:
            self._logger.error(f"Error in upgrade process: {e}")
            return make_json_exception(BadGatewayError("Failed to upgrade firmware"), 502)
