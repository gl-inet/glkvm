import asyncio
import aiohttp
from aiohttp import web
from typing import Dict, Any
import time
import os
import re
import zipfile
import io
import datetime
import json
from ....logging import get_logger
from .... import htclient

from ....htserver import exposed_http, make_json_exception, make_json_response, start_streaming, stream_json, stream_json_exception
from ....validators.basic import valid_bool
from ....validators.net import valid_url

UPGRADE_DIR = "/userdata/"
UPGRADE_FILE = "update.img"
EDID_FILE = "/tmp/edid.bin"
EDID_USER_FILE = "/etc/kvmd/user/edid.txt"
LOG_DIR = "/tmp/log"
LT6911C_UPGRADE_CMD = "lt6911c_upgrade -d /dev/i2c-1 -e /tmp/edid.bin && sleep 1 && echo 1 >  /sys/bus/i2c/devices/1-002b/reset"
MODEL_PATH = "/proc/gl-hw-info/model"
BASE_URL = "https://fw.gl-inet.com/kvm/{model}/release"

class UpgradeApi:
    def __init__(self):
        self.__download_lock = asyncio.Lock()
        self.__current_download_task = None
        self.__total_firmware_size = 0


        try:
            with open(MODEL_PATH, "r") as f:
                model = f.read().strip()
        except Exception as e:
            get_logger(0).warning(f"Failed to read model info, using default value rm1: {str(e)}")
            model = "rm1"


        self.__version_url = f"{BASE_URL.format(model=model)}/version"
        self.__firmware_url = f"{BASE_URL.format(model=model)}/update.img"
        self.__update_engine = UpdateEngine(BASE_URL.format(model=model))

    def __validate_edid(self, edid_str: str) -> bool:

        edid_str = ''.join(edid_str.split())


        if len(edid_str) not in [256, 512]:
            return False


        if not re.match(r'^[0-9A-Fa-f]+$', edid_str):
            return False

        return True

    def __convert_edid_to_bytes(self, edid_str: str) -> bytes:

        edid_str = ''.join(edid_str.split())


        if len(edid_str) == 256:

            additional_bytes = (
                "02 03 12 F0 23 09 04 01 83 01 00 00 65 03 0C 00 "
                "10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0"
            )

            additional_bytes = ''.join(additional_bytes.split())

            edid_str = edid_str + additional_bytes
            get_logger(0).info("EDID is only 128 bytes, automatically appending additional 128 bytes")


        return bytes.fromhex(edid_str)

    @exposed_http("POST", "/upgrade/upload")
    async def __upload_handler(self, request: web.Request) -> web.Response:
        reader = await request.multipart()
        field = await reader.next()
        if field and field.name == "file":
            filename = field.filename

            self.__total_firmware_size = 0
            size = 0

            with open(f"{UPGRADE_DIR}{UPGRADE_FILE}", "wb") as f:
                while True:
                    chunk = await field.read_chunk()
                    if not chunk:
                        break
                    size += len(chunk)
                    f.write(chunk)
            get_logger(0).info("Firmware file uploaded, size: %d bytes", size)
            return make_json_response({"filename": filename, "size": size})
        return web.HTTPBadRequest(text="No file uploaded")

    @exposed_http("GET", "/upgrade/compare")
    async def __compare_handler(self, request: web.Request) -> web.Response:
        result = await self.__update_engine.compare_versions()
        return make_json_response(result)

    @exposed_http("GET", "/upgrade/version")
    async def __version_handler(self, request: web.Request) -> web.Response:
        version = await self.__update_engine.get_local_verion()
        return make_json_response({"version": version})

    @exposed_http("GET", "/upgrade/reboot")
    async def __reboot_handler(self, request: web.Request) -> web.Response:
        asyncio.create_task(self.__delayed_reboot())
        return make_json_response({"status": "Reboot started"})

    @exposed_http("POST", "/upgrade/start")
    async def __start_handler(self, request: web.Request) -> web.Response:
        save_config = request.query.get("save_config")

        save_config_value = str(save_config).lower() if save_config is not None else "true"
        should_save = save_config_value not in ["false", "0"]

        result = await self.__update_engine.start_upgrade(save_config=should_save)
        if result.get("status") == "Upgrade started":
            asyncio.create_task(self.__delayed_reboot())
        return make_json_response(result)

    async def __delayed_reboot(self):
        await asyncio.create_subprocess_shell("sync")
        await asyncio.sleep(1)
        await asyncio.create_subprocess_shell("reboot")

    @exposed_http("GET", "/upgrade/status")
    async def __status_handler(self, request: web.Request) -> web.Response:
        return make_json_response({"enabled": True})

    @exposed_http("GET", "/upgrade/reset_default")
    async def __reset_default_handler(self, request: web.Request) -> web.Response:

        asyncio.create_task(self.__delayed_reset_default())
        return make_json_response({"status": "Reset to factory default started"})

    async def __delayed_reset_default(self):

        await asyncio.create_subprocess_shell("sync")
        await asyncio.sleep(1)

        await asyncio.create_subprocess_shell("/usr/sbin/reset_default.sh")

    @exposed_http("GET", "/upgrade/download")
    async def __download_handler(self, request: web.Request) -> web.StreamResponse:

        if self.__current_download_task and not self.__current_download_task.done():
            self.__current_download_task.cancel()
            try:
                await self.__current_download_task
            except asyncio.CancelledError:
                pass


        self.__current_download_task = asyncio.create_task(self._download_latest_firmware(request))
        return await self.__current_download_task

    @exposed_http("GET", "/upgrade/download_cancel")
    async def __download_cancel_handler(self, request: web.Request) -> web.Response:
        self.__total_firmware_size = 0
        if self.__current_download_task and not self.__current_download_task.done():

            self.__current_download_task.cancel()
            try:
                await self.__current_download_task
            except asyncio.CancelledError:
                pass
            get_logger(0).info("Firmware download task has been manually cancelled")
            return make_json_response({"status": "success", "message": "download task has been cancelled"})
        else:
            return make_json_response({"status": "warning", "message": "no download task is running"})

    @exposed_http("GET", "/upgrade/download_info")
    async def __download_info_handler(self, request: web.Request) -> web.Response:

        try:
            size = os.path.getsize(f"{UPGRADE_DIR}{UPGRADE_FILE}")
        except Exception as ex:
            return make_json_response({"size": 0, "total_size": 0})
        return make_json_response({"size": size, "total_size": self.__total_firmware_size})

    @exposed_http("POST", "/upgrade/edid")
    async def __edid_handler(self, request: web.Request) -> web.Response:
        try:

            data = await request.post()
            edid_str = data.get("edid", "")


            if not self.__validate_edid(edid_str):
                return make_json_exception("Invalid EDID format", 400)


            edid_bytes = self.__convert_edid_to_bytes(edid_str)


            with open(EDID_FILE, "wb") as f:
                f.write(edid_bytes)


            os.makedirs(os.path.dirname(EDID_USER_FILE), exist_ok=True)
            with open(EDID_USER_FILE, "w") as f:
                f.write(edid_str)
            await asyncio.create_subprocess_shell("sync")


            proc = await asyncio.create_subprocess_shell(
                LT6911C_UPGRADE_CMD,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                return make_json_exception(f"Failed to execute lt6911c_upgrade: {stderr.decode()}", 500)

            return make_json_response({
                "status": "success",
                "message": "EDID data has been written and applied"
            })

        except Exception as ex:
            return make_json_exception(str(ex), 500)

    @exposed_http("GET", "/upgrade/get_edid")
    async def __get_edid_handler(self, request: web.Request) -> web.Response:
        try:
            if not os.path.exists(EDID_USER_FILE):

                return make_json_response({"edid": ""})


            with open(EDID_USER_FILE, "r") as f:
                edid_str = f.read().strip()

            return make_json_response({"edid": edid_str})

        except Exception as ex:
            get_logger(0).error(f"Error getting EDID data: {str(ex)}")
            return make_json_exception(str(ex), 500)

    @exposed_http("GET", "/upgrade/log")
    async def __log_handler(self, request: web.Request) -> web.Response:
        try:

            os.makedirs(LOG_DIR, exist_ok=True)


            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


            log_commands = {
                "dmesg": f"{LOG_DIR}/dmesg_{timestamp}.log",
                "logread": f"{LOG_DIR}/logread_{timestamp}.log",
                "lsusb": f"{LOG_DIR}/lsusb_{timestamp}.log",
                "ps auxww": f"{LOG_DIR}/ps_auxww_{timestamp}.log",
                "cat /proc/meminfo": f"{LOG_DIR}/meminfo_{timestamp}.log",
                "cat /etc/version": f"{LOG_DIR}/version_{timestamp}.log",
                "cat /proc/gl-hw-info/device_mac": f"{LOG_DIR}/device_mac_{timestamp}.log",
                "cat /etc/glinet/gl-cloud.conf": f"{LOG_DIR}/gl-cloud.conf_{timestamp}.log",
                "ifconfig": f"{LOG_DIR}/ifconfig_{timestamp}.log",
                "wg": f"{LOG_DIR}/wg_{timestamp}.log"
            }


            for cmd, filename in log_commands.items():
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                with open(filename, "wb") as f:
                    f.write(stdout)
                    if stderr:
                        f.write(b"\n\n--- STDERR ---\n\n")
                        f.write(stderr)

                get_logger(0).info(f"Log collected: {filename}")


            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
                for _, log_file in log_commands.items():
                    if os.path.exists(log_file):

                        zip_file.write(log_file, os.path.basename(log_file))


            response = web.StreamResponse()
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = f'attachment; filename="system_logs_{timestamp}.zip"'


            zip_buffer.seek(0, io.SEEK_END)
            size = zip_buffer.tell()
            zip_buffer.seek(0)

            response.content_length = size
            await response.prepare(request)


            await response.write(zip_buffer.getvalue())


            for _, log_file in log_commands.items():
                if os.path.exists(log_file):
                    os.remove(log_file)


            try:
                os.rmdir(LOG_DIR)
            except OSError:
                pass

            await response.write_eof()
            return response

        except Exception as ex:
            get_logger(0).error(f"Error collecting logs: {str(ex)}")
            return make_json_exception(f"Error collecting logs: {str(ex)}", 500)

    async def _download_latest_firmware(self, request: web.Request) -> web.StreamResponse:
        written = size = 0

        async with self.__download_lock:
            try:

                version, firmware_filename = await self.__update_engine.get_list_sha256()
                if not firmware_filename:
                    raise Exception("Unable to get firmware filename")


                firmware_url = f"{self.__update_engine.get_base_url()}/{firmware_filename}"
                get_logger(0).info("Generated firmware URL: %s", firmware_url)

                async with htclient.download(
                    url=firmware_url,
                    timeout=10.0,
                    read_timeout=(7 * 24 * 3600),
                ) as remote:
                    size = remote.content_length
                    if not size:
                        raise Exception("Unable to get firmware size")


                    response = make_json_response({"size": size})
                    self.__total_firmware_size = size
                    await response.prepare(request)
                    await response.write_eof()

                    get_logger(0).info("Downloading firmware from %r to %r ...", firmware_url, f"{UPGRADE_DIR}{UPGRADE_FILE}")


                    chunk_size = 8192
                    with open(f"{UPGRADE_DIR}{UPGRADE_FILE}", "wb") as f:
                        try:
                            async for chunk in remote.content.iter_chunked(chunk_size):
                                f.write(chunk)
                                written += len(chunk)
                        except asyncio.CancelledError:
                            get_logger(0).info("Download task cancelled")
                            raise

                    return response

            except Exception as ex:
                if isinstance(ex, aiohttp.ClientError):
                    return make_json_exception(ex, 400)
                raise

class UpdateEngine:
    def __init__(self,base_url: str):
        self.__base_url = base_url
        self.__version_url = base_url+"/version"
        self.__firmware_url = base_url+"/update.img"
        self.__list_sha256_url = base_url+"/list-sha256.txt"

    async def get_local_verion(self):
        with open("/etc/version", "r") as f:
            local_content = f.read().strip()
        local_dict = dict(line.split('=') for line in local_content.splitlines())
        return local_dict.get('RK_VERSION', '')

    async def get_list_sha256(self)->tuple[str,str]:
        async with aiohttp.ClientSession() as session:
            async with session.get(self.__list_sha256_url) as response:
                if response.status == 200:
                    content = await response.text()
                    first_line = content.splitlines()[0]
                    version = first_line.split()[0]
                    firmware = first_line.split()[1]
                    return version,firmware
                else:
                    return "", ""

    def get_base_url(self) -> str:
        """获取base_url"""
        return self.__base_url

    async def __get_metadata(self, version: str) -> Dict[str, Any]:
        """获取指定版本的metadata信息"""
        try:
            metadata_url = f"{self.__base_url}/metadata_{version}"
            async with aiohttp.ClientSession() as session:
                async with session.get(metadata_url) as response:
                    if response.status == 200:
                        text = await response.text()
                        metadata = json.loads(text)
                        return metadata
                    else:
                        get_logger(0).error(f"Failed to get metadata: {response.status}")
                        return {}
        except Exception as e:
            get_logger(0).error(f"Error getting metadata: {str(e)}")
            return {}

    async def compare_versions(self) -> Dict[str, Any]:

        result = {
            "local_model": "",
            "local_version": "",
            "server_model": "",
            "server_version": "",
            "error": None
        }


        try:
            with open("/etc/version", "r") as f:
                local_content = f.read().strip()
            local_dict = dict(line.split('=') for line in local_content.splitlines())
            result["local_model"] = local_dict.get('RK_MODEL', '')
            result["local_version"] = local_dict.get('RK_VERSION', '')
        except Exception as e:
            result["error"] = f"Failed to read local version: {str(e)}"
            return result


        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.__list_sha256_url) as response:
                    if response.status == 200:
                        list_content = await response.text()

                        first_line = list_content.splitlines()[0]
                        version = first_line.split()[0]


                        metadata = await self.__get_metadata(version)
                        if metadata and "version" in metadata:
                            version_info = metadata["version"]
                            result["server_model"] = result["local_model"]
                            result["server_version"] = f"V{version_info['release']} {version_info['firmware_type']}"
                            result["release_note"] = metadata.get("release_note", "")
                            result["release_note_cn"] = metadata.get("release_note_cn", "")
                        else:
                            result["error"] = "Unable to get server version information"
                    else:
                        result["error"] = f"Server returned status code: {response.status}"
        except Exception as e:
            result["error"] = f"Failed to fetch server version: {str(e)}"

        return result

    async def start_upgrade(self,save_config: bool=True) -> Dict[str, str]:
        save_config_cmd = " --keep_config" if save_config else ""
        cmd = f"updateEngine --image_url={UPGRADE_DIR}{UPGRADE_FILE} --misc=update --savepath=/userdata/update.img --n {save_config_cmd}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return {"status": "Upgrade started", "stdout": stdout.decode(), "stderr": stderr.decode()}
        else:
            return {"status": "Upgrade failed", "stdout": stdout.decode(), "stderr": stderr.decode()}
