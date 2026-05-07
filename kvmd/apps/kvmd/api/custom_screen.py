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


from typing import Optional
from asyncio import create_subprocess_exec
import subprocess
import json
import os
import base64
import chardet
import shutil
from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    NotFoundError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger

logger = get_logger()


async def _ubus_send_async(service: str, event_data: str) -> None:
    """Send event to ubus service (fire-and-forget, no response expected)."""
    cmd = ["ubus", "send", service, event_data]
    try:
        process = await create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.warning(f"ubus send to {service} failed: {stderr.decode()}")
    except Exception as e:
        logger.warning(f"ubus send to {service} exception: {e}")


async def _ubus_call_async(service: str, method: str, args: dict = {}) -> dict:
    """Call ubus method and return response."""
    cmd = ["ubus", "call", service, method, json.dumps(args)]
    try:
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
    except Exception as e:
        logger.error(f"ubus call to {service}.{method} failed: {e}")
        raise


class CustomScreenApi:

    def __init__(self) -> None:
        self._logger = logger

    @exposed_http("GET", "/custom_screen/background")
    async def __get_background_handler(self, _: Request) -> Response:
        """Get custom background image as base64.

        背景图片路径从 ubus 获取，返回 base64 编码的数据 URI 格式。
        """
        try:
            # 从 ubus 获取当前背景图片路径
            res = await _ubus_call_async("gui", "custom_screen_get_status")
            bg_path = res.get("background_path", "")

            # 检查路径是否有效
            if not bg_path or not os.path.isfile(bg_path):
                return make_json_exception(
                    NotFoundError("Background image not found"),
                    status=404
                )

            # 读取文件内容并转为 base64
            with open(bg_path, "rb") as f:
                image_data = f.read()
            base64_data = base64.b64encode(image_data).decode("utf-8")

            # 根据扩展名确定 mime 类型
            ext = os.path.splitext(bg_path)[1].lower()
            mime_types = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg"
            }
            mime_type = mime_types.get(ext, "image/png")

            # 返回 base64 格式的数据 URI
            return make_json_response({
                "format": mime_type,
                "data": base64_data
            })

        except subprocess.CalledProcessError:
            return make_json_exception(
                NotFoundError("Background image not found"),
                status=404
            )
        except Exception as e:
            self._logger.error(f"Error getting background image: {e}")
            return make_json_exception(
                BadRequestError(f"Failed to get background image: {e}"),
                status=502
            )

    @exposed_http("GET", "/custom_screen/status")
    async def __get_status_handler(self, _: Request) -> Response:
        """Get custom screen status."""
        try:
            res = await _ubus_call_async("gui", "custom_screen_get_status")

            # 只返回屏幕模式、时间格式、日期格式，不包含背景路径信息
            return make_json_response({
                "screen_mode": res.get("screen_mode", "default"),
                "time_format": res.get("time_format", "24h"),
                "date_format": res.get("date_format", "locale")
            })
        except Exception as e:
            self._logger.error(f"Error getting custom screen status: {e}")
            return make_json_exception(
                BadRequestError(f"Failed to get custom screen status: {e}"),
                status=502
            )

    @exposed_http("POST", "/custom_screen/update_background")
    async def __update_background_handler(self, req: Request) -> Response:
        """Upload and update custom background image."""
        try:
            reader = await req.multipart()
            field = await reader.next()

            if field is None or field.name != "file":
                return make_json_exception(
                    BadRequestError("No file uploaded or invalid field name. Use 'file' as the field name"),
                    status=400
                )

            filename = field.filename
            if not filename:
                return make_json_exception(
                    BadRequestError("Filename is required"),
                    status=400
                )

            # 验证文件扩展名
            allowed_extensions = {".png", ".jpg", ".jpeg"}
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext not in allowed_extensions:
                return make_json_exception(
                    BadRequestError(f"Invalid file type. Allowed: {allowed_extensions}"),
                    status=400
                )

            upload_dir = "/tmp/custom_screen"
            os.makedirs(upload_dir, exist_ok=True)

            save_path = os.path.join(upload_dir, "background" + file_ext)
            size = 0
            max_size = 5 * 1024 * 1024  # 5MB

            with open(save_path, "wb") as f:
                while True:
                    chunk = await field.read_chunk()
                    if not chunk:
                        break
                    size += len(chunk)
                    # 实时检查文件大小
                    if size > max_size:
                        f.close()
                        os.remove(save_path)
                        return make_json_exception(
                            BadRequestError(f"File too large. Max size: {max_size // 1024 // 1024}MB"),
                            status=400
                        )
                    f.write(chunk)

            event_data = json.dumps({
                "event_module": "custom_screen",
                "event_type": "update_background",
                "event_data": json.dumps({"path": save_path})
            })

            await _ubus_send_async("gui", event_data)

            return make_json_response({
                "status": "success",
                "message": "Background image uploaded and update request sent",
                "path": save_path,
                "size": size
            })

        except Exception as e:
            self._logger.error(f"Error uploading background: {e}")
            return make_json_exception(
                BadRequestError(f"Failed to upload background: {e}"),
                status=502
            )

    @exposed_http("POST", "/custom_screen/delete_background")
    async def __delete_background_handler(self, _: Request) -> Response:
        """Delete custom background image."""
        try:
            event_data = json.dumps({
                "event_module": "custom_screen",
                "event_type": "delete_background"
            })

            await _ubus_send_async("gui", event_data)

            return make_json_response({
                "status": "success",
                "message": "Background delete request sent"
            })

        except Exception as e:
            self._logger.error(f"Error deleting background: {e}")
            return make_json_exception(
                BadRequestError(f"Failed to delete background: {e}"),
                status=502
            )

    @exposed_http("POST", "/custom_screen/update_screen_mode")
    async def __update_screen_mode_handler(self, req: Request) -> Response:
        """Update screen mode.

        Args:
            mode_str: One of "default", "clock_only", "wallpaper_only"
        """
        try:
            mode_str = req.query.get("mode_str", "").strip()

            valid_modes = ["default", "clock_only", "wallpaper_only"]
            if not mode_str or mode_str not in valid_modes:
                return make_json_exception(
                    BadRequestError(f"Invalid mode_str. Must be one of: {valid_modes}"),
                    status=400
                )

            event_data = json.dumps({
                "event_module": "custom_screen",
                "event_type": "update_screen_mode",
                "event_data": json.dumps({"mode_str": mode_str})
            })

            await _ubus_send_async("gui", event_data)

            return make_json_response({
                "status": "success",
                "message": f"Screen mode update request sent (mode={mode_str})"
            })

        except Exception as e:
            self._logger.error(f"Error updating screen mode: {e}")
            return make_json_exception(
                BadRequestError(f"Failed to update screen mode: {e}"),
                status=502
            )

    @exposed_http("POST", "/custom_screen/update_time_format")
    async def __update_time_format_handler(self, req: Request) -> Response:
        """Update time format.

        Args:
            format_str: One of "24h", "12h"
        """
        try:
            format_str = req.query.get("format_str", "").strip()

            valid_formats = ["24h", "12h"]
            if not format_str or format_str not in valid_formats:
                return make_json_exception(
                    BadRequestError(f"Invalid format_str. Must be one of: {valid_formats}"),
                    status=400
                )

            event_data = json.dumps({
                "event_module": "custom_screen",
                "event_type": "update_time_format",
                "event_data": json.dumps({"format_str": format_str})
            })

            await _ubus_send_async("gui", event_data)

            return make_json_response({
                "status": "success",
                "message": f"Time format update request sent (format={format_str})"
            })

        except Exception as e:
            self._logger.error(f"Error updating time format: {e}")
            return make_json_exception(
                BadRequestError(f"Failed to update time format: {e}"),
                status=502
            )

    @exposed_http("POST", "/custom_screen/update_date_format")
    async def __update_date_format_handler(self, req: Request) -> Response:
        """Update date format.

        Args:
            format_str: One of "locale", "mm_dd_yyyy", "dd_mm_yyyy", "yyyy_mm_dd"
        """
        try:
            format_str = req.query.get("format_str", "").strip()

            valid_formats = ["locale", "mm_dd_yyyy", "dd_mm_yyyy", "yyyy_mm_dd"]
            if not format_str or format_str not in valid_formats:
                return make_json_exception(
                    BadRequestError(f"Invalid format_str. Must be one of: {valid_formats}"),
                    status=400
                )

            event_data = json.dumps({
                "event_module": "custom_screen",
                "event_type": "update_date_format",
                "event_data": json.dumps({"format_str": format_str})
            })

            await _ubus_send_async("gui", event_data)

            return make_json_response({
                "status": "success",
                "message": f"Date format update request sent (format={format_str})"
            })

        except Exception as e:
            self._logger.error(f"Error updating date format: {e}")
            return make_json_exception(
                BadRequestError(f"Failed to update date format: {e}"),
                status=502
            )