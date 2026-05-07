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


import asyncio
import os
import signal
import time

from datetime import datetime
from typing import AsyncGenerator

from aiohttp.web import Request
from aiohttp.web import Response

from ....logging import get_logger

from .... import aiotools

from ....htserver import exposed_http
from ....htserver import make_json_response

from ....plugins.msd import BaseMsd

from ..streamer import Streamer


# =====
_NEED_USTREAMER_PATH = "/tmp/need_ustreamer"


class RecorderApi:
    def __init__(self, streamer: Streamer, msd: BaseMsd) -> None:
        self.__streamer = streamer
        self.__msd = msd

        self.__recording = False
        self.__start_time: float = 0.0
        self.__output_file: str = ""
        self.__process: (asyncio.subprocess.Process | None) = None
        self.__lock = asyncio.Lock()
        self.__notifier = aiotools.AioNotifier()

    # =====

    async def trigger_state(self) -> None:
        self.__notifier.notify()

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        while True:
            await self.__notifier.wait()
            yield self.__get_state()

    async def systask(self) -> None:
        while True:
            try:
                if self.__recording:
                    self.__notifier.notify()
                    await asyncio.sleep(1.0)
                else:
                    await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                raise

    async def cleanup(self) -> None:
        if self.__recording:
            await self.__do_stop()

    # =====

    def __get_state(self) -> dict:
        elapsed = int(time.time() - self.__start_time) if self.__recording else 0
        return {
            "recording": self.__recording,
            "elapsed_seconds": elapsed,
            "file": os.path.basename(self.__output_file),
        }

    async def __do_start(self) -> None:
        storage_root = self.__msd.get_storage_root()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(storage_root, f"rec_{timestamp}.mp4")

        cmd = (
            f"ustreamer-dump --sink kvmd::ustreamer::h264 --output - | "
            f"ffmpeg -hide_banner "
            f"-use_wallclock_as_timestamps 1 "
            f"-thread_queue_size 1024 -i pipe: "
            f"-itsoffset 1.2 -f alsa -thread_queue_size 1024 -i multi_hdmi_input "
            f"-c:v copy "
            f"-c:a aac -b:a 128k "
            f"-map 0:v:0 -map 1:a:0 "
            f"-af 'aresample=async=1' "
            f"-fflags +genpts+igndts "
            f"-avoid_negative_ts make_zero "
            f"-shortest "
            f"-y {output_file}"
        )

        try:
            with open(_NEED_USTREAMER_PATH, "w") as f:
                f.write("1")
        except Exception:
            get_logger(0).exception("Failed to write need_ustreamer flag")

        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )

        self.__process = process
        self.__output_file = output_file
        self.__start_time = time.time()
        self.__recording = True
        self.__notifier.notify()

        get_logger(0).info("Recording started: %s (pid=%d)", output_file, process.pid)

    async def __do_stop(self) -> None:
        process = self.__process
        if process is not None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except Exception:
                get_logger(0).exception("Failed to send SIGTERM to recorder process group")
            try:
                await asyncio.wait_for(process.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except Exception:
                    pass
                await process.wait()

        try:
            if os.path.exists(_NEED_USTREAMER_PATH):
                os.remove(_NEED_USTREAMER_PATH)
        except Exception:
            get_logger(0).exception("Failed to remove need_ustreamer flag")

        get_logger(0).info("Recording stopped: %s", self.__output_file)

        self.__process = None
        self.__recording = False
        self.__notifier.notify()

    # =====

    @exposed_http("GET", "/recorder")
    async def __state_handler(self, _: Request) -> Response:
        return make_json_response(self.__get_state())

    @exposed_http("POST", "/recorder/start")
    async def __start_handler(self, _: Request) -> Response:
        async with self.__lock:
            if not self.__recording:
                await self.__do_start()
        return make_json_response(self.__get_state())

    @exposed_http("POST", "/recorder/stop")
    async def __stop_handler(self, _: Request) -> Response:
        async with self.__lock:
            if self.__recording:
                await self.__do_stop()
        return make_json_response(self.__get_state())
