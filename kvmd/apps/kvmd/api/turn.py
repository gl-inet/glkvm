




















from typing import Optional, AsyncGenerator
from asyncio import sleep, create_task, CancelledError
import os
import json
import asyncio

from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger
from ....inotify import Inotify, InotifyMask

logger = get_logger()


class TurnApi:
    _turn_file_path = "/tmp/turnserver.json"
    __need_update = False

    def __init__(self) -> None:
        self._logger = logger
        self._last_mtime: Optional[float] = None
        self._inotify_task: Optional[asyncio.Task] = None

    def _get_file_mtime(self) -> Optional[float]:
        """获取文件的修改时间"""
        try:
            if os.path.exists(self._turn_file_path):
                return os.path.getmtime(self._turn_file_path)
            return None
        except Exception as e:
            self._logger.error(f"Error getting file mtime: {e}")
            return None

    def _read_turn_file(self) -> Optional[dict]:
        """读取 turnserver.json 文件内容"""
        try:
            if not os.path.exists(self._turn_file_path):
                return None

            with open(self._turn_file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self._logger.error(f"Error reading turn file: {e}")
            return None

    async def get_state(self) -> dict:
        """获取当前状态"""
        return self._read_turn_file() or {}

    async def _inotify_watcher(self) -> AsyncGenerator[dict, None]:
        """使用 inotify 监听文件变化"""
        try:
            with Inotify() as inotify:

                watch_dir = os.path.dirname(self._turn_file_path)


                os.makedirs(watch_dir, exist_ok=True)


                await inotify.watch_all_changes(watch_dir)

                self._logger.info(f"Started inotify watching for {self._turn_file_path}")


                prev_turn_data = self._read_turn_file()
                if prev_turn_data is not None:
                    yield prev_turn_data


                while True:
                    events = await inotify.get_series(timeout=1)
                    for event in events:

                        if event.path == self._turn_file_path:
                            turn_data = self._read_turn_file()


                            if turn_data != prev_turn_data:
                                self._logger.info(f"Turn file changed, sending updated content")

                                if turn_data is not None:
                                    yield turn_data
                                prev_turn_data = turn_data
                            else:
                                self._logger.debug(f"Turn file modified but content unchanged, skipping update")
                    if self.__need_update:
                        self.__need_update = False
                        turn_data = self._read_turn_file()
                        prev_turn_data = turn_data
                        yield turn_data

        except Exception as e:
            self._logger.error(f"Error in inotify watcher: {e}")

            async for event in self._polling_watcher():
                yield event

    async def _polling_watcher(self) -> AsyncGenerator[dict, None]:
        """轮询模式监听文件变化（作为 inotify 的后备方案）"""
        prev_data = None

        while True:
            current_data = self._read_turn_file()


            if prev_data != current_data:
                if current_data is not None:
                    yield current_data
                prev_data = current_data
            elif self.__need_update:
                yield current_data
                prev_data = current_data
                self.__need_update = False

            await sleep(1)

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        """监听文件状态变化"""
        try:
            async for event in self._inotify_watcher():
                yield event
        except CancelledError:
            self._logger.info("Turn file monitoring cancelled")
            raise
        except Exception as e:
            self._logger.error(f"Error in poll_state: {e}")

            async for event in self._polling_watcher():
                yield event

    async def trigger_state(self) -> None:
        """触发状态更新"""
        self.__need_update = True

    @exposed_http("GET", "/turn/get_turn")
    async def _get_turn_handler(self, _: Request) -> Response:
        """获取 turnserver.json 文件内容的 API"""
        if not os.path.exists(self._turn_file_path):
            return make_json_exception(
                BadRequestError("turnserver.json file not found"), 404
            )

        turn_data = self._read_turn_file()
        if turn_data is None:
            return make_json_exception(
                BadRequestError("Failed to read turnserver.json file"), 500
            )

        return make_json_response(turn_data)
