import asyncio
import subprocess
import os
from typing import AsyncGenerator

from ... import aiotools
from ...logging import get_logger

from . import AtxError
from . import AtxIsBusyError
from . import BaseAtx



class Plugin(BaseAtx):
    def __init__(self) -> None:
        self.__device = "/dev/ttyACM0"
        self.__atxpower_bin = "/usr/sbin/atxpower"
        self.__notifier = aiotools.AioNotifier()
        self.__region = aiotools.AioExclusiveRegion(AtxIsBusyError, self.__notifier)
        self.__need_update = False

    async def get_state(self) -> dict:
        try:

            device_exists = os.path.exists(self.__device)
            if not device_exists:
                return {
                    "enabled": False,
                    "busy": self.__region.is_busy(),
                    "power": False,
                    "leds": {
                        "power": False,
                        "hdd": False,
                    },
                }


            cmd = f"{self.__atxpower_bin} {self.__device} power_state"

            try:

                def run_command():
                    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)

                result = await aiotools.run_async(run_command)

                if result.returncode != 0:
                    error = result.stderr.strip() if result.stderr else "Unknown error"
                    raise AtxError(f"Failed to get power state: {error}")

                power_state = result.stdout.strip()
                power_state_bool = (power_state == "on" or power_state == "sleep")

                return {
                    "enabled": True,
                    "busy": self.__region.is_busy(),
                    "power": power_state_bool,
                    "leds": {
                        "power": False,
                        "hdd": False,
                    },
                }
            except subprocess.TimeoutExpired:
                get_logger(0).error("Timeout while getting power state")
                raise AtxError("Command timeout while getting power state")

        except Exception as e:
            get_logger(0).error("Failed to get power state: %s", str(e))
            return {
                "enabled": False,
                "busy": self.__region.is_busy(),
                "power": False,
                "leds": {
                    "power": False,
                    "hdd": False,
                },
            }

    async def trigger_state(self) -> None:
        self.__need_update = True

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        prev_device_exists = os.path.exists(self.__device)
        prev_state = await self.get_state()

        while True:
            try:

                current_device_exists = os.path.exists(self.__device)


                if current_device_exists != prev_device_exists or current_device_exists:
                    state = await self.get_state()
                    if self.__need_update or state != prev_state:
                        get_logger(0).info(f"ATX状态变化: {state}")
                        yield state
                        prev_state = state
                        self.__need_update = False

                prev_device_exists = current_device_exists
            except Exception as e:
                get_logger(0).error(f"监测ATX设备状态时出错: {e}")

            await asyncio.sleep(1)

    async def cleanup(self) -> None:
        pass


    @aiotools.atomic_fg
    async def __run_cmd(self, action: str, wait: bool) -> None:
        if wait:
            async with self.__region:
                await self.__inner_run_cmd(action)
        else:
            await aiotools.run_region_task(
                f"Can't perform ATX {action} operation or operation was not completed",
                self.__region, self.__inner_run_cmd, action,
            )

    async def power_on(self, wait: bool) -> None:
        await self.__run_cmd("power_on", wait)

    async def power_off(self, wait: bool) -> None:
        await self.__run_cmd("power_off", wait)

    async def power_off_hard(self, wait: bool) -> None:
        await self.__run_cmd("power_off_hard", wait)

    async def power_reset_hard(self, wait: bool) -> None:
        await self.__run_cmd("power_reset", wait)



    async def click_power(self, wait: bool) -> None:
        await self.__run_cmd("click_power_short", wait)

    async def click_power_long(self, wait: bool) -> None:
        await self.__run_cmd("click_power_long", wait)

    async def click_reset(self, wait: bool) -> None:
        await self.__run_cmd("click_reset", wait)




    @aiotools.atomic_fg
    async def __inner_run_cmd(self, action: str) -> None:
        cmd = f"{self.__atxpower_bin} {self.__device} {action}"
        try:

            def run_command():
                return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)

            try:
                result = await aiotools.run_async(run_command)

                if result.returncode != 0:
                    error = result.stderr.strip() if result.stderr else "Unknown error"
                    get_logger(0).error(f"stdout: {result.stdout}")
                    raise AtxError(f"Failed to execute {cmd}: {error}")

                get_logger(0).info("Executed ATX command %r", action)

            except subprocess.TimeoutExpired:
                get_logger(0).error("Timeout while executing ATX command %r", action)
                raise AtxError(f"Command timeout while executing {action}")

        except Exception as e:
            get_logger(0).error("Failed to execute ATX command %r: %s", action, str(e))
            raise
