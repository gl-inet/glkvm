from typing import Dict
import asyncio

from aiohttp.web import Request
from aiohttp.web import Response
from typing import AsyncGenerator


from ....validators.basic import valid_bool

from ....validators.kvm import valid_stream_quality
from ....validators.kvm import valid_stream_fps
from ....validators.kvm import valid_stream_resolution
from ....validators.kvm import valid_stream_h264_bitrate
from ....validators.kvm import valid_stream_h264_gop

from ....htserver import make_json_response
from ....htserver import exposed_http



class RndisApi:
    def __init__(self):
        self.running = False
        return

    @exposed_http("POST", "/rndis/start")
    async def __start_handler(self, _: Request) -> Response:
        print("Starting RNDIS")
        try:
            import asyncio
            process = await asyncio.create_subprocess_exec(
                "kvmd-rndis", "start",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            if process.returncode != 0:
                raise Exception("Failed to start RNDIS")
            self.running = True
        except Exception as err:
            raise Exception(str(err))
        return make_json_response()

    @exposed_http("POST", "/rndis/stop")
    async def __stop_handler(self, _: Request) -> Response:
        print("Stopping RNDIS")
        try:
            import asyncio
            process = await asyncio.create_subprocess_exec(
                "kvmd-rndis", "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            if process.returncode != 0:
                raise Exception("Failed to stop RNDIS")
            self.running = False
        except Exception as err:
            raise Exception(str(err))
        return make_json_response()

    @exposed_http("GET", "/rndis/status")
    async def __status_handler(self, _: Request) -> Response:
        try:
            state = await self.get_state()
            return make_json_response(state)
        except Exception as err:
            raise Exception(str(err))

    async def get_state(self) -> dict:
        return {
            "running": self.running
        }

    async def trigger_state(self) -> None:
        pass

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        prev_running = None
        while True:
            if self.running != prev_running:
                yield self.get_state()
                prev_running = self.running
            await asyncio.sleep(1)