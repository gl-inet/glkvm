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


import dataclasses
import os
import pathlib

from typing import Callable
from typing import Coroutine
from typing import AsyncGenerator
from typing import Any

from aiohttp.web import Request
from aiohttp.web import Response
from aiohttp.web import WebSocketResponse

from ... import __version__

from ...logging import get_logger
from ...utils import parse_user_agent

from ...errors import OperationError

from ... import aiotools
from ... import aioproc
import asyncio

from ...htserver import HttpExposed
from ...htserver import exposed_http
from ...htserver import exposed_ws
from ...htserver import make_json_response
from ...htserver import WsSession
from ...htserver import HttpServer

from ...plugins import BasePlugin
from ...plugins.hid import BaseHid
from ...plugins.atx import BaseAtx
from ...plugins.msd import BaseMsd

from ...validators.basic import valid_bool
from ...validators.kvm import valid_stream_quality
from ...validators.kvm import valid_stream_fps
from ...validators.kvm import valid_stream_resolution
from ...validators.kvm import valid_stream_video_format
from ...validators.kvm import valid_stream_h264_bitrate
from ...validators.kvm import valid_stream_h264_gop
from ...validators.kvm import valid_stream_zero_delay
from ...validators.kvm import valid_stream_venc_mode

from .auth import AuthManager
from .init import InitManager
from .info import InfoManager
from .logreader import LogReader
from .ugpio import UserGpio
from .streamer import Streamer
from .snapshoter import Snapshoter
from .ocr import Ocr
from .switch import Switch

from .api.auth import AuthApi
from .api.auth import check_request_auth

from .api.init import InitApi
from .api.twofa import TwoFaApi
from .api.astrowarp import AstrowarpApi
from .api.fingerbot import FingerbotApi
from .api.turn import TurnApi
from .api.repeater import RepeaterApi
from .api.modem import ModemApi
from .api.ap import ApApi
from .api.wol import WolApi
from .api.tailscale import TailscaleApi
from .api.netbird import NetbirdApi
from .api.cloudflare import CloudflareApi
from .api.zerotier import ZerotierApi
from .api.system import SystemApi
from .api.info import InfoApi
from .api.log import LogApi
from .api.ugpio import UserGpioApi
from .api.hid import HidApi
from .api.atx import AtxApi
from .api.msd import MsdApi
from .api.rndis import RndisApi
from .api.upgrade import UpgradeApi
from .api.streamer import StreamerApi
from .api.switch import SwitchApi
from .api.export import ExportApi
from .api.redfish import RedfishApi
from .api.custom_screen import CustomScreenApi
from .api.recorder import RecorderApi


# =====
class StreamerQualityNotSupported(OperationError):
    def __init__(self) -> None:
        super().__init__("This streamer does not support quality settings")


class StreamerResolutionNotSupported(OperationError):
    def __init__(self) -> None:
        super().__init__("This streamer does not support resolution settings")


class StreamerH264NotSupported(OperationError):
    def __init__(self) -> None:
        super().__init__("This streamer does not support H264")


# =====
@dataclasses.dataclass
class _Subsystem:
    name:          str
    event_type:    str
    sysprep:       (Callable[[], None] | None)
    systask:       (Callable[[], Coroutine[Any, Any, None]] | None)
    cleanup:       (Callable[[], Coroutine[Any, Any, dict]] | None)
    trigger_state: (Callable[[], Coroutine[Any, Any, None]] | None) = None
    poll_state:    (Callable[[], AsyncGenerator[dict, None]] | None) = None

    def __post_init__(self) -> None:
        if self.event_type:
            assert self.trigger_state
            assert self.poll_state

    @classmethod
    def make(cls, obj: object, name: str, event_type: str="") -> "_Subsystem":
        if isinstance(obj, BasePlugin):
            name = f"{name} ({obj.get_plugin_name()})"
        return _Subsystem(
            name=name,
            event_type=event_type,
            sysprep=getattr(obj, "sysprep", None),
            systask=getattr(obj, "systask", None),
            cleanup=getattr(obj, "cleanup", None),
            trigger_state=getattr(obj, "trigger_state", None),
            poll_state=getattr(obj, "poll_state", None),
        )


class KvmdServer(HttpServer):  # pylint: disable=too-many-arguments,too-many-instance-attributes
    __EV_GPIO_STATE = "gpio"
    __EV_HID_STATE = "hid"
    __EV_HID_KEYMAPS_STATE = "hid_keymaps"  # FIXME
    __EV_ATX_STATE = "atx"
    __EV_MSD_STATE = "msd"
    __EV_STREAMER_STATE = "streamer"
    __EV_OCR_STATE = "ocr"
    __EV_INFO_STATE = "info"
    __EV_SWITCH_STATE = "switch"
    __EV_RNDIS_STATE = "rndis"
    __EV_FINGERBOT_STATE = "fingerbot"
    __EV_REPEATER_STATE = "repeater"
    __EV_MODEMO_STATE = "modem"
    __EV_AP_STATE = "ap"
    __EV_TURN_STATE = "turn"
    __EV_RECORDER_STATE = "recorder"

    def __init__(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        auth_manager: AuthManager,
        init_manager: InitManager,
        info_manager: InfoManager,
        log_reader: (LogReader | None),
        user_gpio: UserGpio,
        ocr: Ocr,
        switch: (Switch | None),

        hid: BaseHid,
        atx: BaseAtx,
        msd: BaseMsd,
        rndis: RndisApi,
        upgrade: UpgradeApi,
        streamer: Streamer,
        snapshoter: Snapshoter,

        keymap_path: str,

        stream_forever: bool,
    ) -> None:

        super().__init__()

        self.__auth_manager = auth_manager
        self.__init_manager = init_manager
        self.__hid = hid
        self.__streamer = streamer
        self.__snapshoter = snapshoter  # Not a component: No state or cleanup

        self.__stream_forever = stream_forever
        self.__switch = switch
        self.__fingerbot_api = FingerbotApi()
        self.__turn_api = TurnApi()
        self.__repeater_api = RepeaterApi()
        self.__modem_api = ModemApi()
        self.__ap_api = ApApi()
        self.__custom_screen_api = CustomScreenApi()
        self.__recorder_api = RecorderApi(streamer, msd)
        self.__hid_api = HidApi(hid, keymap_path)  # Ugly hack to get keymaps state
        self.__apis: list[object] = [
            self,
            AuthApi(auth_manager),
            InitApi(init_manager),
            TwoFaApi(),
            AstrowarpApi(),
            self.__fingerbot_api,
            WolApi(),
            self.__repeater_api,
            self.__modem_api,
            self.__ap_api,
            self.__custom_screen_api,
            TailscaleApi(),
            NetbirdApi(),
            CloudflareApi(),
            ZerotierApi(),
            self.__turn_api,
            SystemApi(
                get_wss_callback=self._get_wss,
                close_ws_callback=self._close_ws_by_session,
                logout_callback=auth_manager.logout,
            ),
            InfoApi(info_manager),
            LogApi(log_reader),
            UserGpioApi(user_gpio),
            self.__hid_api,
            AtxApi(atx),
            MsdApi(msd),
            RndisApi(),
            UpgradeApi(),
            StreamerApi(streamer, ocr),
            self.__recorder_api,
            # SwitchApi(switch),
            ExportApi(info_manager, atx, user_gpio),
            RedfishApi(info_manager, atx),
        ]
        if self.__switch is not None:
            self.__apis.append(SwitchApi(self.__switch))
        self.__subsystems = [
            _Subsystem.make(auth_manager, "Auth manager"),
            _Subsystem.make(user_gpio,    "User-GPIO",    self.__EV_GPIO_STATE),
            _Subsystem.make(hid,          "HID",          self.__EV_HID_STATE),
            _Subsystem.make(atx,          "ATX",          self.__EV_ATX_STATE),
            _Subsystem.make(msd,          "MSD",          self.__EV_MSD_STATE),
            _Subsystem.make(streamer,     "Streamer",     self.__EV_STREAMER_STATE),
            _Subsystem.make(ocr,          "OCR",          self.__EV_OCR_STATE),
            _Subsystem.make(info_manager, "Info manager", self.__EV_INFO_STATE),
            # _Subsystem.make(switch,       "Switch",       self.__EV_SWITCH_STATE),
            _Subsystem.make(rndis,        "RNDIS",        self.__EV_RNDIS_STATE),
            _Subsystem.make(self.__fingerbot_api, "Fingerbot", self.__EV_FINGERBOT_STATE),
            _Subsystem.make(self.__repeater_api, "Repeater", self.__EV_REPEATER_STATE),
            _Subsystem.make(self.__modem_api, "Modem", self.__EV_MODEMO_STATE),
            _Subsystem.make(self.__ap_api, "Ap", self.__EV_AP_STATE),
            _Subsystem.make(self.__turn_api, "turn", self.__EV_TURN_STATE),
            _Subsystem.make(self.__recorder_api, "Recorder", self.__EV_RECORDER_STATE),
        ]
        if self.__switch is not None:
            self.__subsystems.append(_Subsystem.make(switch, "Switch", self.__EV_SWITCH_STATE))

        self.__streamer_notifier = aiotools.AioNotifier()
        self.__reset_streamer = False
        self.__new_streamer_params: dict = {}

        # ===== 自适应模式 (webrtc_client) 相关状态
        self.__adaptive_mode: bool = False
        self.__webrtc_client_proc: (asyncio.subprocess.Process | None) = None  # pylint: disable=no-member
        self.__webrtc_client_task: (asyncio.Task | None) = None
        self.__webrtc_client_cmd: list[str] = ["/usr/bin/webrtc_client"]

    # ===== ADAPTIVE MODE (webrtc_client) MANAGEMENT

    @staticmethod
    async def __kill_proc_graceful(proc_name: str, logger: Any) -> None:
        """先发 SIGTERM，等待 500ms 后若进程仍存在则发 SIGKILL。
        既给进程机会清理 PID 文件/Unix socket（避免残留导致重启失败），
        又将缓冲区播放时长限制在 ≤500ms（优于纯 SIGTERM 的 ~1s）。
        """
        # --- SIGTERM：请求进程自行清理后退出 ---
        try:
            p = await asyncio.create_subprocess_exec(
                "killall", "-TERM", proc_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            rc = await p.wait()
            if rc != 0:
                # rc != 0 表示进程本就不存在，无需继续等待和 SIGKILL
                logger.debug("%s not running (killall -TERM rc=%d), skipping SIGKILL", proc_name, rc)
                return
            logger.info("Sent SIGTERM to %s, waiting 500ms ...", proc_name)
        except Exception as ex:
            # killall 本身执行失败（如二进制缺失），无法确认进程状态，跳过后续操作
            logger.warning("Failed to send SIGTERM to %s: %s", proc_name, ex)
            return

        # 等待进程响应 SIGTERM 并自行清理；500ms 是优雅关闭的超时上限。
        # 若进程在此期间已退出，后续 SIGKILL 会返回 rc!=0 并静默跳过，无额外代价。
        await asyncio.sleep(0.5)

        # --- SIGKILL：兜底确保进程完全退出 ---
        try:
            p = await asyncio.create_subprocess_exec(
                "killall", "-9", proc_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            rc = await p.wait()
            if rc == 0:
                logger.info("Sent SIGKILL to %s", proc_name)
            else:
                # 进程已在 500ms 内自行退出，SIGKILL 时已不存在——正常情况
                logger.debug("%s already exited before SIGKILL (rc=%d)", proc_name, rc)
        except Exception as ex:
            logger.warning("Failed to send SIGKILL to %s: %s", proc_name, ex)

    async def __enter_adaptive_mode(self) -> None:
        """进入自适应模式：杀掉 janus 和 ustreamer，启动 webrtc_client 并加入看门狗"""
        logger = get_logger(0)
        logger.info("Entering adaptive mode: killing janus and ustreamer, starting webrtc_client ...")

        try:
            # 首先设置标志。放在 try 内，确保若后续操作因 CancelledError 或异常
            # 失败时，except BaseException 的回滚能完整覆盖该标志的状态，
            # 避免 _on_cleanup 等并发路径在 await 点看到 True 但资源尚未就绪的窗口。
            self.__adaptive_mode = True

            # 先写入禁用标志文件，阻止 JanusRunner 在 janus 被杀后自动重启它
            try:
                pathlib.Path("/tmp/kvmd_janus_disable").write_text("1")
                logger.info("Wrote /tmp/kvmd_janus_disable to suppress JanusRunner auto-restart")
            except Exception as ex:
                logger.warning("Failed to write /tmp/kvmd_janus_disable: %s", ex)

            # 停止 kvmd 的 ustreamer 进程
            await self.__streamer.ensure_stop(immediately=True, force=True)

            # 并行优雅终止 janus/ustreamer：SIGTERM → 等待 500ms → SIGKILL
            # 并行执行使总等待时间保持 ~500ms（而非串行的 ~1s+）；
            # SIGTERM 给进程机会删除 PID 文件和 Unix socket，防止残留影响后续重启
            await asyncio.gather(
                self.__kill_proc_graceful("janus", logger),
                self.__kill_proc_graceful("ustreamer", logger),
            )

            # 启动 webrtc_client 看门狗任务
            if self.__webrtc_client_task and not self.__webrtc_client_task.done():
                self.__webrtc_client_task.cancel()
                await asyncio.gather(self.__webrtc_client_task, return_exceptions=True)
            self.__webrtc_client_task = asyncio.create_task(self.__webrtc_client_watchdog())
            logger.info("Adaptive mode activated")
        except BaseException:
            # 进入失败（含 CancelledError），原子回滚所有状态，
            # 确保 _on_cleanup 等路径不会基于不完整状态做出错误决策
            logger.warning("Failed to enter adaptive mode, rolling back state ...")
            self.__adaptive_mode = False
            self.__webrtc_client_task = None
            self.__webrtc_client_proc = None
            try:
                pathlib.Path("/tmp/kvmd_janus_disable").unlink(missing_ok=True)
            except Exception:
                pass
            raise

    async def __exit_adaptive_mode(self) -> None:
        """退出自适应模式：停止 webrtc_client 看门狗，恢复正常流程"""
        logger = get_logger(0)
        logger.info("Exiting adaptive mode: stopping webrtc_client ...")
        self.__adaptive_mode = False

        # 先取消看门狗任务，再 kill webrtc_client 进程
        # 确保 webrtc_client 完全退出（释放音频设备）后，再移除禁用标志
        # 这样 JanusRunner 看到标志消失时可以立即启动 Janus，无需额外延迟
        if self.__webrtc_client_task and not self.__webrtc_client_task.done():
            self.__webrtc_client_task.cancel()
            await asyncio.gather(self.__webrtc_client_task, return_exceptions=True)
        self.__webrtc_client_task = None

        # 杀掉 webrtc_client 进程（如果还在运行）
        # 超时设为 2.0s：给 webrtc_client 足够时间正常释放 IOMMU/DMA 映射，
        # 避免 SIGKILL 强杀导致 rk_iommu page fault 错误风暴阻塞 asyncio 事件循环
        if self.__webrtc_client_proc:
            await aioproc.kill_process(self.__webrtc_client_proc, 2.0, logger)
            self.__webrtc_client_proc = None
        logger.info("Adaptive mode deactivated")

        # webrtc_client 已完全退出，现在移除禁用标志，JanusRunner 立即启动 Janus
        try:
            pathlib.Path("/tmp/kvmd_janus_disable").unlink(missing_ok=True)
            logger.info("Removed /tmp/kvmd_janus_disable, JanusRunner may resume")
        except Exception as ex:
            logger.warning("Failed to remove /tmp/kvmd_janus_disable: %s", ex)

    async def __webrtc_client_log_pipe(self, stream: asyncio.StreamReader, log_file: "Any") -> None:
        """读取 webrtc_client stdout/stderr，通过线程池异步写入文件并转发给 syslog（供 logread 查看）"""
        import syslog as _syslog
        _syslog.openlog("webrtc_client", _syslog.LOG_PID | _syslog.LOG_NDELAY, _syslog.LOG_USER)
        loop = asyncio.get_running_loop()
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode(errors="replace").rstrip()
                # write/flush/syslog 均为同步阻塞调用，放入线程池避免阻塞事件循环
                def _write_and_log(t: str = text) -> None:
                    log_file.write(t + "\n")
                    log_file.flush()
                    _syslog.syslog(_syslog.LOG_INFO, t)
                await loop.run_in_executor(None, _write_and_log)
        finally:
            _syslog.closelog()

    async def __webrtc_client_watchdog(self) -> None:
        """webrtc_client 看门狗：当进程意外退出时自动重启"""
        logger = get_logger(0)
        log_path = "/var/log/kvmd.log"
        while True:
            log_file = None
            pipe_task = None
            try:
                logger.info("Starting webrtc_client: %s (log: %s)", self.__webrtc_client_cmd, log_path)
                # open() 仅分配文件描述符，无磁盘 I/O，同步调用即可。
                # 不可用 run_in_executor：若 Task 在线程完成后被取消，文件句柄
                # 无法赋值给 log_file，将永久孤立造成资源泄漏。
                log_file = open(log_path, "a")  # pylint: disable=consider-using-with
                self.__webrtc_client_proc = await asyncio.create_subprocess_exec(
                    *self.__webrtc_client_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    preexec_fn=os.setpgrp,
                )
                assert self.__webrtc_client_proc.stdout is not None
                pipe_task = asyncio.ensure_future(
                    self.__webrtc_client_log_pipe(self.__webrtc_client_proc.stdout, log_file)
                )
                exit_code = await self.__webrtc_client_proc.wait()
                await pipe_task
                pipe_task = None
                self.__webrtc_client_proc = None
                log_file.close()
                log_file = None
                logger.warning("webrtc_client exited (code=%d), restarting in 2s ...", exit_code)
            except asyncio.CancelledError:
                # 看门狗被取消：先 kill 进程，再清理 pipe_task
                # log_file 由 finally 统一关闭，此处无需重复处理
                if self.__webrtc_client_proc:
                    # 给 2.0s 让进程正常退出并释放 IOMMU/DMA 资源
                    await aioproc.kill_process(self.__webrtc_client_proc, 2.0, logger)
                    self.__webrtc_client_proc = None
                if pipe_task and not pipe_task.done():
                    pipe_task.cancel()
                    await asyncio.gather(pipe_task, return_exceptions=True)
                raise
            except Exception:
                logger.exception("webrtc_client watchdog error")
                self.__webrtc_client_proc = None
                if pipe_task and not pipe_task.done():
                    pipe_task.cancel()
                    await asyncio.gather(pipe_task, return_exceptions=True)
            finally:
                # 无论正常退出、CancelledError 还是其他异常，都确保 log_file 被关闭。
                # finally 仅做同步操作，避免在异步取消期间引入新的 await 点。
                if log_file:
                    log_file.close()
                    log_file = None
            await asyncio.sleep(2)

    # ===== STREAMER CONTROLLER

    @exposed_http("POST", "/streamer/set_params")
    async def __streamer_set_params_handler(self, req: Request) -> Response:
        current_params = self.__streamer.get_params()
        # gl_webrtc 不是 streamer 内部参数，单独处理
        gl_webrtc_raw = req.query.get("gl_webrtc")
        if gl_webrtc_raw:
            self.__new_streamer_params["gl_webrtc"] = valid_bool(gl_webrtc_raw)
        for (name, validator, exc_cls) in [
            ("quality",      valid_stream_quality,      StreamerQualityNotSupported),
            ("desired_fps",  valid_stream_fps,          None),
            ("resolution",   valid_stream_resolution,   StreamerResolutionNotSupported),
            ("video_format", valid_stream_video_format, None),
            ("h264_bitrate", valid_stream_h264_bitrate, StreamerH264NotSupported),
            ("h264_gop",     valid_stream_h264_gop,     StreamerH264NotSupported),
            ("zero_delay",   valid_stream_zero_delay,   None),
            ("venc_mode",    valid_stream_venc_mode,    None),
        ]:
            value = req.query.get(name)
            if value:
                if name not in current_params:
                    assert exc_cls is not None, name
                    raise exc_cls()
                value = validator(value)  # type: ignore
                if current_params[name] != value:
                    self.__new_streamer_params[name] = value
        self.__streamer_notifier.notify()
        return make_json_response()

    @exposed_http("POST", "/streamer/reset")
    async def __streamer_reset_handler(self, _: Request) -> Response:
        self.__reset_streamer = True
        self.__streamer_notifier.notify()
        return make_json_response()

    # ===== WEBSOCKET

    @exposed_http("GET", "/ws")
    async def __ws_handler(self, req: Request) -> WebSocketResponse:
        stream = valid_bool(req.query.get("stream", True))
        # 从请求头中获取客户端真实 IP
        client_ip = req.headers.get("X-Real-IP") or \
                    (req.headers.get("X-Forwarded-For", "").split(",")[0].strip()) or \
                    "unknown"
        # 获取客户端浏览器信息
        user_agent = req.headers.get("User-Agent", "unknown")
        # 在连接建立时就解析 user_agent，保存 device_type 和 browser
        device_type, browser = parse_user_agent(user_agent)
        # 提取 auth_token 以便后续断开连接时可以删除
        auth_token = req.query.get("auth_token") or \
                     req.headers.get("Token") or \
                     req.cookies.get("auth_token", "")
        async with self._ws_session(req, stream=stream, client_ip=client_ip, user_agent=user_agent, device_type=device_type, browser=browser, auth_token=auth_token) as ws:
            (major, minor) = __version__.split(".")
            await ws.send_event("loop", {
                "version": {
                    "major": int(major),
                    "minor": int(minor),
                },
            })
            for sub in self.__subsystems:
                if sub.event_type:
                    assert sub.trigger_state
                    await sub.trigger_state()
            await self._broadcast_ws_event(self.__EV_HID_KEYMAPS_STATE, await self.__hid_api.get_keymaps())  # FIXME
            return (await self._ws_loop(ws))

    @exposed_ws("ping")
    async def __ws_ping_handler(self, ws: WsSession, _: dict) -> None:
        self.__refresh_token_from_ws(ws)
        await ws.send_event("pong", {})

    @exposed_ws(0)
    async def __ws_bin_ping_handler(self, ws: WsSession, _: bytes) -> None:
        self.__refresh_token_from_ws(ws)
        await ws.send_bin(255, b"")  # Ping-pong

    def __refresh_token_from_ws(self, ws: WsSession) -> None:
        """Refresh token expiry from WebSocket session (sliding expiration)"""
        auth_token = ws.kwargs.get("auth_token", "")
        if auth_token and self.__auth_manager.is_auth_enabled():
            self.__auth_manager.refresh_token_expiry(auth_token)

    # ===== SYSTEM STUFF

    def run(self, **kwargs: Any) -> None:  # type: ignore  # pylint: disable=arguments-differ
        for sub in self.__subsystems:
            if sub.sysprep:
                sub.sysprep()
        aioproc.rename_process("main")
        super().run(**kwargs)

    async def _check_request_auth(self, exposed: HttpExposed, req: Request) -> None:
        await check_request_auth(self.__auth_manager, exposed, req)

    async def _init_app(self) -> None:
        aiotools.create_deadly_task("Stream controller", self.__stream_controller())
        for sub in self.__subsystems:
            if sub.systask:
                # add log
                get_logger(0).info(f"Starting system task: {sub.name}")
                aiotools.create_deadly_task(sub.name, sub.systask())
            if sub.event_type:
                assert sub.poll_state
                aiotools.create_deadly_task(f"{sub.name} [poller]", self.__poll_state(sub.event_type, sub.poll_state()))
        aiotools.create_deadly_task("Stream snapshoter", self.__stream_snapshoter())
        self._add_exposed(*self.__apis)

    async def _on_shutdown(self) -> None:
        logger = get_logger(0)
        logger.info("Waiting short tasks ...")
        await aiotools.wait_all_short_tasks()
        logger.info("Stopping system tasks ...")
        await aiotools.stop_all_deadly_tasks()
        logger.info("Disconnecting clients ...")
        await self._close_all_wss()
        logger.info("On-Shutdown complete")

    async def _on_cleanup(self) -> None:
        logger = get_logger(0)
        # 如果处于自适应模式，退出时清理 webrtc_client
        if self.__adaptive_mode:
            await self.__exit_adaptive_mode()
        for sub in self.__subsystems:
            if sub.cleanup:
                logger.info("Cleaning up %s ...", sub.name)
                try:
                    await sub.cleanup()  # type: ignore
                except Exception:
                    logger.exception("Cleanup error on %s", sub.name)
        logger.info("On-Cleanup complete")

    async def _on_ws_opened(self, _: WsSession) -> None:
        # 清理所有键盘按键状态，确保新连接时按键都是抬起状态
        self.__hid.clear_events()
        self.__streamer_notifier.notify()
        # 异步发送 SIGUSR1 信号给 gl_kvm_gui 进程
        aiotools.create_short_task(asyncio.create_subprocess_shell("killall -SIGUSR1 gl_kvm_gui"))

    async def _on_ws_closed(self, _: WsSession) -> None:
        # 这里清理会受到rtty不会正确释放tcp连接的影响,导致会隔好几秒才进行收尾
        # 所以我们在open的时候清理一遍
        self.__hid.clear_events()
        self.__streamer_notifier.notify()
        # 异步发送 SIGUSR1 信号给 gl_kvm_gui 进程
        aiotools.create_short_task(asyncio.create_subprocess_shell("killall -SIGUSR1 gl_kvm_gui"))

    def __has_stream_clients(self) -> bool:
        return bool(sum(map(
            (lambda ws: ws.kwargs["stream"]),
            self._get_wss(),
        )))

    # ===== SYSTEM TASKS

    async def __stream_controller(self) -> None:
        prev_internal = False
        while True:
            # 自适应模式下不启动 ustreamer，让 webrtc_client 处理视频流
            internal_need = (
                (self.__has_stream_clients() or self.__snapshoter.snapshoting() or self.__stream_forever)
                and not self.__adaptive_mode
            )

            # 优先处理参数变化：确保在启动/重启 streamer 之前参数已经更新
            # 这样可以避免"先以旧参数启动、再重启为新参数"的双启动问题
            if self.__new_streamer_params or self.__reset_streamer:
                # 提取并移除 gl_webrtc（非 streamer 内部参数），用于控制自适应模式切换
                new_gl_webrtc = self.__new_streamer_params.pop("gl_webrtc", None)
                if new_gl_webrtc is True and not self.__adaptive_mode:
                    # gl_webrtc=True：进入自适应模式，杀掉 janus+ustreamer，启动 webrtc_client
                    self.__streamer.set_params(self.__new_streamer_params)
                    self.__new_streamer_params = {}
                    self.__reset_streamer = False
                    prev_internal = False  # 重置，以便 adaptive_mode 生效后重新计算
                    await self.__enter_adaptive_mode()
                    await self.__streamer_notifier.wait()
                    continue
                elif new_gl_webrtc is False and self.__adaptive_mode:
                    # gl_webrtc=False：退出自适应模式，恢复正常流
                    await self.__exit_adaptive_mode()
                    prev_internal = False  # 重置，以便退出 adaptive_mode 后重新计算
                    # 强制走完整重启路径（streamer 已被 exit_adaptive_mode 停止）
                    self.__reset_streamer = True
                elif self.__adaptive_mode:
                    # 处于自适应模式时，忽略其他参数变更（not gl_webrtc），不重启 ustreamer
                    # 但仍保存参数更新，以便退出自适应模式后生效
                    if self.__new_streamer_params:
                        self.__streamer.set_params(self.__new_streamer_params)
                        self.__new_streamer_params = {}
                    self.__reset_streamer = False
                    await self.__streamer_notifier.wait()
                    continue

                # 检查是否包含h264_bitrate参数变化
                has_bitrate_change = "h264_bitrate" in self.__new_streamer_params
                only_bitrate_change = (
                    len(self.__new_streamer_params) == 1 and
                    "h264_bitrate" in self.__new_streamer_params and
                    not self.__reset_streamer
                )

                # 如果包含bitrate变化，先写入文件
                if has_bitrate_change:
                    bitrate_value = self.__new_streamer_params["h264_bitrate"]
                    try:
                        with open("/tmp/bitrate", "w") as f:
                            f.write(str(bitrate_value * 1000))
                        get_logger(0).info("Updated H264 bitrate to %d", bitrate_value)
                    except Exception as e:
                        get_logger(0).error("Failed to write bitrate to /tmp/bitrate: %s", e)

                if only_bitrate_change:
                    # 只有码率变化时，不重启 streamer，仅更新参数状态
                    self.__streamer.set_params(self.__new_streamer_params)
                    self.__new_streamer_params = {}
                    get_logger(0).info("Updated H264 bitrate without restarting streamer")
                else:
                    # 其他参数变化（如 venc_mode、h264_gop 等）或需要重置时：
                    # 先决定是否需要重启，再 stop → set_params → start
                    # 需重启的条件：streamer 当前正在被需要（running）或当前 internal_need=True
                    should_restart = self.__streamer.is_required() or internal_need
                    await self.__streamer.ensure_stop(immediately=True, force=True)
                    if self.__new_streamer_params:
                        self.__streamer.set_params(self.__new_streamer_params)
                        self.__new_streamer_params = {}
                    if should_restart:
                        await self.__streamer.ensure_start(reset=self.__reset_streamer)
                        # 已经按 internal_need 启动，同步 prev_internal 避免下面重复启动
                        prev_internal = internal_need

                self.__reset_streamer = False

            # 再处理 internal_need 变化（此时 streamer 参数已经是最新的）
            if internal_need != prev_internal:
                if internal_need:
                    await self.__streamer.set_internal_stream_required(True)
                else:
                    await self.__streamer.set_internal_stream_required(False, stop_immediately=False)
                prev_internal = internal_need

            if self.__reset_streamer or self.__new_streamer_params:
                # 检查是否包含h264_bitrate参数变化
                has_bitrate_change = "h264_bitrate" in self.__new_streamer_params
                only_bitrate_change = (
                    len(self.__new_streamer_params) == 1 and 
                    "h264_bitrate" in self.__new_streamer_params and
                    not self.__reset_streamer
                )
                
                # 如果包含bitrate变化，先写入文件
                if has_bitrate_change:
                    bitrate_value = self.__new_streamer_params["h264_bitrate"]
                    try:
                        with open("/tmp/bitrate", "w") as f:
                            f.write(str(bitrate_value*1000))
                        get_logger(0).info("Updated H264 bitrate to %d", bitrate_value)
                    except Exception as e:
                        get_logger(0).error("Failed to write bitrate to /tmp/bitrate: %s", e)
                
                if only_bitrate_change:
                    # 只有码率变化时，不重启streamer
                    try:
                        # 更新内部参数状态
                        self.__streamer.set_params(self.__new_streamer_params)
                        self.__new_streamer_params = {}
                        get_logger(0).info("Updated H264 bitrate without restarting streamer")
                    except Exception as e:
                        get_logger(0).error("Failed to update streamer params: %s", e)
                        # 如果更新失败，回退到重启streamer的方式
                        need_after = self.__streamer.is_required()
                        await self.__streamer.ensure_stop(immediately=True, force=True)
                        self.__streamer.set_params(self.__new_streamer_params)
                        self.__new_streamer_params = {}
                        if need_after:
                            await self.__streamer.ensure_start(reset=self.__reset_streamer)
                else:
                    # 其他参数变化或需要重置时，重启streamer
                    need_after = self.__streamer.is_required()
                    await self.__streamer.ensure_stop(immediately=True, force=True)
                    if self.__new_streamer_params:
                        self.__streamer.set_params(self.__new_streamer_params)
                        self.__new_streamer_params = {}
                    if need_after:
                        await self.__streamer.ensure_start(reset=self.__reset_streamer)

                self.__reset_streamer = False

            await self.__streamer_notifier.wait()

    async def __stream_snapshoter(self) -> None:
        await self.__snapshoter.run(
            is_live=self.__has_stream_clients,
            notifier=self.__streamer_notifier,
        )

    async def __poll_state(self, event_type: str, poller: AsyncGenerator[dict, None]) -> None:
        async for state in poller:
            await self._broadcast_ws_event(event_type, state)
