import asyncio
import asyncio.subprocess
import socket
import dataclasses

import netifaces

from ... import tools
from ... import aiotools
from ... import aioproc

from ...logging import get_logger

from .stun import StunNatType
from .stun import Stun


# =====
@dataclasses.dataclass(frozen=True)
class _Netcfg:
    nat_type:  StunNatType = dataclasses.field(default=StunNatType.ERROR)
    src_ip:    str = dataclasses.field(default="")
    ext_ip:    str = dataclasses.field(default="")
    stun_ip:   str = dataclasses.field(default="")
    stun_port: int = dataclasses.field(default=0)


# =====
class JanusRunner:  # pylint: disable=too-many-instance-attributes
    def __init__(  # pylint: disable=too-many-arguments
        self,
        stun_host: str,
        stun_port: int,
        stun_timeout: float,
        stun_retries: int,
        stun_retries_delay: float,

        check_interval: int,
        check_retries: int,
        check_retries_delay: float,

        cmd: list[str],
        cmd_remove: list[str],
        cmd_append: list[str],
    ) -> None:

        self.__stun = Stun(stun_host, stun_port, stun_timeout, stun_retries, stun_retries_delay)

        self.__check_interval = check_interval
        self.__check_retries = check_retries
        self.__check_retries_delay = check_retries_delay

        self.__cmd = tools.build_cmd(cmd, cmd_remove, cmd_append)

        self.__janus_task: (asyncio.Task | None) = None
        self.__janus_proc: (asyncio.subprocess.Process | None) = None  # pylint: disable=no-member

    def run(self) -> None:
        logger = get_logger(0)
        logger.info("Starting Janus Runner ...")
        aiotools.run(self.__run(), self.__stop_janus())
        logger.info("Bye-bye")

    # =====

    async def __run(self) -> None:
        netcfg_diff_times = 0
        logger = get_logger(0)
        logger.info("Probbing the network first time ...")

        prev_netcfg: (_Netcfg | None) = None
        while True:
            retry = 0
            netcfg = _Netcfg()
            for retry in range(1 if prev_netcfg is None else self.__check_retries):
                netcfg = await self.__get_netcfg()
                if netcfg.ext_ip:
                    break
                await asyncio.sleep(self.__check_retries_delay)
            if retry != 0 and netcfg.ext_ip:
                logger.info("I'm fine, continue working ...")

            if prev_netcfg is None:
                logger.info("Initializing Janus with %s ...", netcfg)
                if netcfg.src_ip:
                    await self.__stop_janus()
                    await self.__start_janus(netcfg)
                else:
                    logger.error("Empty src_ip; stopping Janus ...")
                    await self.__stop_janus()
                prev_netcfg = netcfg
            elif prev_netcfg != netcfg:
                if netcfg_diff_times <= 6:
                    netcfg_diff_times += 1
                    logger.info("Public IP address changed to %s, original %s, but it's not stable yet, waiting %d seconds ...", netcfg.ext_ip, prev_netcfg.ext_ip, self.__check_interval)
                    await asyncio.sleep(self.__check_interval)
                    continue
                netcfg_diff_times = 0
                prev_netcfg = netcfg
                logger.info("Got new %s", netcfg)
                if netcfg.src_ip:
                    await self.__stop_janus()
                    await self.__start_janus(netcfg)
                else:
                    logger.error("Empty src_ip; stopping Janus ...")
                    await self.__stop_janus()
            else:
                netcfg_diff_times = 0
            await asyncio.sleep(self.__check_interval)

    async def __get_netcfg(self) -> _Netcfg:
        src_ip = (self.__get_default_ip() or "0.0.0.0")
        info = await self.__stun.get_info(src_ip, 0)
        # В текущей реализации _Netcfg() это копия StunInfo()
        return _Netcfg(**dataclasses.asdict(info))

    def __get_default_ip(self) -> str:
        try:
            gws = netifaces.gateways()
            if "default" in gws:
                for proto in [socket.AF_INET, socket.AF_INET6]:
                    if proto in gws["default"]:
                        iface = gws["default"][proto][1]
                        addrs = netifaces.ifaddresses(iface)
                        return addrs[proto][0]["addr"]

            for iface in netifaces.interfaces():
                if not iface.startswith(("lo", "docker")):
                    addrs = netifaces.ifaddresses(iface)
                    for proto in [socket.AF_INET, socket.AF_INET6]:
                        if proto in addrs:
                            return addrs[proto][0]["addr"]
        except Exception as ex:
            get_logger().error("Can't get default IP: %s", tools.efmt(ex))
        return ""

    # =====

    @aiotools.atomic_fg
    async def __start_janus(self, netcfg: _Netcfg) -> None:
        get_logger(0).info("Starting Janus ...")
        assert not self.__janus_task
        self.__janus_task = asyncio.create_task(self.__janus_task_loop(netcfg))

    @aiotools.atomic_fg
    async def __stop_janus(self) -> None:
        if self.__janus_task:
            get_logger(0).info("Stopping Janus ...")
            self.__janus_task.cancel()
            await asyncio.gather(self.__janus_task, return_exceptions=True)
        await self.__kill_janus_proc()
        self.__janus_task = None

    # =====

    async def __janus_task_loop(self, netcfg: _Netcfg) -> None:  # pylint: disable=too-many-branches
        logger = get_logger(0)
        while True:  # pylint: disable=too-many-nested-blocks
            try:
                await self.__start_janus_proc(netcfg)
                assert self.__janus_proc is not None
                await aioproc.log_stdout_infinite(self.__janus_proc, logger)
                raise RuntimeError("Janus unexpectedly died")
            except asyncio.CancelledError:
                break
            except Exception:
                if self.__janus_proc:
                    logger.exception("Unexpected Janus error: pid=%d", self.__janus_proc.pid)
                else:
                    logger.exception("Can't start Janus")
                await self.__kill_janus_proc()
                await asyncio.sleep(1)

    async def __start_janus_proc(self, netcfg: _Netcfg) -> None:
        assert self.__janus_proc is None
        placeholders = {
            "o_stun_server": f"--stun-server={netcfg.stun_ip}:{netcfg.stun_port}",
            **{
                key: str(value)
                for (key, value) in dataclasses.asdict(netcfg).items()
            },
        }
        cmd = list(self.__cmd)
        if not netcfg.ext_ip:
            placeholders["o_stun_server"] = ""
            while "{o_stun_server}" in cmd:
                cmd.remove("{o_stun_server}")
        cmd = [
            part.format(**placeholders)
            for part in cmd
        ]
        self.__janus_proc = await aioproc.run_process(cmd)
        get_logger(0).info("Started Janus pid=%d: %s", self.__janus_proc.pid, tools.cmdfmt(cmd))

    async def __kill_janus_proc(self) -> None:
        if self.__janus_proc:
            await aioproc.kill_process(self.__janus_proc, 5, get_logger(0))
        self.__janus_proc = None
