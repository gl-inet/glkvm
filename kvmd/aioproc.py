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


import os
import signal
import asyncio
import asyncio.subprocess
import logging

import setproctitle

from .logging import get_logger


# =====
async def run_process(
    cmd: list[str],
    err_to_null: bool=False,
    env: (dict[str, str] | None)=None,
) -> asyncio.subprocess.Process:  # pylint: disable=no-member

    return (await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=(asyncio.subprocess.DEVNULL if err_to_null else asyncio.subprocess.STDOUT),
        preexec_fn=os.setpgrp,
        env=env,
    ))


async def read_process(
    cmd: list[str],
    err_to_null: bool=False,
    env: (dict[str, str] | None)=None,
) -> tuple[asyncio.subprocess.Process, str]:  # pylint: disable=no-member

    proc = await run_process(cmd, err_to_null, env)
    (stdout, _) = await proc.communicate()
    return (proc, stdout.decode(errors="ignore").strip())


async def log_process(
    cmd: list[str],
    logger: logging.Logger,
    env: (dict[str, str] | None)=None,
    prefix: str="",
) -> asyncio.subprocess.Process:  # pylint: disable=no-member

    (proc, stdout) = await read_process(cmd, env=env)
    if stdout:
        log = (logger.info if proc.returncode == 0 else logger.error)
        if prefix:
            prefix += " "
        for line in stdout.split("\n"):
            log("%s=> %s", prefix, line)
    return proc


async def log_stdout_infinite(proc: asyncio.subprocess.Process, logger: logging.Logger) -> None:  # pylint: disable=no-member
    empty = 0
    async for line_bytes in proc.stdout:  # type: ignore
        line = line_bytes.decode(errors="ignore").strip()
        if line:
            logger.info("=> %s", line)
            empty = 0
        else:
            empty += 1
            if empty == 100:  # asyncio bug
                raise RuntimeError("Asyncio process: too many empty lines")


async def kill_process(proc: asyncio.subprocess.Process, wait: float, logger: logging.Logger) -> None:  # pylint: disable=no-member
    if proc.returncode is None:
        try:

            logger.debug("Terminating process pid=%d", proc.pid)
            proc.terminate()


            try:
                await asyncio.wait_for(proc.wait(), wait)
                logger.info("Process terminated: retcode=%d", proc.returncode)
                return
            except asyncio.TimeoutError:
                logger.warning("Process termination timed out after %.1f seconds, sending SIGKILL", wait)


            if proc.returncode is None:
                try:
                    logger.debug("Killing process group pgid=%d", os.getpgid(proc.pid))
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


                    try:
                        await asyncio.wait_for(proc.wait(), wait)
                    except asyncio.TimeoutError:
                        logger.error("Process still alive after SIGKILL and %.1f seconds wait, giving up", wait)
                        return
                except ProcessLookupError:

                    pass
                except Exception as e:
                    logger.exception("Error sending SIGKILL to process group: %s", str(e))

                    if proc.returncode is None:
                        try:
                            os.kill(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        except Exception:
                            logger.exception("Can't kill process pid=%d directly", proc.pid)


            if proc.returncode is not None:
                logger.info("Process killed: retcode=%d", proc.returncode)
            else:

                try:
                    await asyncio.wait_for(proc.wait(), wait)
                    logger.info("Process killed: retcode=%d", proc.returncode)
                except asyncio.TimeoutError:
                    logger.error("Failed to kill process pid=%d after multiple attempts", proc.pid)
        except asyncio.CancelledError:

            pass
        except Exception:
            logger.exception("Unexpected error while killing process pid=%d", proc.pid)


def rename_process(suffix: str, prefix: str="kvmd") -> None:
    setproctitle.setproctitle(f"{prefix}/{suffix}: {setproctitle.getproctitle()}")


def settle(name: str, suffix: str, prefix: str="kvmd") -> logging.Logger:
    logger = get_logger(1)
    logger.info("Started %s pid=%d", name, os.getpid())
    os.setpgrp()
    rename_process(suffix, prefix)
    return logger
