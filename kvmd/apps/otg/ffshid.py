# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
# ========================================================================== #


import os
import sys
import json
import signal
import logging
import logging.handlers
import subprocess
import time

from ...logging import get_logger

from .hid import Hid
from .hid.ffs import make_descriptors
from .hid.ffs import make_strings
from .hid.ffs import serve


# =====
MOUSE_FUNCTION = "ffs.mouse"  # FunctionFS instance name is "mouse"

_DAEMON_MODULE = "kvmd.apps.otg.ffshid"
_STOP_TIMEOUT = 3.0


# =====
def prepare(mount: str, hids: list[Hid], names: list[str], timeout: float) -> None:
    """
    Mount FunctionFS for the given function and start the ep0 daemon
    that keeps the function alive. Called by kvmd-otg before binding the UDC.
    Idempotent: a running daemon is reused.
    """

    instance = MOUSE_FUNCTION.split(".", 1)[1]
    os.makedirs(mount, exist_ok=True)
    if not _is_mounted(mount):
        subprocess.run(["mount", "-t", "functionfs", instance, mount], check=True)
    try:
        proc: (subprocess.Popen | None) = None
        if _get_daemon_pid(mount) is None:
            spec = {
                "mount": mount,
                "interfaces": [
                    {
                        "name": name,
                        "protocol": hid.protocol,
                        "subclass": hid.subclass,
                        "report_length": hid.report_length,
                        "report_descriptor": hid.report_descriptor.hex(),
                    }
                    for (name, hid) in zip(names, hids)
                ],
            }
            proc = subprocess.Popen(  # pylint: disable=consider-using-with
                [sys.executable, "-m", _DAEMON_MODULE],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
            assert proc.stdin is not None
            proc.stdin.write(json.dumps(spec).encode())
            proc.stdin.close()
            with open(_get_pidfile_path(mount), "w") as file:
                file.write(str(proc.pid))
        deadline = time.monotonic() + timeout
        while not os.path.exists(os.path.join(mount, "ep1")):
            if proc is not None and proc.poll() is not None:
                raise RuntimeError(f"FunctionFS HID daemon exited with code {proc.returncode}")
            if time.monotonic() >= deadline:
                raise RuntimeError("FunctionFS HID daemon did not create the endpoints")
            time.sleep(0.05)
    except Exception:
        cleanup(mount)
        raise


def cleanup(mount: str) -> None:
    """
    Stop the daemon and unmount FunctionFS. Only call this after the gadget
    is unbound from the UDC: closing ep0 of a bound function tears down the whole gadget.
    """

    pid = _get_daemon_pid(mount)
    if pid is not None:
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + _STOP_TIMEOUT
        while _get_daemon_pid(mount) is not None:
            if time.monotonic() >= deadline:
                raise RuntimeError("FunctionFS HID daemon did not stop")
            time.sleep(0.05)
    try:
        os.unlink(_get_pidfile_path(mount))
    except FileNotFoundError:
        pass
    if _is_mounted(mount):
        subprocess.run(["umount", mount], check=True)


def _get_pidfile_path(mount: str) -> str:
    return (mount.rstrip("/") + ".pid")


def _get_daemon_pid(mount: str) -> (int | None):
    try:
        with open(_get_pidfile_path(mount)) as file:
            pid = int(file.read().strip())
        with open(f"/proc/{pid}/cmdline", "rb") as file:
            args = file.read().split(b"\0")
    except (FileNotFoundError, ProcessLookupError, ValueError):
        return None
    if _DAEMON_MODULE.encode() not in args:
        return None  # PID was reused by another process
    return pid


def _is_mounted(mount: str) -> bool:
    with open("/proc/mounts") as file:
        return any(line.split()[1] == mount for line in file if len(line.split()) >= 2)


# =====
def main() -> None:
    """
    The ep0 daemon. It reads the interfaces spec from stdin (see prepare()),
    writes the FunctionFS descriptors and then answers HID control requests
    until it receives SIGTERM.

    It deliberately never exits on errors while running: closing ep0 unbinds
    the entire USB gadget, including the keyboard, which is worse than a
    temporarily unresponsive control endpoint.
    """

    spec = json.load(sys.stdin)
    sys.stdin.close()
    hids = [
        Hid(
            protocol=int(iface["protocol"]),
            subclass=int(iface["subclass"]),
            report_length=int(iface["report_length"]),
            report_descriptor=bytes.fromhex(iface["report_descriptor"]),
        )
        for iface in spec["interfaces"]
    ]
    names = [str(iface["name"]) for iface in spec["interfaces"]]

    _setup_logging()
    logger = get_logger(0)

    stop = False

    def on_signal(signum: int, _: object) -> None:
        nonlocal stop
        logger.info("Got signal %d, stopping", signum)
        stop = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    fd = os.open(os.path.join(spec["mount"], "ep0"), os.O_RDWR)
    try:
        for blob in [make_descriptors(hids), make_strings(names)]:
            if os.write(fd, blob) != len(blob):
                raise RuntimeError("Short FunctionFS ep0 write")
        logger.info("Serving %d FunctionFS HID interface(s): %s", len(hids), ", ".join(names))
        while not stop:
            try:
                serve(fd, hids, (lambda: stop))
            except Exception:
                logger.exception("Unexpected FunctionFS ep0 error")
                time.sleep(1)
    finally:
        os.close(fd)
    logger.info("Bye-bye")


def _setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if os.path.exists("/dev/log"):
        handler: logging.Handler = logging.handlers.SysLogHandler(address="/dev/log")
        handler.setFormatter(logging.Formatter("kvmd-otg-ffshid: %(message)s"))
    else:
        handler = logging.StreamHandler(sys.stderr)
    root.addHandler(handler)


if __name__ == "__main__":
    main()
