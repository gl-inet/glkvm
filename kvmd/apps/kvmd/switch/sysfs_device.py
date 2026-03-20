# ==========================================================================
#
#   Sysfs-based Device implementation for KVMD
#   Replace serial-based Device with Linux sysfs control
#
# ==========================================================================

from pathlib import Path
from typing import Dict, List
import asyncio
import subprocess
# =====
class DeviceError(Exception):
    pass


class Device:
    """
    Sysfs-backed replacement for kvmd.device.Device

    This class exposes a Device-like interface but operates purely
    via Linux sysfs files instead of serial protocol.
    """
    __channel_count = 4

    # ===== 固定 sysfs 路径 =====
    CHANNEL_FILE = Path("/sys/bus/i2c/devices/3-0058/channel")
    HDMI_STATUS_FILE = Path("/sys/bus/i2c/devices/3-0058/hdmi_status")
    USB_STATUS_FILE = Path("/sys/bus/i2c/devices/3-0058/usb_otg_status")

    # ===== 配置持久化 =====
    CONF_DIR = Path("/etc/kvmd")
    CONF_FILE = CONF_DIR / "channel.conf"

    def __init__(self, device: str | None = None) -> None:
        self.__active_port = -1
        self._device = device
        #init 阶段：只读配置，不动硬件
        self.__saved_channel: int | None = self.__load_channel()

        #像 upgrade.py 一样：丢给 event loop 一个延后任务
        if self.__saved_channel is not None:
            try:
                asyncio.get_event_loop().create_task(
                    self.__delayed_restore_channel()
                )
            except RuntimeError:
                pass

    # ------------------------------------------------------------------
    # 生命周期（保持与 Device 兼容）
    # ------------------------------------------------------------------
    def __enter__(self) -> "SysfsDevice":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    # ------------------------------------------------------------------
    # 基础能力
    # ------------------------------------------------------------------
    def has_device(self) -> bool:
        """
        Check whether sysfs device exists.
        """
        return self.CHANNEL_FILE.exists()

    def get_fd(self) -> int:
        """
        Serial Device exposes fd; sysfs does not.
        Keep for interface compatibility.
        """
        raise DeviceError("SysfsDevice has no file descriptor")

    # ------------------------------------------------------------------
    # sysfs helpers
    # ------------------------------------------------------------------
    def _read_file(self, path: Path) -> str:
        try:
            return path.read_text().strip()
        except Exception as ex:
            raise DeviceError(ex)

    def _write_file(self, path: Path, value: str) -> None:
        try:
            path.write_text(value)
        except Exception as ex:
            raise DeviceError(ex)
    
    # ------------------------------------------------------------------
    # ===== Channel persistence helpers =====
    # ------------------------------------------------------------------
    async def __delayed_restore_channel(self) -> None:
        ch = self.__saved_channel
        self.__saved_channel = None

        if ch is None:
            return

        try:
            await asyncio.sleep(0)
            self._write_file(self.CHANNEL_FILE, str(ch))
            print(f"[sysfs-device] restored channel {ch}")
        except Exception as e:
            print(f"[sysfs-device] restore channel failed: {e}")
        
    def __load_channel(self) -> int | None:
        try:
            if self.CONF_FILE.exists():
                return int(self.CONF_FILE.read_text().strip())
        except Exception as e:
            print(f"[sysfs-device] load channel failed: {e}")
        return None

    def __save_channel(self, ch: int) -> None:
        try:
            self.CONF_DIR.mkdir(parents=True, exist_ok=True)
            self.CONF_FILE.write_text(str(ch))
        except Exception as e:
            print(f"[sysfs-device] save channel failed: {e}")

    # ------------------------------------------------------------------
    # Channel
    # ------------------------------------------------------------------
    def get_current_channel(self) -> int:
        """
        Parse:
            'Current Channel : 0'
        """
        text = self._read_file(self.CHANNEL_FILE)
        try:
            return int(text.split(":")[-1].strip())
        except Exception:
            raise DeviceError(f"Invalid channel format: {text}")

    def set_channel(self, ch: int) -> None:
        ch = int(ch)
        if not 0 <= ch <= 3:
            raise ValueError(f"invalid channel: {ch}")
        self.CHANNEL_FILE.write_text(str(ch))
        self.__save_channel(int(ch))

    # ------------------------------------------------------------------
    # HDMI status
    # ------------------------------------------------------------------
    def get_hdmi_status(self) -> Dict[int, bool]:
        """
        Return example:
        {
            0: True,
            1: False,
            2: False,
            3: True,
        }
        """
        raw = self._read_file(self.HDMI_STATUS_FILE).splitlines()
        status: Dict[int, bool] = {}

        for idx, line in enumerate(raw):
            status[idx] = "Connected" in line

        return status

    # ------------------------------------------------------------------
    # USB OTG status
    # ------------------------------------------------------------------
    def get_usb_otg_status(self) -> Dict[int, bool]:
        """
        Return example:
        {
            0: True,
            1: False,
            2: False,
            3: True,
        }
        """
        raw = self._read_file(self.USB_STATUS_FILE).splitlines()
        status: Dict[int, bool] = {}

        for idx, line in enumerate(raw):
            status[idx] = "Connected" in line
        return status

    def get_usb_host_connected(self) -> bool:
        """
        Detect external USB-A device by:
            lsusb | wc -l

        Baseline:
            3 -> no device
            4+ -> device connected
        """
        try:
            result = subprocess.run(
                ["lsusb"],
                capture_output=True,
                text=True,
                timeout=1,
            )

            if result.returncode != 0:
                return False

            line_count = len(result.stdout.strip().splitlines())

            return line_count > 3

        except Exception:
            return False


    def request_state(self) -> dict:  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
        state: dict = {}
        
        # if x_summary:
        self.__active_port = self.get_current_channel()
        state["summary"] = {
        "active_port": self.__active_port,
        "active_id": f"1.{self.__active_port + 1}",
        "synced": True,
        }
        
        # if x_usb:
        usb_status = self.get_usb_status()
        state["usb"] = {"links": [usb_status.get(ch, False) for ch in range(self.__channel_count)]}
        # if x_video:
        hdmi_status = self.get_hdmi_status()
        state["video"] = {"links": [hdmi_status.get(ch, False) for ch in range(self.__channel_count)]}
        print(f"{state}")
        return state


    # ------------------------------------------------------------------
    # ===== Device-like request APIs =====
    # ------------------------------------------------------------------
    def request_switch(self, unit: int, ch: int) -> int:
        """
        unit is ignored (single device).
        """
        self.set_channel(ch)
        return 0  # rid placeholder

    # ------------------------------------------------------------------
    # ===== Unsupported / Stub APIs (for compatibility) =====
    # ------------------------------------------------------------------
    def request_reboot(self, unit: int, bootloader: bool) -> int:
        raise DeviceError("Reboot not supported via sysfs")

    def request_beacon(self, unit: int, ch: int, on: bool) -> int:
        return 0

    def request_atx_leds(self) -> int:
        return 0

    def request_atx_cp(self, unit: int, ch: int, delay_ms: int) -> int:
        return 0

    def request_atx_cr(self, unit: int, ch: int, delay_ms: int) -> int:
        return 0

    def request_set_edid(self, unit: int, ch: int, edid) -> int:
        return 0

    def request_set_dummy(self, unit: int, ch: int, on: bool) -> int:
        return 0

    def request_set_colors(self, unit: int, ch: int, colors) -> int:
        return 0

    def request_set_quirks(self, unit: int, ignore_hpd: bool) -> int:
        return 0

    def read_all(self):
        return []