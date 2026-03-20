# sysfs_chain.py
# ==========================================================================

from typing import AsyncGenerator

from .device import DeviceError
from .sysfs_device import Device


# ===== 事件（保持名字，简化实现） =====
class BaseEvent:
    pass


class DeviceFoundEvent(BaseEvent):
    pass


class PortActivatedEvent(BaseEvent):
    def __init__(self, port: int) -> None:
        self.port = port


# =====
class Chain:
    """
    Sysfs-based Chain implementation.

    Keeps Chain public interface but maps everything
    to SysfsDevice.
    """

    CHANNEL_COUNT = 4

    def __init__(self, ignore_hpd_on_top: bool = False) -> None:
        self.__device = Device()
        self.__active_port = -1
        self.__ignore_hpd_on_top = ignore_hpd_on_top

    # ------------------------------------------------------------------
    # 基础接口（与原 Chain 保持）
    # ------------------------------------------------------------------

    def set_actual(self, actual: bool) -> None:
        # sysfs 不支持 actual 概念，忽略
        pass

    # ------------------------------------------------------------------

    def translate_port(self, port: float) -> int:
        if int(port) == port:
            return int(port)
        (unit, ch) = map(int, str(port).split("."))
        unit = max(unit - 1, 0)
        ch = max(ch - 1, 0)
        return unit * 4 + ch

    # ------------------------------------------------------------------
    # Active port control
    # ------------------------------------------------------------------

    def set_active_prev(self) -> None:
        if self.__active_port > 0:
            self.set_active_port(self.__active_port - 1)

    def set_active_next(self) -> None:
        if self.__active_port < self.CHANNEL_COUNT - 1:
            self.set_active_port(self.__active_port + 1)

    def set_active_port(self, port: int) -> None:
        if not (0 <= port < self.CHANNEL_COUNT):
            return
        self.__device.request_switch(0, port)
        self.__active_port = port

    def get_current_channel(self) -> int:
        return self.__device.get_current_channel()

    def get_channel_count(self) -> int:
        return self.CHANNEL_COUNT
    # ------------------------------------------------------------------
    # video.links 和 usb.links 接口
    # ------------------------------------------------------------------
    def get_video_links(self) -> list[bool]:
        status = self.__device.get_hdmi_status()
        return [status.get(ch, False) for ch in range(self.CHANNEL_COUNT)]

    def get_usb_otg_links(self) -> list[bool]:
        status = self.__device.get_usb_otg_status()
        return [status.get(ch, False) for ch in range(self.CHANNEL_COUNT)]

    def get_usb_host_link(self) -> bool:
        return self.__device.get_usb_host_connected()

    # ------------------------------------------------------------------
    # Beacon / EDID / ATX（sysfs 不支持，保留接口）
    # ------------------------------------------------------------------

    def set_port_beacon(self, port: int, on: bool) -> None:
        pass

    def set_uplink_beacon(self, unit: int, on: bool) -> None:
        pass

    def set_downlink_beacon(self, unit: int, on: bool) -> None:
        pass

    def set_edids(self, edids) -> None:
        pass

    def set_dummies(self, dummies) -> None:
        pass

    def set_colors(self, colors) -> None:
        pass

    def click_power(self, port: int, delay: float, if_powered) -> None:
        pass

    def click_reset(self, port: int, delay: float, if_powered) -> None:
        pass

    def reboot_unit(self, unit: int, bootloader: bool) -> None:
        raise DeviceError("Reboot not supported via sysfs")

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    async def poll_events(self) -> AsyncGenerator[BaseEvent, None]:
        """
        Sysfs does not generate async events.
        Yield DeviceFoundEvent once if device exists.
        """
        if self.__device.has_device():
            yield DeviceFoundEvent()

        while True:
            await self._sleep()

    async def _sleep(self) -> None:
        import asyncio
        await asyncio.sleep(1)

    # ------------------------------------------------------------------
    # 工具函数
    # ------------------------------------------------------------------

    @classmethod
    def get_real_unit_channel(cls, port: int) -> tuple[int, int]:
        return (0, port)

    @classmethod
    def get_unit_target_channel(cls, unit: int, port: int) -> int:
        return port

    @classmethod
    def get_virtual_port(cls, unit: int, ch: int) -> int:
        return ch
