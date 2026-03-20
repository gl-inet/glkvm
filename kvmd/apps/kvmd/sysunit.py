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


import types

import dbus_next
import dbus_next.aio
import dbus_next.aio.proxy_object
import dbus_next.introspection
import dbus_next.errors


# =====
class SystemdUnitInfo:
    def __init__(self) -> None:
        # D-Bus消息总线
        self.__bus: (dbus_next.aio.MessageBus | None) = None
        # D-Bus内省信息
        self.__intr: (dbus_next.introspection.Node | None) = None
        # systemd管理器接口
        self.__manager: (dbus_next.aio.proxy_object.ProxyInterface | None) = None
        # 是否已请求过单元信息
        self.__requested = False

    async def get_status(self, name: str) -> tuple[bool, bool]:
        # 确保D-Bus连接已建立
        assert self.__bus is not None
        assert self.__intr is not None
        assert self.__manager is not None

        # 确保服务名以.service结尾
        if not name.endswith(".service"):
            name += ".service"

        try:
            # 获取单元对象路径
            unit_p = await self.__manager.call_get_unit(name)  # type: ignore
            # 获取单元代理对象
            unit = self.__bus.get_proxy_object("org.freedesktop.systemd1", unit_p, self.__intr)
            # 获取属性接口
            unit_props = unit.get_interface("org.freedesktop.DBus.Properties")
            # 检查服务是否处于活动状态
            started = ((await unit_props.call_get("org.freedesktop.systemd1.Unit", "ActiveState")).value == "active")  # type: ignore
            self.__requested = True
        except dbus_next.errors.DBusError as ex:
            # 如果单元不存在，将started设为False
            if ex.type != "org.freedesktop.systemd1.NoSuchUnit":
                raise
            started = False
        
        # 检查服务是否已启用
        enabled = ((await self.__manager.call_get_unit_file_state(name)) in [  # type: ignore
            "enabled",
            "enabled-runtime",
            "static",
            "indirect",
            "generated",
        ])
        return (enabled, started)

    async def open(self) -> None:
        self.__bus = await dbus_next.aio.MessageBus(bus_type=dbus_next.BusType.SYSTEM).connect()
        self.__intr = await self.__bus.introspect("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
        systemd = self.__bus.get_proxy_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1", self.__intr)
        self.__manager = systemd.get_interface("org.freedesktop.systemd1.Manager")

    async def __aenter__(self) -> "SystemdUnitInfo":
        await self.open()
        return self

    async def close(self) -> None:
        try:
            if self.__bus is not None:
                try:
                    # XXX: Workaround for dbus_next bug: https://github.com/pikvm/kvmd/pull/182
                    if not self.__requested:
                        await self.__manager.call_get_default_target()  # type: ignore
                finally:
                    self.__bus.disconnect()
                    await self.__bus.wait_for_disconnect()
        except Exception:
            pass
        self.__manager = None
        self.__intr = None
        self.__bus = None

    async def __aexit__(
        self,
        _exc_type: type[BaseException],
        _exc: BaseException,
        _tb: types.TracebackType,
    ) -> None:

        await self.close()
