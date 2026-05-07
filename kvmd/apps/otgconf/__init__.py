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
import json
import contextlib
import dataclasses
import argparse
import time

from typing import Generator

import yaml

from ...validators.basic import valid_stripped_string_not_empty

from ... import usb

from .. import init


# =====
@dataclasses.dataclass(frozen=True)
class _Function:
    name:    str
    desc:    str
    eps:     int
    enabled: bool
    order:   int = 0  # configfs symlink 插入顺序，由 kvmd-otg start 写入 meta 文件


class _GadgetControl:
    def __init__(
        self,
        meta_path: str,
        gadget: str,
        udc: str,
        eps: int,
        init_delay: float,
    ) -> None:

        self.__meta_path = meta_path
        self.__gadget = gadget
        self.__udc = udc
        self.__eps = eps
        self.__init_delay = init_delay

    def __find_dwc3(self, udc: str) -> tuple[str, str]:
        # /sys/class/udc/<udc>/device 软链接可能直接指向平台设备，也可能指向其
        # 子设备（不同内核/平台层级不同）。从该路径逐级向上查找携带 driver
        # 软链接的设备目录，取第一个匹配项作为 dwc3 平台设备。
        path = os.path.realpath(usb.get_udc_path(udc, "device"))
        while path and path != "/":
            driver_link = os.path.join(path, "driver")
            if os.path.islink(driver_link):
                device_name = os.path.basename(path)
                driver_dir = os.path.realpath(driver_link)
                return (device_name, driver_dir)
            path = os.path.dirname(path)
        raise RuntimeError(f"Cannot find DWC3 driver for UDC {udc!r}")

    @contextlib.contextmanager
    def __udc_stopped(self) -> Generator[None, None, None]:
        udc = usb.find_udc(self.__udc)
        udc_path = usb.get_gadget_path(self.__gadget, usb.G_UDC)
        with open(udc_path) as file:
            enabled = bool(file.read().strip())

        dwc3_name: (str | None) = None
        driver_dir: (str | None) = None

        if enabled:
            # 在 unbind 之前获取 dwc3 信息（unbind 后 driver 软链接消失）
            (dwc3_name, driver_dir) = self.__find_dwc3(udc)
            # 先软断开 gadget
            with open(udc_path, "w") as file:
                file.write("\n")
            # 再 unbind dwc3 驱动，彻底复位控制器
            with open(os.path.join(driver_dir, "unbind"), "w") as file:
                file.write(dwc3_name)
            # 等待 UDC 从 sysfs 消失
            deadline = time.monotonic() + self.__init_delay
            while time.monotonic() < deadline:
                if not os.path.exists(usb.get_udc_path(udc)):
                    break
                time.sleep(0.05)
        try:
            yield
        finally:
            self.__clear_profile(recreate=True)
            # Only restart UDC if there is at least one function in the profile.
            # Writing UDC with an empty config causes kernel EINVAL (-22).
            has_functions = any(
                os.path.islink(self.__get_fdest_path(func))
                for func in os.listdir(self.__get_fdest_path())
            )
            if has_functions:
                time.sleep(0.1)
                if dwc3_name and driver_dir:
                    # bind dwc3 驱动，等待 UDC 重新出现
                    with open(os.path.join(driver_dir, "bind"), "w") as file:
                        file.write(dwc3_name)
                    deadline = time.monotonic() + self.__init_delay
                    while time.monotonic() < deadline:
                        if os.path.exists(usb.get_udc_path(udc)):
                            break
                        time.sleep(0.05)
                with open(udc_path, "w") as file:
                    file.write(udc)

    def __clear_profile(self, recreate: bool) -> None:
        # XXX: See pikvm/pikvm#1235
        # After unbind and bind, the gadgets stop working,
        # unless we recreate their links in the profile.
        # Some kind of kernel bug.
        #
        # configfs 按 symlink 插入顺序分配 USB 接口编号，因此重建时必须按照
        # meta 文件记录的 order 顺序逐一创建，而不能依赖 os.listdir() 的任意顺序。
        existing = {
            func for func in os.listdir(self.__get_fdest_path())
            if os.path.islink(self.__get_fdest_path(func))
        }
        # 第一步：删除所有现有 symlink
        for func in existing:
            try:
                os.unlink(self.__get_fdest_path(func))
            except (FileNotFoundError, FileExistsError):
                pass
        # 第二步：按 meta 顺序（即初始创建顺序）重建 symlink
        if recreate:
            for meta_func in self.__read_metas():
                if meta_func.name in existing:
                    try:
                        os.symlink(self.__get_fsrc_path(meta_func.name), self.__get_fdest_path(meta_func.name))
                    except (FileNotFoundError, FileExistsError):
                        pass

    def __read_metas(self) -> Generator[_Function, None, None]:
        funcs: list[_Function] = []
        for name in sorted(os.listdir(self.__meta_path)):
            with open(os.path.join(self.__meta_path, name)) as file:
                meta = json.loads(file.read())
                enabled = os.path.exists(self.__get_fdest_path(meta["function"]))
                funcs.append(_Function(
                    name=meta["function"],
                    desc=meta["description"],
                    eps=meta["endpoints"],
                    enabled=enabled,
                    order=meta.get("order", 0),  # 兼容旧版 meta（无 order 字段时默认 0）
                ))
        # 按 kvmd-otg start 写入的 order 排序，保证 symlink 插入顺序 == USB 接口编号顺序
        yield from sorted(funcs, key=lambda f: f.order)

    def __get_fsrc_path(self, func: str) -> str:
        return usb.get_gadget_path(self.__gadget, usb.G_FUNCTIONS, func)

    def __get_fdest_path(self, func: (str | None)=None) -> str:
        if func is None:
            return usb.get_gadget_path(self.__gadget, usb.G_PROFILE)
        return usb.get_gadget_path(self.__gadget, usb.G_PROFILE, func)

    def change_functions(self, enable: set[str], disable: set[str]) -> None:
        funcs = list(self.__read_metas())  # 已按 meta order 排序
        new: set[str] = set(func.name for func in funcs if func.enabled)
        new = (new - disable) | enable
        eps_req = sum(func.eps for func in funcs if func.name in new)
        if eps_req > self.__eps:
            raise RuntimeError(f"No available endpoints for this config: {eps_req} required, {self.__eps} is maximum")
        with self.__udc_stopped():
            self.__clear_profile(recreate=False)
            # 必须按 meta order（即 kvmd-otg start 的创建顺序）逐一创建 symlink，
            # 而非按 set 的任意迭代顺序，否则 configfs 会分配错误的 USB 接口编号。
            for func in funcs:
                if func.name not in new:
                    continue
                try:
                    os.symlink(self.__get_fsrc_path(func.name), self.__get_fdest_path(func.name))
                except FileExistsError:
                    pass
                except OSError as ex:
                    # configfs on some platforms rejects function links while UDC is stopped;
                    # log and skip so the remaining functions still get linked.
                    print(f"--   WARN -- Failed to link function {func.name}: {ex}", flush=True)

    def list_functions(self) -> None:
        funcs = list(self.__read_metas())
        eps_used = sum(func.eps for func in funcs if func.enabled)
        print(f"# Endpoints used: {eps_used} of {self.__eps}")
        print(f"# Endpoints free: {self.__eps - eps_used}")
        for func in funcs:
            print(f"{'+' if func.enabled else '-'} {func.name}  # [{func.eps}] {func.desc}")

    def make_gpio_config(self) -> None:
        class Dumper(yaml.Dumper):
            def increase_indent(self, flow: bool=False, indentless: bool=False) -> None:
                _ = indentless
                super().increase_indent(flow, False)

            def ignore_aliases(self, data) -> bool:  # type: ignore
                _ = data
                return True

        class InlineList(list):
            pass

        def represent_inline_list(dumper: yaml.Dumper, data):  # type: ignore
            return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=True)

        Dumper.add_representer(InlineList, represent_inline_list)

        config = {
            "drivers": {"otgconf": {"type": "otgconf"}},
            "scheme": {},
            "view": {"table": []},
        }
        for func in self.__read_metas():
            config["scheme"][func.name] = {  # type: ignore
                "driver": "otgconf",
                "pin": func.name,
                "mode": "output",
                "pulse": False,
            }
            config["view"]["table"].append(InlineList([  # type: ignore
                "#" + func.desc,
                "#" + func.name,
                func.name,
            ]))
        print(yaml.dump({"kvmd": {"gpio": config}}, indent=4, Dumper=Dumper))

    def reset(self) -> None:
        with self.__udc_stopped():
            pass


# =====
def main(argv: (list[str] | None)=None) -> None:
    (parent_parser, argv, config) = init(
        add_help=False,
        cli_logging=True,
        argv=argv,
    )
    parser = argparse.ArgumentParser(
        prog="kvmd-otgconf",
        description="KVMD OTG low-level runtime configuration tool",
        parents=[parent_parser],
    )
    parser.add_argument("-l", "--list-functions", action="store_true", help="List functions")
    parser.add_argument("-e", "--enable-function", nargs="+", default=[], metavar="<name>", help="Enable function(s)")
    parser.add_argument("-d", "--disable-function", nargs="+", default=[], metavar="<name>", help="Disable function(s)")
    parser.add_argument("-r", "--reset-gadget", action="store_true", help="Reset gadget")
    parser.add_argument("--make-gpio-config", action="store_true")
    options = parser.parse_args(argv[1:])

    gc = _GadgetControl(config.otg.meta, config.otg.gadget, config.otg.udc, config.otg.endpoints, config.otg.init_delay)

    if options.list_functions:
        gc.list_functions()

    elif options.enable_function or options.disable_function:
        enable = set(map(valid_stripped_string_not_empty, options.enable_function))
        disable = set(map(valid_stripped_string_not_empty, options.disable_function))
        gc.change_functions(enable, disable)
        gc.list_functions()

    elif options.reset_gadget:
        gc.reset()

    elif options.make_gpio_config:
        gc.make_gpio_config()

    else:
        gc.list_functions()
