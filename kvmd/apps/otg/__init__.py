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
import re
import shutil
import json
import time
import argparse
import glob

from os.path import join  # pylint: disable=ungrouped-imports

from ...logging import get_logger

from ...yamlconf import Section

from ...validators import ValidatorError

from ... import usb

from .. import init

from .hid import Hid
from .hid.keyboard import make_keyboard_hid
from .hid.mouse import make_mouse_hid
from .hid.touch import make_touch_hid
from . import mtp
from . import ffshid


# =====
def _mkdir(path: str) -> None:
    get_logger().info("MKDIR --- %s", path)
    os.mkdir(path)


def _chown(path: str, user: str) -> None:
    get_logger().info("CHOWN --- %s - %s", user, path)
    shutil.chown(path, user)


def _symlink(src: str, dest: str) -> None:
    get_logger().info("SYMLINK - %s --> %s", dest, src)
    os.symlink(src, dest)


def _rmdir(path: str) -> None:
    get_logger().info("RMDIR --- %s", path)
    os.rmdir(path)


def _cleanup_uvc_function(path: str) -> None:
    logger = get_logger()
    logger.info("UVC_CLEAN - %s", path)

    # Remove user-created UVC links/directories in reverse order.
    for sp in [
        "streaming/class/fs/h",
        "streaming/class/hs/h",
        "streaming/class/ss/h",
        "streaming/header/h/u",
        "control/class/fs/h",
        "control/class/ss/h",
    ]:
        _unlink(join(path, sp), optional=True)

    # Remove all dynamically created uncompressed resolution dirs.
    uncompressed_path = join(path, "streaming/uncompressed/u")
    if os.path.isdir(uncompressed_path):
        for name in os.listdir(uncompressed_path):
            child = join(uncompressed_path, name)
            if os.path.isdir(child) and not os.path.islink(child):
                try:
                    _rmdir(child)
                except OSError as ex:
                    logger.info("UVC_CLEAN - [SKIPPED] %s: %s", child, ex)

    # Remove user-created containers. Ignore failures for kernel-owned nodes.
    for dp in [
        "streaming/header/h",
        "streaming/uncompressed/u",
        "control/header/h",
    ]:
        try:
            _rmdir(join(path, dp))
        except OSError as ex:
            logger.info("UVC_CLEAN - [SKIPPED] %s: %s", join(path, dp), ex)

    _rmdir(path)


def _unlink(path: str, optional: bool=False) -> None:
    logger = get_logger()
    if optional and not os.access(path, os.F_OK):
        logger.info("RM ------ [SKIPPED] %s", path)
        return
    logger.info("RM ------ %s", path)
    os.unlink(path)


def _write(path: str, value: (str | int), optional: bool=False) -> None:
    logger = get_logger()
    if optional and not os.access(path, os.F_OK):
        logger.info("WRITE --- [SKIPPED] %s", path)
        return
    logger.info("WRITE --- %s", path)
    with open(path, "w") as file:
        file.write(str(value))


def _write_bytes(path: str, data: bytes) -> None:
    get_logger().info("WRITE --- %s", path)
    with open(path, "wb") as file:
        file.write(data)


def _check_config(config: Section) -> None:
    if (
        not config.otg.devices.serial.enabled
        and not config.otg.devices.ethernet.enabled
        and not config.otg.devices.mtp.enabled
        and config.kvmd.hid.type != "otg"
        and config.kvmd.msd.type != "otg"
    ):
        raise RuntimeError("Nothing to do")


# =====
class _GadgetConfig:
    def __init__(self, gadget_path: str, profile_path: str, meta_path: str, eps: int) -> None:
        self.__gadget_path = gadget_path
        self.__profile_path = profile_path
        self.__meta_path = meta_path
        self.__eps_max = eps
        self.__eps_used = 0
        self.__hid_instance = 0
        self.__msd_instance = 0
        self.__func_order = 0  # 记录函数创建顺序，供 kvmd-otgconf 重建 symlink 时使用
        _mkdir(meta_path)

    def add_audio_mic(self, start: bool, product: str) -> None:
        eps = 2
        func = "uac2.usb0"
        func_path = self.__create_function(func)
        _write(join(func_path, "c_chmask"), 0)
        _write(join(func_path, "p_chmask"), 0b11)
        _write(join(func_path, "p_srate"), 48000)
        _write(join(func_path, "p_ssize"), 2)
        _write(join(func_path, "function_name"), product,optional=True) #rm1 can't support function_name
        if start:
            self.__start_function(func, eps)
        self.__create_meta(func, product, eps)

    def add_camera(self, start: bool, product: str) -> None:
        eps = 2
        func = "uvc.gs6"
        func_path = self.__create_function(func)
        _write(join(func_path, "device_name"), product, optional=True)
        _write(join(func_path, "function_name"), product, optional=True)  # rm1 can't support function_name
        config_path = join(self.__gadget_path, "configs/b.1")

        _write(join(self.__gadget_path, "bcdDevice"), 0x0310)
        _write(join(self.__gadget_path, "bDeviceProtocol"), 1)
        _write(join(self.__gadget_path, "bDeviceSubClass"), 2)
        _write(join(self.__gadget_path, "bDeviceClass"), 239)

        _write(join(func_path, "streaming_maxpacket"), 3072)
        _write(join(func_path, "uvc_num_request"), 2)
                
        control_header_path = join(func_path, "control/header/h")
        if not os.path.exists(control_header_path):
            _mkdir(control_header_path)
        
        _symlink(control_header_path,join(func_path, "control/class/fs/h"))
        _symlink(control_header_path,join(func_path, "control/class/ss/h"))

        streaming_path = join(func_path, "streaming/uncompressed/u")
        if not os.path.exists(streaming_path):
            _mkdir(streaming_path)

        _write(join(streaming_path, "bBitsPerPixel"), 12)
        _write_bytes(join(streaming_path, "guidFormat"),
                     b'\x4e\x56\x31\x32\x00\x00\x10\x00\x80\x00\x00\xaa\x00\x38\x9b\x71')

        res_path = join(streaming_path, "576p")
        _mkdir(res_path)

        width = 1024
        height = 576
        _write(join(res_path, "wWidth"), width)
        _write(join(res_path, "wHeight"), height)
        _write(join(res_path, "dwDefaultFrameInterval"), 333333)
        _write(join(res_path, "dwMinBitRate"), width * height * 20)
        _write(join(res_path, "dwMaxBitRate"), width * height * 20)
        _write(join(res_path, "dwMaxVideoFrameBufferSize"), width * height * 2)
        _write(join(res_path, "dwFrameInterval"), "333333\n666666\n1000000\n2000000")
        # _write(join(res_path, "bFrameIndex"), 1)
        
        streaming_header_path = join(func_path, "streaming/header/h")
        if not os.path.exists(streaming_header_path):
            _mkdir(streaming_header_path)
        
        _symlink(streaming_path,join(streaming_header_path, "u"))
        _symlink(streaming_header_path,join(func_path, "streaming/class/fs/h"))
        _symlink(streaming_header_path,join(func_path, "streaming/class/ss/h"))
        _symlink(streaming_header_path,join(func_path, "streaming/class/hs/h"))
        
        os_desc_path = join(self.__gadget_path, "os_desc")
        if not os.path.exists(os_desc_path):
            _mkdir(os_desc_path)    
        _symlink(config_path,join(os_desc_path, "b.1"))
                                           
        if start:
            self.__start_function(func, eps)
        self.__create_meta(func, product, eps)

    def add_serial(self, start: bool) -> None:
        eps = 3
        func = "acm.usb0"
        self.__create_function(func)
        if start:
            self.__start_function(func, eps)
        self.__create_meta(func, "Serial Port", eps)

    def add_ethernet(self, start: bool, driver: str, host_mac: str, kvm_mac: str) -> None:
        eps = 3
        if host_mac and kvm_mac and host_mac == kvm_mac:
            raise RuntimeError("Ethernet host_mac should not be equal to kvm_mac")
        real_driver = driver
        if driver == "rndis5":
            real_driver = "rndis"
        func = f"{real_driver}.usb0"
        func_path = self.__create_function(func)
        if host_mac:
            _write(join(func_path, "host_addr"), host_mac)
        if kvm_mac:
            _write(join(func_path, "dev_addr"), kvm_mac)
        if driver in ["ncm", "rndis"]:
            _write(join(self.__gadget_path, "os_desc/use"), "1")
            _write(join(self.__gadget_path, "os_desc/b_vendor_code"), "0xCD")
            _write(join(self.__gadget_path, "os_desc/qw_sign"), "MSFT100")
            if driver == "ncm":
                _write(join(func_path, "os_desc/interface.ncm/compatible_id"), "WINNCM")
            elif driver == "rndis":
                # On Windows 7 and later, the RNDIS 5.1 driver would be used by default,
                # but it does not work very well. The RNDIS 6.0 driver works better.
                # In order to get this driver to load automatically, we have to use
                # a Microsoft-specific extension of USB.
                _write(join(func_path, "os_desc/interface.rndis/compatible_id"), "RNDIS")
                _write(join(func_path, "os_desc/interface.rndis/sub_compatible_id"), "5162001")
            _symlink(self.__profile_path, join(self.__gadget_path, "os_desc", usb.G_PROFILE_NAME))
        if start:
            self.__start_function(func, eps)
        self.__create_meta(func, "Ethernet", eps)   

    def add_rndis(self, start: bool) -> None:
        eps = 2
        func = "rndis.usb0"
        func_path = join(self.__gadget_path, "functions", func)
        _mkdir(func_path)
        if start:
            _symlink(func_path, join(self.__profile_path, func))
        self.__create_meta(func, "RNDIS",eps)

    def add_mtp(self, start: bool) -> None:
        eps = 3
        func = "ffs.mtp"
        self.__create_function(func)
        if start:
            self.__start_function(func, eps)
        self.__create_meta(func, "MTP Storage", eps)

    def add_keyboard(self, start: bool, remote_wakeup: bool) -> None:
        self.__add_hid("Keyboard", start, remote_wakeup, make_keyboard_hid())

    def add_mouse(self, start: bool, remote_wakeup: bool, absolute: bool, horizontal_wheel: bool) -> None:
        desc = ("Absolute" if absolute else "Relative") + " Mouse"
        self.__add_hid(desc, start, remote_wakeup, make_mouse_hid(absolute, horizontal_wheel))

    def add_touch(self, start: bool, remote_wakeup: bool) -> None:
        self.__add_hid("Touch Screen", start, remote_wakeup, make_touch_hid())

    def add_ffs_mouse(self, start: bool, hids: list[Hid], names: list[str]) -> None:
        # One FunctionFS function with one interrupt IN endpoint per mouse, no OUT endpoints.
        # The descriptors are served by the ffshid daemon, see ffshid.prepare().
        eps = len(hids)
        func = ffshid.MOUSE_FUNCTION
        self.__create_function(func)
        if start:
            self.__start_function(func, eps)
        self.__create_meta(func, " + ".join(names) + " (FunctionFS)", eps)

    def __add_hid(self, desc: str, start: bool, remote_wakeup: bool, hid: Hid) -> None:
        eps = 1
        func = f"hid.usb{self.__hid_instance}"
        func_path = self.__create_function(func)
        _write(join(func_path, "no_out_endpoint"), "1", optional=True)
        if remote_wakeup:
            _write(join(func_path, "wakeup_on_write"), "1", optional=True)
        _write(join(func_path, "protocol"), hid.protocol)
        _write(join(func_path, "subclass"), hid.subclass)
        _write(join(func_path, "report_length"), hid.report_length)
        _write_bytes(join(func_path, "report_desc"), hid.report_descriptor)
        if start:
            self.__start_function(func, eps)
        self.__create_meta(func, desc, eps)
        self.__hid_instance += 1

    def add_msd(
        self,
        start: bool,
        user: str,
        stall: bool,
        cdrom: bool,
        rw: bool,
        removable: bool,
        fua: bool,
        inquiry_string_cdrom: str,
        inquiry_string_flash: str,
    ) -> None:

        # Endpoints number depends on transport_type but we can consider that this is 2
        # because transport_type is always USB_PR_BULK by default if CONFIG_USB_FILE_STORAGE_TEST
        # is not defined. See drivers/usb/gadget/function/storage_common.c
        eps = 2
        func = f"mass_storage.{self.__msd_instance}"
        func_path = self.__create_function(func)
        _write(join(func_path, "stall"), int(stall))
        _write(join(func_path, "lun.0/cdrom"), int(cdrom))
        _write(join(func_path, "lun.0/ro"), int(not rw))
        _write(join(func_path, "lun.0/removable"), int(removable))
        _write(join(func_path, "lun.0/nofua"), int(not fua))
        inquiry_string = inquiry_string_cdrom if cdrom else inquiry_string_flash
        _write(join(func_path, "lun.0/inquiry_string"), inquiry_string)
        if user != "root":
            _chown(join(func_path, "lun.0/cdrom"), user)
            _chown(join(func_path, "lun.0/ro"), user)
            _chown(join(func_path, "lun.0/file"), user)
            _chown(join(func_path, "lun.0/forced_eject"), user)
        
        # 如果需要立即启动，创建符号链接
        if start:
            self.__start_function(func, eps)
        desc = ("Mass Storage CD-ROM" if self.__msd_instance == 0 else f"Mass Storage Disk #{self.__msd_instance}")
        self.__create_meta(func, desc, eps)
        self.__msd_instance += 1

    def __create_function(self, func: str) -> str:
        func_path = join(self.__gadget_path, "functions", func)
        _mkdir(func_path)
        return func_path

    def __start_function(self, func: str, eps: int) -> None:
        func_path = join(self.__gadget_path, "functions", func)
        if self.__eps_max - self.__eps_used >= eps:
            _symlink(func_path, join(self.__profile_path, func))
            self.__eps_used += eps
        else:
            get_logger().info("Will not be started: No available endpoints")

    def __create_meta(self, func: str, desc: str, eps: int) -> None:
        _write(join(self.__meta_path, f"{func}@meta.json"), json.dumps({
            "function": func,
            "description": desc,
            "endpoints": eps,
            "order": self.__func_order,  # configfs symlink 必须按此顺序创建才能保持 USB 接口编号不变
        }))
        self.__func_order += 1


def _cmd_start(config: Section) -> None:  # pylint: disable=too-many-statements,too-many-branches
    # https://www.kernel.org/doc/Documentation/usb/gadget_configfs.txt
    # https://www.isticktoit.net/?p=1383

    logger = get_logger()

    try:
        with open("/proc/gl-hw-info/model", "r") as file:
            model = file.read().strip().lower()
    except OSError:
        model = ""

    _check_config(config)

    udc = usb.find_udc(config.otg.udc)
    logger.info("Using UDC %s", udc)

    logger.info("Creating gadget %r ...", config.otg.gadget)
    gadget_path = usb.get_gadget_path(config.otg.gadget)
    _mkdir(gadget_path)

    _write(join(gadget_path, "idVendor"), f"0x{config.otg.vendor_id:04X}")
    _write(join(gadget_path, "idProduct"), f"0x{config.otg.product_id:04X}")
    _write(join(gadget_path, "bcdUSB"), f"0x{config.otg.usb_version:04X}")

    # bcdDevice should be incremented any time there are breaking changes
    # to this script so that the host OS sees it as a new device
    # and re-enumerates everything rather than relying on cached values.
    device_version = config.otg.device_version
    if device_version < 0:
        device_version = 0x0100
        if config.otg.devices.ethernet.enabled:
            if config.otg.devices.ethernet.driver == "ncm":
                device_version = 0x0102
            elif config.otg.devices.ethernet.driver == "rndis":
                device_version = 0x0101
    _write(join(gadget_path, "bcdDevice"), f"0x{device_version:04X}")

    lang_path = join(gadget_path, "strings/0x409")
    _mkdir(lang_path)
    _write(join(lang_path, "manufacturer"), config.otg.manufacturer)
    _write(join(lang_path, "product"), config.otg.product)
    if config.otg.serial is not None:
        _write(join(lang_path, "serialnumber"), config.otg.serial)

    profile_path = join(gadget_path, usb.G_PROFILE)
    _mkdir(profile_path)
    if config.otg.config:
        _mkdir(join(profile_path, "strings/0x409"))
        _write(join(profile_path, "strings/0x409/configuration"), config.otg.config)
    if model == "rmq1":
        _write(join(profile_path, "MaxPower"), 120)
    else:
        _write(join(profile_path, "MaxPower"), config.otg.max_power)
    if config.otg.remote_wakeup:
        # XXX: Should we use MaxPower=100 with Remote Wakeup?
        _write(join(profile_path, "bmAttributes"), "0xA0")

    gc = _GadgetConfig(gadget_path, profile_path, config.otg.meta, config.otg.endpoints)
    cod = config.otg.devices

    if cod.rndis.enabled:
        logger.info("===== RNDIS =====")
        gc.add_rndis(cod.rndis.start)

    if cod.mtp.enabled:
        logger.info("===== MTP =====")
        gc.add_mtp(cod.mtp.start)

    ffs_mouse_hids: list[Hid] = []
    ffs_mouse_names: list[str] = []

    if config.kvmd.hid.type == "otg":
        ckhm = config.kvmd.hid.mouse
        ffs_mouse = cod.hid.ffs_mouse.enabled
        if cod.hid.keyboard.enabled:
            logger.info("===== HID-Keyboard =====")
            gc.add_keyboard(cod.hid.keyboard.start, config.otg.remote_wakeup)
        # In FunctionFS mouse mode the configfs mouse functions are still created
        # (so the /dev/hidgN numbering of the other HID devices does not change),
        # but they are not linked into the profile. The ffs.mouse function
        # replaces them in the same position of the interface order.
        if cod.hid.mouse.enabled:
            logger.info("===== HID-Mouse =====")
            gc.add_mouse((cod.hid.mouse.start and not ffs_mouse), config.otg.remote_wakeup, ckhm.absolute, ckhm.horizontal_wheel)
            if ffs_mouse:
                ffs_mouse_hids.append(make_mouse_hid(ckhm.absolute, ckhm.horizontal_wheel))
                ffs_mouse_names.append(("Absolute" if ckhm.absolute else "Relative") + " Mouse")
        if cod.hid.mouse_alt.enabled and cod.hid.mouse_alt.device:
            logger.info("===== HID-Mouse-Alt =====")
            gc.add_mouse((cod.hid.mouse_alt.start and not ffs_mouse), config.otg.remote_wakeup, (not ckhm.absolute), ckhm.horizontal_wheel)
            if ffs_mouse and ffs_mouse_hids:
                ffs_mouse_hids.append(make_mouse_hid((not ckhm.absolute), ckhm.horizontal_wheel))
                ffs_mouse_names.append(("Relative" if ckhm.absolute else "Absolute") + " Mouse")
        if ffs_mouse_hids:
            logger.info("===== HID-Mouse-FFS =====")
            gc.add_ffs_mouse(cod.hid.mouse.start, ffs_mouse_hids, ffs_mouse_names)
        if cod.hid.touch.enabled:
            logger.info("===== HID-Touch =====")
            gc.add_touch(cod.hid.touch.start, config.otg.remote_wakeup)

    if config.kvmd.msd.type == "otg":
        logger.info("===== MSD =====")
        logger.info("===== MSD Extra:=====", cod.drives.default._unpack())
        # first for cdrom
        if cod.msd.default.cdrom:
            gc.add_msd(
                start=cod.msd.start_cdrom,
                user=config.otg.user,
                inquiry_string_cdrom=usb.make_inquiry_string(**cod.msd.default.inquiry_string.cdrom._unpack()),
                inquiry_string_flash=usb.make_inquiry_string(**cod.msd.default.inquiry_string.flash._unpack()),
                **cod.msd.default._unpack(ignore="inquiry_string"),
            )
        else:
            gc.add_msd(
                cod.msd.start_cdrom, config.otg.user, stall=False, cdrom=True, rw=False, removable=True, fua=True,
                inquiry_string_cdrom=usb.make_inquiry_string(**cod.msd.default.inquiry_string.cdrom._unpack()),
                inquiry_string_flash=usb.make_inquiry_string(**cod.msd.default.inquiry_string.flash._unpack()),
                )
        # second for thumbdrive
        gc.add_msd(
            cod.msd.start_flash, config.otg.user, stall=False, cdrom=False, rw=True, removable=True, fua=True,
            inquiry_string_cdrom=usb.make_inquiry_string(**cod.msd.default.inquiry_string.cdrom._unpack()),
            inquiry_string_flash=usb.make_inquiry_string(**cod.msd.default.inquiry_string.flash._unpack()),
            )
        if cod.drives.enabled:
            for count in range(cod.drives.count):
                logger.info("===== MSD Extra: %d =====", count + 1)
                gc.add_msd(
                    start=cod.drives.start,
                    user="root",
                    inquiry_string_cdrom=usb.make_inquiry_string(**cod.drives.default.inquiry_string.cdrom._unpack()),
                    inquiry_string_flash=usb.make_inquiry_string(**cod.drives.default.inquiry_string.flash._unpack()),
                    **cod.drives.default._unpack(ignore="inquiry_string"),
                )

    if cod.ethernet.enabled:
        logger.info("===== Ethernet =====")
        gc.add_ethernet(**cod.ethernet._unpack(ignore=["enabled"]))

    if cod.serial.enabled:
        logger.info("===== Serial =====")
        gc.add_serial(cod.serial.start)

    if cod.audio.enabled:
        logger.info("===== Microphone %s =====", model)
        gc.add_audio_mic(cod.audio.start, cod.audio.product)
        
    if cod.camera.enabled:
        logger.info("===== Camera =====")
        gc.add_camera(cod.camera.start, cod.camera.product)

    logger.info("===== Preparing complete =====")

    mtp_started = os.path.islink(join(profile_path, "ffs.mtp"))
    if mtp_started:
        logger.info("Preparing uMTPrd ...")
        mtp.prepare(config.otg.init_delay)

    # The daemon is started even if the function is not linked yet,
    # so that kvmd-otgconf can enable it later without a reboot.
    if ffs_mouse_hids:
        logger.info("Preparing FunctionFS mouse ...")
        try:
            ffshid.prepare(cod.hid.ffs_mouse.mount, ffs_mouse_hids, ffs_mouse_names, config.otg.init_delay)
        except Exception:
            if mtp_started:
                mtp.cleanup()
            raise

    try:
        logger.info("Enabling the gadget ...")
        _write(join(gadget_path, "UDC"), udc)
        time.sleep(config.otg.init_delay)
        _chown(join(gadget_path, "UDC"), config.otg.user)
        _chown(profile_path, config.otg.user)
    except Exception:
        if mtp_started:
            try:
                mtp.cleanup()
            except Exception as ex:
                logger.error("Can't clean up uMTPrd after gadget start failure: %s", ex)
        if ffs_mouse_hids:
            try:
                ffshid.cleanup(cod.hid.ffs_mouse.mount)
            except Exception as ex:
                logger.error("Can't clean up FunctionFS mouse after gadget start failure: %s", ex)
        raise

    logger.info("Ready to work")


# =====
def _cmd_stop(config: Section) -> None:
    # https://www.kernel.org/doc/Documentation/usb/gadget_configfs.txt

    logger = get_logger()

    _check_config(config)

    gadget_path = usb.get_gadget_path(config.otg.gadget)

    logger.info("Disabling gadget %r ...", config.otg.gadget)
    _write(join(gadget_path, "UDC"), "\n")
    if os.path.isdir(join(gadget_path, "functions/ffs.mtp")):
        logger.info("Stopping uMTPrd ...")
        mtp.cleanup()
    if os.path.isdir(join(gadget_path, "functions", ffshid.MOUSE_FUNCTION)):
        logger.info("Stopping FunctionFS mouse ...")
        ffshid.cleanup(config.otg.devices.hid.ffs_mouse.mount)

    _unlink(join(gadget_path, "os_desc", usb.G_PROFILE_NAME), optional=True)

    profile_path = join(gadget_path, usb.G_PROFILE)
    for func in os.listdir(profile_path):
        if re.search(r"\.usb\d+$", func) or re.search(r"mass_storage\.\d+$", func) or re.search(r"\.gs\d+$", func) or func.startswith("ffs."):
            _unlink(join(profile_path, func))
    _rmdir(join(profile_path, "strings/0x409"))
    _rmdir(profile_path)

    funcs_path = join(gadget_path, "functions")
    for func in os.listdir(funcs_path):
        if func.startswith("uvc."):
            _cleanup_uvc_function(join(funcs_path, func))
        elif re.search(r"\.usb\d+$", func) or re.search(r"mass_storage\.\d+$", func) or re.search(r"\.gs\d+$", func) or func.startswith("ffs."):
            _rmdir(join(funcs_path, func))

    _rmdir(join(gadget_path, "strings/0x409"))
    _rmdir(gadget_path)

    for meta in os.listdir(config.otg.meta):
        _unlink(join(config.otg.meta, meta))
    _rmdir(config.otg.meta)

    logger.info("Bye-bye")


# =====
def main(argv: (list[str] | None)=None) -> None:
    # 初始化配置和参数解析器
    (parent_parser, argv, config) = init(
        add_help=False,
        argv=argv,
        load_hid=True,
        load_atx=True,
        load_msd=True,
    )
    
    # 创建主参数解析器
    parser = argparse.ArgumentParser(
        prog="kvmd-otg",
        description="Control KVMD OTG device",
        parents=[parent_parser],
    )
    
    # 设置默认命令为打印帮助信息
    parser.set_defaults(cmd=(lambda *_: parser.print_help()))
    
    # 创建子命令解析器
    subparsers = parser.add_subparsers()

    # 添加"start"子命令
    cmd_start_parser = subparsers.add_parser("start", help="Start OTG")
    cmd_start_parser.set_defaults(cmd=_cmd_start)

    # 添加"stop"子命令
    cmd_stop_parser = subparsers.add_parser("stop", help="Stop OTG")
    cmd_stop_parser.set_defaults(cmd=_cmd_stop)

    # 解析命令行参数
    options = parser.parse_args(argv[1:])
    
    # 执行选定的命令
    try:
        options.cmd(config)
    except ValidatorError as ex:
        # 如果发生验证错误，则以错误信息退出程序
        raise SystemExit(str(ex))
