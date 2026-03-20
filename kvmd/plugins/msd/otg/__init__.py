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


import asyncio
import contextlib
import dataclasses
import functools
import time
import os
import copy
import re

from typing import AsyncGenerator

from ....logging import get_logger

from ....inotify import Inotify

from ....yamlconf import Option

from ....validators.basic import valid_bool
from ....validators.basic import valid_number
from ....validators.os import valid_command
from ....validators.kvm import valid_msd_image_name
from ....validators.basic import valid_stripped_string

from .... import aiotools
from .... import aiohelpers
from .... import fstab

from .. import MsdIsBusyError
from .. import MsdOfflineError
from .. import MsdConnectedError
from .. import MsdDisconnectedError
from .. import MsdImageNotSelected
from .. import MsdUnknownImageError
from .. import MsdImageExistsError
from .. import MsdImageInUseError
from .. import MsdDisabledError
from .. import BaseMsd
from .. import MsdFileReader
from .. import MsdFileWriter

from .storage import Image
from .storage import Storage
from .drive import Drive

from asyncio import create_subprocess_exec
import subprocess
import yaml
from ....utils import get_model_name

model_name = get_model_name()

# =====
@dataclasses.dataclass(frozen=True)
class _DriveState:
    image: (Image | None)
    cdrom: bool
    rw: bool


@dataclasses.dataclass
class _VirtualDriveState:
    image: (Image | None)
    connected: bool
    cdrom: bool
    rw: bool

    @classmethod
    def from_drive_state(cls, state: _DriveState) -> "_VirtualDriveState":
        return _VirtualDriveState(
            image=state.image,
            connected=bool(state.image),
            cdrom=state.cdrom,
            rw=state.rw,
        )


class _State:
    def __init__(self, notifier: aiotools.AioNotifier) -> None:
        self.__notifier = notifier

        self.storage: (Storage | None) = None
        self.vd: (_VirtualDriveState | None) = None
        self.vd_partition: (_VirtualDriveState | None) = None

        self._region = aiotools.AioExclusiveRegion(MsdIsBusyError)
        self._lock = asyncio.Lock()

    @contextlib.asynccontextmanager
    async def busy(self, check_online: bool=True) -> AsyncGenerator[None, None]:
        try:
            with self._region:
                async with self._lock:
                    self.__notifier.notify()
                    if check_online:
                        if self.vd is None:
                            raise MsdOfflineError()
                        assert self.storage
                    yield
        finally:
            self.__notifier.notify()

    def is_busy(self) -> bool:
        return self._region.is_busy()


# =====
class Plugin(BaseMsd):  # pylint: disable=too-many-instance-attributes
    mount_dict = {}
    if model_name == "rmq1":
        mount_dict = {
            "/dev/mmcblk0p18": "/userdata/media",
            "/dev/block/by-name/media": "/userdata/media",
        }
    else:
        mount_dict = {
            "/dev/mmcblk0p10": "/userdata/media",
            "/dev/block/by-name/media": "/userdata/media",
        }
    
    def get_mount_path(self, device_path: str) -> str:
        # 如果设备路径直接在mount_dict中，返回对应的挂载点
        if device_path in self.mount_dict:
            return self.mount_dict[device_path]
        
        # 如果设备路径匹配/dev/sdxx模式，返回/mnt/sdcard/
        if device_path.startswith("/dev/sd"):
            return "/mnt/sdcard/"
            
        # 默认返回None
        return None

    def __notify_remount(self) -> None:
        # 通知systask重新初始化inotify监听器，用于处理分区重新挂载的情况
        logger = get_logger(0)
        logger.info("Partition remount detected, notifying systask to reinitialize inotify...")
        self.__reset = True
        self.__notifier.notify(1)

    async def partition_remount(self) -> None:
        # 重新挂载partition_device
        await aiohelpers.umount(self.__partition_device)
        await aiohelpers.mount(self.__partition_device, self.get_mount_path(self.__partition_device), "rw", cmd=["mount"])

    def __init__(  # pylint: disable=super-init-not-called
        self,
        read_chunk_size: int,
        write_chunk_size: int,
        sync_chunk_size: int,

        remount_cmd: list[str],

        initial: dict,

        gadget: str,  # XXX: Not from options, see /kvmd/apps/kvmd/__init__.py for details
        partition_device: str = "/dev/block/by-name/media",
    ) -> None:

        self.__read_chunk_size = read_chunk_size
        self.__write_chunk_size = write_chunk_size
        self.__sync_chunk_size = sync_chunk_size
        self.__partition_device = os.path.realpath(partition_device)

        self.__initial_image: str = initial["image"]
        self.__initial_cdrom: bool = initial["cdrom"]

        # 多说一句,经过测试,在windows上,一个mass storage device只能模拟为一种设备
        # 所以,如果需要模拟为两种设备,则需要两个gadget
        # 并且,在windows上,一个ISO只能被模拟成CDROM,不能被模拟成U盘.LINUX没有这个问题.
        # 但是考虑到兼容性,还是使用两个gadget
        self.__drive = Drive(gadget, instance=0, lun=0) # cdrom drive
        self.__drive_partition = Drive(gadget, instance=1, lun=0) # partition drive

        # 把原本fstab/hotplug里面挂载的行为,移到这里来
        # 需要重新挂载partition_device
        aiotools.run_sync(self.partition_remount())

        # self.__storage = Storage(fstab.find_msd().root_path, remount_cmd)
        # 直接用固定值,或者 TODO:后面增加一个main/override配置
        # 这原本的代码是给debian用的,对于嵌入式没必要这么麻烦
        # 删了这个,fstab里面那个奇怪的记录也就可以删了
        self.__storage = Storage(self.get_mount_path(self.__partition_device), remount_cmd)

        self.__reader: (MsdFileReader | None) = None
        self.__writer: (MsdFileWriter | None) = None

        self.__notifier = aiotools.AioNotifier()
        self.__state = _State(self.__notifier)
        self.__reset = False
        self._enabled = True  # 动态启用/禁用标志

        logger = get_logger(0)
        logger.info("Using OTG gadget %r as MSD", gadget)
        aiotools.run_sync(self.__unsafe_reload_state())

    @classmethod
    def get_plugin_options(cls) -> dict:
        return {
            "read_chunk_size":   Option(65536,   type=functools.partial(valid_number, min=1024)),
            "write_chunk_size":  Option(65536,   type=functools.partial(valid_number, min=1024)),
            "sync_chunk_size":   Option(4194304, type=functools.partial(valid_number, min=1024)),
            "partition_device":  Option("/dev/block/by-name/media", type=valid_stripped_string),

            "remount_cmd": Option([
                "/bin/mount",
                "-o", "remount,${mode}",
            ], type=valid_command),

            "initial": {
                "image": Option("",    type=valid_msd_image_name, if_empty=""),
                "cdrom": Option(False, type=valid_bool),
            },
        }

    # =====

    async def set_enabled(self, enabled: bool) -> None:
        """动态启用或禁用 MSD 模块"""
        logger = get_logger(0)
        if self._enabled != enabled:
            self._enabled = enabled
            logger.info("MSD module %s", "enabled" if enabled else "disabled")
            self.__notifier.notify()

    def _check_enabled(self) -> None:
        """检查 MSD 是否被禁用，如果禁用则抛出异常"""
        if not self._enabled:
            raise MsdDisabledError()

    async def get_state(self) -> dict:
        # 获取MSD设备的当前状态
        async with self.__state._lock:  # pylint: disable=protected-access
            storage: (dict | None) = None
            if self.__state.storage:
                assert self.__state.vd
                # 在任何时候都显示实时统计信息
                # 之前他的代码逻辑是每写入/删除一个文件都要把分区remount from ro to rw,
                # 但是我们不需要这要做,他的这个做法应该是和sd卡有概率出现块损坏有关
                # 但是我们的emmc不会出现这种情况,所以不需要这么做
                # 我修改了不再重新remount,但是之前在reload进行的信息重载也必须换一个地方做
                # 我决定在__inotify中进行信息重载,这样应该就会上传/删除文件之后都会进行信息重载
                await self.__storage.reload_parts_info()

                # 将存储状态转换为字典
                storage = dataclasses.asdict(self.__state.storage)
                # 删除不需要暴露的内部字段
                for name in list(storage["images"]):
                    del storage["images"][name]["name"]
                    del storage["images"][name]["path"]
                    del storage["images"][name]["in_storage"]
                for name in list(storage["parts"]):
                    del storage["parts"][name]["name"]

                # 添加下载和上传状态
                storage["downloading"] = (self.__reader.get_state() if self.__reader else None)
                storage["uploading"] = (self.__writer.get_state() if self.__writer else None)

            # 获取虚拟驱动器状态
            vd: (dict | None) = None
            if self.__state.vd:
                assert self.__state.storage
                vd = dataclasses.asdict(self.__state.vd)
                # 删除镜像路径信息
                if vd["image"]:
                    del vd["image"]["path"]
            
            vd_partition: (dict | None) = None
            if self.__state.vd_partition:
                vd_partition = dataclasses.asdict(self.__state.vd_partition)
                if vd_partition["image"]:
                    del vd_partition["image"]["path"]
            
            # 获取USB设备状态
            available_devices = await self.partition_show()

            # 返回完整状态信息
            return {
                "enabled": self._enabled,
                "online": (self._enabled and bool(vd) and self.__drive.is_enabled()),
                "busy": self.__state.is_busy(),
                "storage": storage if self._enabled else None,
                "drive": vd if self._enabled else None,
                "drive_partition": vd_partition if self._enabled else None,  # 虚拟驱动器状态
                "available_devices": available_devices if self._enabled else {},  # USB设备状态
            }

    async def trigger_state(self) -> None:
        self.__notifier.notify(1)

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        prev: dict = {}
        while True:
            if (await self.__notifier.wait()) > -1:
                prev = {}
            new = await self.get_state()
            if not prev or (prev.get("online") != new["online"]):
                prev = copy.deepcopy(new)
                yield new
            else:
                diff: dict = {}
                for sub in ["busy", "drive", "drive_partition"]:
                    if prev.get(sub) != new[sub]:
                        diff[sub] = new[sub]
                for sub in ["images", "parts", "downloading", "uploading"]:
                    if (prev.get("storage") or {}).get(sub) != (new["storage"] or {}).get(sub):
                        if "storage" not in diff:
                            diff["storage"] = {}
                        diff["storage"][sub] = new["storage"][sub]
                # 检查USB设备变化
                if prev.get("available_devices") != new["available_devices"]:
                    diff["available_devices"] = new["available_devices"]
                if diff:
                    prev = copy.deepcopy(new)
                    yield diff

    @aiotools.atomic_fg
    async def reset(self) -> None:
        async with self.__state.busy(check_online=False):
            try:
                self.__reset = True
                self.__drive.set_image_path("")
                self.__drive.set_cdrom_flag(False)
                self.__drive.set_rw_flag(False)
                await self.__storage.remount_rw(False)
            except Exception:
                get_logger(0).exception("Can't reset MSD properly")

    # =====

    @aiotools.atomic_fg
    async def set_params(
        self,
        name: (str | None)=None,
        cdrom: (bool | None)=None,
        rw: (bool | None)=None,
    ) -> None:
        self._check_enabled()  # 检查 MSD 是否被禁用
        async with self.__state.busy():
            assert self.__state.vd
            self.__STATE_check_disconnected()

            if name is not None:
                if name:
                    self.__state.vd.image = await self.__STATE_get_storage_image(name)
                else:
                    self.__state.vd.image = None

            if cdrom is not None:
                self.__state.vd.cdrom = cdrom
                if cdrom:
                    rw = False

            if rw is not None:
                self.__state.vd.rw = rw
                if rw:
                    self.__state.vd.cdrom = False

    # 这里按照设计既要支持ISO也要支持分区路径
    @aiotools.atomic_fg
    async def set_connected(self, connected: bool) -> None:
        self._check_enabled()  # 检查 MSD 是否被禁用
        async with self.__state.busy():
            assert self.__state.vd
            if connected:
                self.__STATE_check_disconnected()

                if self.__state.vd.image is None:
                    raise MsdImageNotSelected()

                if not (await self.__state.vd.image.exists()):
                    raise MsdUnknownImageError()

                assert self.__state.vd.image.in_storage

                self.__drive.set_rw_flag(self.__state.vd.rw)
                self.__drive.set_cdrom_flag(self.__state.vd.cdrom)
                if self.__state.vd.rw:
                    await self.__state.vd.image.remount_rw(True)
                self.__drive.set_image_path(self.__state.vd.image.path)

            else:
                self.__STATE_check_connected()
                self.__drive.set_image_path("")
                await self.__storage.remount_rw(False, fatal=False)

            self.__state.vd.connected = connected
    
    def __parse_blkid_output(self, output: str) -> dict:
        # 解析blkid输出，兼容busybox和util-linux版本
        # 
        # Args:
        #     output: blkid命令的输出字符串
        #     
        # Returns:
        #     包含uuid、filesystem和label的字典
        uuid = ""
        filesystem = ""
        label = ""
        
        # 使用正则表达式来解析键值对，支持带引号和不带引号的值
        # 匹配 KEY="value" 或 KEY=value 格式
        pattern = r'(\w+)=(?:"([^"]*)"|([^\s]+))'
        matches = re.findall(pattern, output)
        
        parsed_data = {}
        for match in matches:
            key = match[0]
            # 优先使用带引号的值，如果没有则使用不带引号的值
            value = match[1] if match[1] else match[2]
            parsed_data[key] = value
        
        # 提取UUID
        if "UUID" in parsed_data:
            uuid = parsed_data["UUID"]
            
        # 提取文件系统类型
        if "TYPE" in parsed_data:
            filesystem = parsed_data["TYPE"]
            
        # 提取标签，优先使用LABEL，如果没有则尝试LABEL_FATBOOT
        if "LABEL" in parsed_data:
            label = parsed_data["LABEL"]
        elif "LABEL_FATBOOT" in parsed_data:
            label = parsed_data["LABEL_FATBOOT"]
            
        return {
            "uuid": uuid,
            "filesystem": filesystem,
            "label": label
        }

    async def __get_partition_info(self, dev_path: str, size_kb: int) -> dict:
        # 获取分区的详细信息
        #
        # Args:
        #     dev_path: 分区设备路径
        #     size_kb: 分区大小(KB)
        #
        # Returns:
        #     包含分区信息的字典,包括size、uuid、filesystem和label
        # 获取分区UUID、文件系统类型和标签
        uuid = ""
        filesystem = ""
        label = ""
        try:
            process = await create_subprocess_exec(
                "blkid",
                dev_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            output = stdout.decode().strip()
            
            # 使用新的解析函数来处理blkid输出
            parsed_info = self.__parse_blkid_output(output)
            uuid = parsed_info["uuid"]
            filesystem = parsed_info["filesystem"]
            label = parsed_info["label"]
            
        except Exception as e:
            get_logger(0).error(f"Failed to get UUID, filesystem type and label for {dev_path}: {e}")
        
        return {
            "size": size_kb * 1024,  # 转换为字节
            "uuid": uuid,
            "filesystem": filesystem,
            "label": label
        }

    # 返回所有U盘的设备路径和大小
    @aiotools.atomic_fg
    async def partition_show(self) -> dict[str, dict]:
        devices = {}
        # 获取当前使用的分区设备路径（真实路径）
        current_partition = os.path.realpath(self.__partition_device)

        if model_name == "rmq1":
            MEDIA_PART_NAME = "mmcblk0p16"
        else:
            MEDIA_PART_NAME = "mmcblk0p10"

        # 读取 /proc/partitions 获取所有分区信息
        try:
            with open("/proc/partitions", "r") as f:
                lines = f.readlines()
                # 跳过头两行
                for line in lines[2:]:
                    parts = line.strip().split()
                    if len(parts) == 4:
                        dev_name = parts[3]
                        size_kb = int(parts[2])  # 大小以KB为单位
                        # 只处理 sd 开头的设备
                        if dev_name.startswith("sd"):
                            disk_name = dev_name.rstrip("0123456789") #去掉sda1这类的分区数字
                            # 检查是否是 USB 设备
                            try:
                                # 不再检查removeable,因为有些U盘似乎也会被识别为非可移动设备
                                # with open(f"/sys/block/{disk_name}/removable", "r") as f:
                                #     removable = f.read().strip()
                                # if removable == "1":

                                # 如果是分区（设备名比磁盘名长）且是可移动设备，则添加到列表
                                # 这里额外提一句,直接mkfs /dev/sda并非就不能用.但是拔出U盘插入电脑会直接在电脑上识别不出来,因为没有了引导
                                if len(dev_name) > len(disk_name):
                                    dev_path = f"/dev/{dev_name}"
                                    partition_info = await self.__get_partition_info(dev_path, size_kb)
                                    # 添加is_current字段标识是否为当前使用的分区
                                    partition_info["is_current"] = (dev_path == current_partition)
                                    devices[dev_path] = partition_info
                            except (IOError, OSError):
                                continue
                        if dev_name.startswith(MEDIA_PART_NAME):
                            dev_path = f"/dev/{dev_name}"
                            partition_info = await self.__get_partition_info(dev_path, size_kb)
                            # 添加is_current字段标识是否为当前使用的分区
                            partition_info["is_current"] = (dev_path == current_partition)
                            devices[dev_path] = partition_info
        except (IOError, OSError) as e:
            get_logger(0).error(f"Error reading partitions: {str(e)}")

        return devices

    @aiotools.atomic_fg
    async def partition_connect(self) -> None:
        self._check_enabled()  # 检查 MSD 是否被禁用
        async with self.__state.busy():
            assert self.__state.vd_partition
            # 先运行sync确保缓存数据写入分区
            await aiotools.run_async(os.sync)
            # 使用内置的partition_path
            path = self.__partition_device
            # 如果path中是分区路径，则需要先卸载
            if path.startswith("/dev/"):
                # get realpath of path, path like /dev/block/by-name/media can't be used as mount point
                realpath = os.path.realpath(path)
                await aiohelpers.umount(realpath)

            self.__drive_partition.set_rw_flag(True)
            self.__drive_partition.set_cdrom_flag(False)
            self.__drive_partition.set_image_path(path)
            self.__state.vd_partition.rw = True
            self.__state.vd_partition.cdrom = False
            self.__state.vd_partition.connected = True
            self.__state.vd_partition.image = await self.__storage.make_image_by_path(path)

    async def __clean_trash_dirs(self, mount_path: str) -> None:
        # 清理指定路径下的回收站目录
        #
        # Args:
        #     mount_path: 要清理的挂载路径
        logger = get_logger(0)
        trash_dirs = [".Trashes", "$RECYCLE.BIN", ".Trash-1000"]
        for trash_dir in trash_dirs:
            # 使用os.walk来查找所有匹配的目录（不区分大小写）
            for root, dirs, _ in os.walk(mount_path):
                # logger.info(f"root: {root}, dirs: {dirs},mount_path: {mount_path}")
                for d in dirs:
                    if d.lower() == trash_dir.lower():
                        trash_path = os.path.join(root, d)
                        try:
                            import shutil
                            logger.info(f"Removing trash directory: {trash_path}")
                            shutil.rmtree(trash_path)
                        except Exception as e:
                            logger.error(f"Failed to remove trash directory {trash_path}: {e}")

    async def __run_command(self, cmd: str, args: list[str], error_msg: str) -> bool:
        # 执行命令并处理结果
        #
        # Args:
        #     cmd: 要执行的命令
        #     args: 命令参数列表
        #     error_msg: 错误信息前缀
        #
        # Returns:
        #     bool: 命令是否成功执行
        logger = get_logger(0)
        try:
            process = await create_subprocess_exec(
                cmd,
                *args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                logger.error(f"{error_msg}: {stderr.decode()}")
                return False
            return True
        except Exception as e:
            logger.error(f"{error_msg}: {str(e)}")
            return False

    async def __get_device_uuid(self, device_path: str) -> str:
        # 获取设备的UUID
        #
        # Args:
        #     device_path: 设备路径
        #
        # Returns:
        #     str: 设备UUID，如果获取失败则返回空字符串
        logger = get_logger(0)
        try:
            process = await create_subprocess_exec(
                "blkid",
                device_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            output = stdout.decode().strip()

            # 使用已有的解析函数来处理blkid输出
            parsed_info = self.__parse_blkid_output(output)
            uuid = parsed_info.get("uuid", "")

            if uuid:
                logger.info(f"Got UUID for {device_path}: {uuid}")
            else:
                logger.warning(f"No UUID found for {device_path}")

            return uuid
        except Exception as e:
            logger.error(f"Failed to get UUID for {device_path}: {e}")
            return ""

    async def __read_boot_yaml(self) -> dict:
        # 读取boot.yaml配置文件
        #
        # Returns:
        #     dict: 配置文件内容，如果读取失败则返回空字典
        logger = get_logger(0)
        config_path = "/etc/kvmd/user/boot.yaml"
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    return yaml.safe_load(f) or {}
            return {}
        except Exception as e:
            logger.error(f"Cannot read config file {config_path}: {e}")
            return {}

    async def __write_boot_yaml(self, data: dict) -> None:
        # 写入boot.yaml配置文件
        #
        # Args:
        #     data: 要写入的配置数据
        logger = get_logger(0)
        config_path = "/etc/kvmd/user/boot.yaml"
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w") as f:
                yaml.dump(data, f, default_flow_style=False)
            await asyncio.create_subprocess_shell("sync")
            logger.info(f"Successfully wrote config to {config_path}")
        except Exception as e:
            logger.error(f"Cannot write config file {config_path}: {e}")

    async def __check_and_update_uuid_if_changed(self, device_path: str) -> None:
        # 检查分区UUID是否变化,如果变化则更新配置
        #
        # Args:
        #     device_path: 设备路径
        logger = get_logger(0)

        try:
            # 获取当前的partition_device配置 (可能是UUID路径)
            current_partition_device = self.__partition_device
            logger.info(f"current_partition_device: {current_partition_device}")

            # 获取device_path的真实路径
            real_device_path = os.path.realpath(device_path)

            # 获取当前设备的UUID
            new_uuid = await self.__get_device_uuid(real_device_path)

            if not new_uuid:
                logger.warning(f"Could not get UUID for {real_device_path}, skipping UUID update")
                return

            # 构建新的UUID路径
            new_uuid_path = f"/dev/disk/by-uuid/{new_uuid}"

            # 检查当前partition_device是否是UUID路径
            if current_partition_device.startswith("/dev/disk/by-uuid/"):
                # 提取旧的UUID
                old_uuid = os.path.basename(current_partition_device)

                if old_uuid != new_uuid:
                    logger.info(f"UUID changed: {old_uuid} -> {new_uuid}, updating configuration")

                    # 读取boot.yaml配置
                    boot_config = await self.__read_boot_yaml()

                    # 更新配置中的partition_device
                    if "kvmd" not in boot_config:
                        boot_config["kvmd"] = {}
                    if "msd" not in boot_config["kvmd"]:
                        boot_config["kvmd"]["msd"] = {}
                    boot_config["kvmd"]["msd"]["partition_device"] = new_uuid_path

                    # 写入配置文件
                    await self.__write_boot_yaml(boot_config)

                    # 更新内部的partition_device引用
                    self.__partition_device = new_uuid_path

                    # 更新vd_partition.image以反映新的UUID
                    self.__state.vd_partition.image = await self.__storage.make_image_by_path(new_uuid_path)

                    logger.info(f"Successfully updated partition_device to {new_uuid_path}")
                else:
                    logger.info(f"UUID unchanged: {new_uuid}")
            elif os.path.realpath(current_partition_device) == real_device_path:
                # 如果当前使用的是直接设备路径(非UUID路径),将其转换为UUID路径
                logger.info(f"Converting partition_device from {current_partition_device} to UUID path {new_uuid_path}")

                # 读取boot.yaml配置
                boot_config = await self.__read_boot_yaml()

                # 更新配置中的partition_device
                if "kvmd" not in boot_config:
                    boot_config["kvmd"] = {}
                if "msd" not in boot_config["kvmd"]:
                    boot_config["kvmd"]["msd"] = {}
                boot_config["kvmd"]["msd"]["partition_device"] = new_uuid_path

                # 写入配置文件
                await self.__write_boot_yaml(boot_config)

                # 更新内部的partition_device引用
                self.__partition_device = new_uuid_path

                # 更新vd_partition.image
                self.__state.vd_partition.image = await self.__storage.make_image_by_path(new_uuid_path)

                logger.info(f"Successfully converted partition_device to UUID path {new_uuid_path}")

        except Exception as e:
            logger.error(f"Failed to check and update UUID: {e}")
            # 不抛出异常,因为这不应该影响正常的断开连接流程

    @aiotools.atomic_fg
    async def partition_disconnect(self) -> None:
        self._check_enabled()  # 检查 MSD 是否被禁用
        async with self.__state.busy():
            assert self.__state.vd_partition
            path = self.__drive_partition.get_image_path()
            get_logger(0).info(f"path: {path}")
            if not path or path.strip() == "":
                # 如果U盘在被控端被主动弹出,那获取lun目录下的Path为空,此时需要使用image的path
                # 也有可能从一开始就使用image的path最好?
                path = os.path.realpath(self.__state.vd_partition.image.path)

            self.__drive_partition.set_image_path("")
            await asyncio.sleep(1) # 等待1秒,确保image的path已经被清空,分区已经被远端卸载
            self.__state.vd_partition.connected = False

            # 如果path中是分区路径，则需要重新挂载
            remounted = False
            if path.startswith("/dev/"):
                mount_path = self.get_mount_path(path)
                if mount_path:
                    try:
                        get_logger(0).info(f"Mounting {path} to {mount_path}")
                        await aiohelpers.mount(path, mount_path, "rw",cmd = ["mount"]) #exfat-linux不支持nonempty
                        remounted = True

                        # 清理回收站目录
                        await self.__clean_trash_dirs(mount_path)

                        # 检查UUID是否变化 (可能在被控端被格式化)
                        await self.__check_and_update_uuid_if_changed(path)

                    except Exception as e:
                        get_logger(0).error(f"Failed to remount partition {path} to {mount_path}: {e}")

        # 如果发生了重新挂载，通知systask重新初始化inotify监听
        if remounted:
            self.__notify_remount()

        # 更新inotify
        await self.__reload_state()

    @aiotools.atomic_fg
    async def __do_format(self,path: str = "") -> None:
        # 保留原本的设计,如果path为空,则使用partition_device
        if not path or path.strip() == "":
            path = self.__partition_device

        # 获取真实设备路径（如果path是符号链接）
        real_path = os.path.realpath(path)

        # 获取原来的卷标
        old_label = ""
        try:
            process = await create_subprocess_exec(
                "blkid",
                real_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            output = stdout.decode().strip()
            parsed_info = self.__parse_blkid_output(output)
            old_label = parsed_info.get("label", "")
            if old_label:
                get_logger(0).info(f"Original volume label: {old_label}")
        except Exception as e:
            get_logger(0).warning(f"Failed to get original label: {e}")

        remounted = False
        try:
            # 先尝试卸载
            get_logger(0).info(f"Umounting {path}")
            await aiohelpers.umount(path)

            # 格式化分区
            get_logger(0).info(f"Formatting {path}")
            if not await self.__run_command("mkfs.exfat", [real_path], "mkfs.exfat command failed"):
                raise Exception("Failed to format partition")

            # 恢复原来的卷标,失败的话用GLKVM代替
            if old_label:
                get_logger(0).info(f"Restoring volume label: {old_label}")
                if not await self.__run_command("exfatlabel", [real_path, old_label], "exfatlabel command failed"):
                    get_logger(0).warning("Failed to restore volume label, write GLKVM in label instead")
                    #set GLKVM in label instead of old_label
                    if not await self.__run_command("exfatlabel", [real_path, "GLKVM"], "exfatlabel command failed"):
                        get_logger(0).error("Failed to write GLKVM in label")

            # 格式化后获取新的UUID
            new_uuid = await self.__get_device_uuid(real_path)

            if new_uuid:
                # 更新boot.yaml中的partition_device配置
                try:
                    boot_config = await self.__read_boot_yaml()

                    # 构建新的UUID路径
                    new_uuid_path = f"/dev/disk/by-uuid/{new_uuid}"

                    # 更新配置中的partition_device
                    if "kvmd" not in boot_config:
                        boot_config["kvmd"] = {}
                    if "msd" not in boot_config["kvmd"]:
                        boot_config["kvmd"]["msd"] = {}
                    boot_config["kvmd"]["msd"]["partition_device"] = new_uuid_path

                    # 写入配置文件
                    await self.__write_boot_yaml(boot_config)

                    # 更新内部的partition_device引用
                    self.__partition_device = new_uuid_path

                    get_logger(0).info(f"Updated partition_device to {new_uuid_path} in boot.yaml")
                except Exception as e:
                    get_logger(0).error(f"Failed to update boot.yaml with new UUID: {e}")
                    # 不抛出异常，因为格式化已经成功
            else:
                get_logger(0).warning("Could not get new UUID after formatting, partition_device not updated")

            # 重新挂载分区
            mount_path = self.get_mount_path(real_path)
            if mount_path:
                await aiohelpers.mount(real_path, mount_path, "rw", cmd=["mount"])
                remounted = True
        except Exception as e:
            get_logger(0).error(f"Failed to umount or format partition: {e}")
            raise

        # 如果发生了重新挂载，通知systask重新初始化inotify监听
        if remounted:
            self.__notify_remount()

    @aiotools.atomic_fg
    async def partition_format(self, path: str = "") -> None:
        self._check_enabled()  # 检查 MSD 是否被禁用
        if path is None or path.strip() == "":
            async with self.__state.busy():
                await self.__do_format(self.__partition_device)
        else:
            await self.__do_format(path)

        await self.__reload_state()


    @contextlib.asynccontextmanager
    async def read_image(self, name: str) -> AsyncGenerator[MsdFileReader, None]:
        self._check_enabled()  # 检查 MSD 是否被禁用
        try:
            with self.__state._region:  # pylint: disable=protected-access
                try:
                    async with self.__state._lock:  # pylint: disable=protected-access
                        self.__notifier.notify()
                        # self.__STATE_check_disconnected()

                        image = await self.__STATE_get_storage_image(name)
                        self.__reader = await MsdFileReader(
                            notifier=self.__notifier,
                            name=image.name,
                            path=image.path,
                            chunk_size=self.__read_chunk_size,
                        ).open()

                    self.__notifier.notify()
                    yield self.__reader

                finally:
                    await aiotools.shield_fg(self.__close_reader())
        finally:
            self.__notifier.notify()

    @contextlib.asynccontextmanager
    async def write_image(self, name: str, size: int, remove_incomplete: (bool | None)) -> AsyncGenerator[MsdFileWriter, None]:
        self._check_enabled()  # 检查 MSD 是否被禁用
        image: (Image | None) = None
        complete = False

        async def finish_writing() -> None:
            # Делаем под блокировкой, чтобы эвент айнотифи не был обработан
            # до того, как мы не закончим все процедуры.
            async with self.__state._lock:  # pylint: disable=protected-access
                try:
                    self.__notifier.notify()
                finally:
                    try:
                        if image:
                            await image.set_complete(complete)
                    finally:
                        try:
                            if image and remove_incomplete and not complete:
                                await image.remove(fatal=False)
                        finally:
                            # try:
                            await self.__close_writer()
                            # finally:
                            #     if image:
                            #         await image.remount_rw(False, fatal=False)

        try:
            with self.__state._region:  # pylint: disable=protected-access
                try:
                    async with self.__state._lock:  # pylint: disable=protected-access
                        self.__notifier.notify()
                        # self.__STATE_check_disconnected()

                        image = await self.__STORAGE_create_new_image(name)
                        # await image.remount_rw(True)
                        await image.set_complete(False)
                        self.__writer = await MsdFileWriter(
                            notifier=self.__notifier,
                            name=image.name,
                            path=image.path,
                            file_size=size,
                            sync_size=self.__sync_chunk_size,
                            chunk_size=self.__write_chunk_size,
                        ).open()

                    self.__notifier.notify()
                    yield self.__writer
                    complete = await self.__writer.finish()

                finally:
                    await aiotools.shield_fg(finish_writing())
        finally:
            await aiotools.shield_fg(self.__reload_state())
            self.__notifier.notify()

    @aiotools.atomic_fg
    async def remove(self, name: str) -> None:
        self._check_enabled()  # 检查 MSD 是否被禁用
        async with self.__state.busy():
            assert self.__state.storage
            assert self.__state.vd

            # 获取要删除的镜像
            image = await self.__STATE_get_storage_image(name)

            # 检查镜像是否正在被主驱动器挂载使用
            if self.__state.vd.image == image and self.__state.vd.connected:
                raise MsdImageInUseError()

            # 检查镜像是否正在被分区驱动器挂载使用
            if (self.__state.vd_partition and
                self.__state.vd_partition.image == image and
                self.__state.vd_partition.connected):
                raise MsdImageInUseError()

            # 如果镜像未被挂载，清除引用
            if self.__state.vd.image == image:
                self.__state.vd.image = None

            if self.__state.vd_partition and self.__state.vd_partition.image == image:
                self.__state.vd_partition.image = None

            # await image.remount_rw(True)
            try:
                await image.remove(fatal=True)
            finally:
                # await aiotools.shield_fg(image.remount_rw(False, fatal=False))
                self.__notifier.notify()

    # =====

    def __STATE_check_connected(self) -> None:  # pylint: disable=invalid-name
        assert self.__state.vd
        if not (self.__state.vd.connected or self.__drive.get_image_path()):
            raise MsdDisconnectedError()

    def __STATE_check_disconnected(self) -> None:  # pylint: disable=invalid-name
        assert self.__state.vd
        if self.__state.vd.connected or self.__drive.get_image_path():
            raise MsdConnectedError()

    async def __STATE_get_storage_image(self, name: str) -> Image:  # pylint: disable=invalid-name
        assert self.__state.storage
        image = self.__state.storage.images.get(name)
        if image is None or not (await image.exists()):
            raise MsdUnknownImageError()
        assert image.in_storage
        return image

    async def __STORAGE_create_new_image(self, name: str) -> Image:  # pylint: disable=invalid-name
        assert self.__state.storage
        image = await self.__storage.make_image_by_name(name)
        if image.name in self.__state.storage.images or (await image.exists()):
            raise MsdImageExistsError()
        return image

    # =====

    async def __close_reader(self) -> None:
        if self.__reader:
            try:
                await self.__reader.close()
            finally:
                self.__reader = None

    async def __close_writer(self) -> None:
        if self.__writer:
            try:
                await self.__writer.close()
            finally:
                self.__writer = None

    # =====

    @aiotools.atomic_fg
    async def cleanup(self) -> None:
        await self.__close_reader()
        await self.__close_writer()

    async def systask(self) -> None:
        logger = get_logger(0)
        while True:
            try:
                while True:
                    # Активно ждем, пока не будут на месте все каталоги.
                    await self.__reload_state()
                    if self.__state.vd:
                        break
                    await asyncio.sleep(5)

                with Inotify() as inotify:
                    # Из-за гонки между первым релоадом и установкой вотчеров,
                    # мы можем потерять какие-то каталоги стораджа, но это допустимо,
                    # так как всегда есть ручной перезапуск.
                    await inotify.watch_all_changes(*self.__storage.get_watchable_paths())
                    # OTG 重建时 drive 的 configfs 路径可能不存在，过滤掉避免 inotify 失败
                    drive_paths = [p for p in self.__drive.get_watchable_paths() if os.path.exists(p)]
                    if drive_paths:
                        await inotify.watch_all_changes(*drive_paths)
                    # 监听/dev目录的USB设备变化
                    await inotify.watch_create_and_delete("/dev")

                    # После установки вотчеров еще раз проверяем стейт,
                    # чтобы не потерять состояние привода.
                    await self.__reload_state()

                    while self.__state.vd:  # Если живы после предыдущей проверки
                        need_restart = self.__reset
                        self.__reset = False
                        need_reload_state = False
                        for event in (await inotify.get_series(timeout=1)):
                            # 检查是否是USB设备变化事件
                            if (event.path.startswith("/dev") and event.name and
                                event.name.startswith("sd") and len(event.name) > 3):
                                # 匹配/dev/sdX[数字]格式的USB分区设备
                                logger.info("Detected USB device change: %s", event.path)
                                need_reload_state = True
                            elif not event.path.startswith("/dev"):
                                # 非/dev目录的事件，按原逻辑处理
                                need_reload_state = True

                            if event.restart and not event.path.startswith("/dev"):
                                # Если выгрузили OTG, изменили каталоги, что-то отмонтировали или делают еще какую-то странную фигню.
                                # Проверяется маска InotifyMask.ALL_RESTART_EVENTS
                                logger.info("Got a big inotify event: %s; reinitializing MSD ...", event)
                                need_restart = True
                                break
                        if need_restart:
                            break
                        if need_reload_state:
                            await self.__reload_state()
                        elif self.__writer:
                            # При загрузке файла обновляем статистику раз в секунду (по таймауту).
                            # Это не нужно при обычном релоаде, потому что там и так проверяются все разделы.
                            await self.__reload_parts_info()

            except Exception:
                logger.exception("Unexpected MSD watcher error")
                await asyncio.sleep(1)

    async def __reload_state(self) -> None:
        async with self.__state._lock:  # pylint: disable=protected-access
            await self.__unsafe_reload_state()
        self.__notifier.notify()

    async def __reload_parts_info(self) -> None:
        assert self.__writer  # Использовать только при записи образа
        async with self.__state._lock:  # pylint: disable=protected-access
            await self.__storage.reload_parts_info()
        self.__notifier.notify()

    # ===== Don't call this directly ====

    async def __unsafe_reload_state(self) -> None:
        logger = get_logger(0)
        try:
            path = self.__drive.get_image_path()
            drive_state = _DriveState(
                image=((await self.__storage.make_image_by_path(path)) if path else None),
                cdrom=self.__drive.get_cdrom_flag(),
                rw=self.__drive.get_rw_flag(),
            )
            path_partition = self.__drive_partition.get_image_path()
            drive_state_partition = _DriveState(
                # 如果有镜像路径则创建镜像对象,否则为None
                image=((await self.__storage.make_image_by_path(path_partition)) if path_partition else None),
                cdrom=self.__drive_partition.get_cdrom_flag(), # 是否为CDROM模式
                rw=self.__drive_partition.get_rw_flag(), # 是否可写
            )

            await self.__storage.reload()

            if self.__state.vd is None and drive_state.image is None:
                # Если только что включились и образ не подключен - попробовать
                # перемонтировать хранилище (и создать images и meta).
                logger.info("Probing to remount storage ...")
                await self.__storage.remount_rw(True)
                await self.__storage.remount_rw(False)
                await self.__unsafe_setup_initial()

        except Exception:
            logger.exception("Error while reloading MSD state; switching to offline")
            self.__state.storage = None
            self.__state.vd = None

        else:
            self.__state.storage = self.__storage
            if drive_state.image:
                # При подключенном образе виртуальный стейт заменяется реальным
                self.__state.vd = _VirtualDriveState.from_drive_state(drive_state)
            else:
                if self.__state.vd is None:
                    # Если раньше MSD был отключен
                    self.__state.vd = _VirtualDriveState.from_drive_state(drive_state)

                image = self.__state.vd.image
                if image and (not image.in_storage or not (await image.exists())):
                    # Если только что отключили ручной образ вне хранилища или ранее выбранный образ был удален
                    self.__state.vd.image = None

                    self.__state.vd.connected = False

                if drive_state_partition.image:
                    self.__state.vd_partition = _VirtualDriveState.from_drive_state(drive_state_partition)
                else:
                    if self.__state.vd_partition is None:
                        self.__state.vd_partition = _VirtualDriveState.from_drive_state(drive_state_partition)

                    # 检测 partition 从 connected→disconnected 的转变（OTG 重建场景）
                    # 需要重新挂载分区回原挂载点，否则分区会处于未挂载的孤儿状态
                    was_connected = self.__state.vd_partition.connected
                    image = self.__state.vd_partition.image
                    if image and (not image.in_storage or not (await image.exists())):
                        self.__state.vd_partition.image = None
                    self.__state.vd_partition.connected = False

                    if was_connected:
                        # partition 之前是 connected 状态，现在 drive 路径已消失，需要重新挂载
                        partition_path = os.path.realpath(self.__partition_device)
                        mount_path = self.get_mount_path(partition_path)
                        if mount_path:
                            try:
                                logger.info("Partition was connected but drive disappeared, remounting %s to %s ...",
                                            partition_path, mount_path)
                                await aiohelpers.mount(partition_path, mount_path, "rw", cmd=["mount"])
                            except Exception:
                                logger.exception("Failed to remount partition %s to %s", partition_path, mount_path)
            self.__notifier.notify()

    async def __unsafe_setup_initial(self) -> None:
        if self.__initial_image:
            logger = get_logger(0)
            image = await self.__storage.make_image_by_name(self.__initial_image)
            if (await image.exists()):
                logger.info("Setting up initial image %r ...", self.__initial_image)
                try:
                    self.__drive.set_rw_flag(False)
                    self.__drive.set_cdrom_flag(self.__initial_cdrom)
                    self.__drive.set_image_path(image.path)
                except Exception:
                    logger.exception("Can't setup initial image: ignored")
            else:
                logger.error("Can't find initial image %r: ignored", self.__initial_image)
