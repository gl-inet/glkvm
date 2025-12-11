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
from .. import BaseMsd
from .. import MsdFileReader
from .. import MsdFileWriter

from .storage import Image
from .storage import Storage
from .drive import Drive

from asyncio import create_subprocess_exec
import subprocess
import yaml


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
    mount_dict = {
        "/dev/mmcblk0p10": "/userdata/media",
        "/dev/block/by-name/media": "/userdata/media",
    }

    def get_mount_path(self, device_path: str) -> str:

        if device_path in self.mount_dict:
            return self.mount_dict[device_path]


        if device_path.startswith("/dev/sd"):
            return "/mnt/sdcard/"


        return None

    def __notify_remount(self) -> None:

        logger = get_logger(0)
        logger.info("Partition remount detected, notifying systask to reinitialize inotify...")
        self.__reset = True
        self.__notifier.notify(1)

    async def partition_remount(self) -> None:

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





        self.__drive = Drive(gadget, instance=0, lun=0)
        self.__drive_partition = Drive(gadget, instance=1, lun=0)



        aiotools.run_sync(self.partition_remount())





        self.__storage = Storage(self.get_mount_path(self.__partition_device), remount_cmd)

        self.__reader: (MsdFileReader | None) = None
        self.__writer: (MsdFileWriter | None) = None

        self.__notifier = aiotools.AioNotifier()
        self.__state = _State(self.__notifier)
        self.__reset = False

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



    async def get_state(self) -> dict:

        async with self.__state._lock:  # pylint: disable=protected-access
            storage: (dict | None) = None
            if self.__state.storage:
                assert self.__state.vd






                await self.__storage.reload_parts_info()


                storage = dataclasses.asdict(self.__state.storage)

                for name in list(storage["images"]):
                    del storage["images"][name]["name"]
                    del storage["images"][name]["path"]
                    del storage["images"][name]["in_storage"]
                for name in list(storage["parts"]):
                    del storage["parts"][name]["name"]


                storage["downloading"] = (self.__reader.get_state() if self.__reader else None)
                storage["uploading"] = (self.__writer.get_state() if self.__writer else None)


            vd: (dict | None) = None
            if self.__state.vd:
                assert self.__state.storage
                vd = dataclasses.asdict(self.__state.vd)

                if vd["image"]:
                    del vd["image"]["path"]

            vd_partition: (dict | None) = None
            if self.__state.vd_partition:
                vd_partition = dataclasses.asdict(self.__state.vd_partition)
                if vd_partition["image"]:
                    del vd_partition["image"]["path"]


            available_devices = await self.partition_show()


            return {
                "enabled": True,
                "online": (bool(vd) and self.__drive.is_enabled()),
                "busy": self.__state.is_busy(),
                "storage": storage,
                "drive": vd,
                "drive_partition": vd_partition,
                "available_devices": available_devices,
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


    @aiotools.atomic_fg
    async def set_connected(self, connected: bool) -> None:
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







        uuid = ""
        filesystem = ""
        label = ""



        pattern = r'(\w+)=(?:"([^"]*)"|([^\s]+))'
        matches = re.findall(pattern, output)

        parsed_data = {}
        for match in matches:
            key = match[0]

            value = match[1] if match[1] else match[2]
            parsed_data[key] = value


        if "UUID" in parsed_data:
            uuid = parsed_data["UUID"]


        if "TYPE" in parsed_data:
            filesystem = parsed_data["TYPE"]


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


            parsed_info = self.__parse_blkid_output(output)
            uuid = parsed_info["uuid"]
            filesystem = parsed_info["filesystem"]
            label = parsed_info["label"]

        except Exception as e:
            get_logger(0).error(f"Failed to get UUID, filesystem type and label for {dev_path}: {e}")

        return {
            "size": size_kb * 1024,
            "uuid": uuid,
            "filesystem": filesystem,
            "label": label
        }


    @aiotools.atomic_fg
    async def partition_show(self) -> dict[str, dict]:
        devices = {}

        current_partition = os.path.realpath(self.__partition_device)


        try:
            with open("/proc/partitions", "r") as f:
                lines = f.readlines()

                for line in lines[2:]:
                    parts = line.strip().split()
                    if len(parts) == 4:
                        dev_name = parts[3]
                        size_kb = int(parts[2])

                        if dev_name.startswith("sd"):
                            disk_name = dev_name.rstrip("0123456789")

                            try:







                                if len(dev_name) > len(disk_name):
                                    dev_path = f"/dev/{dev_name}"
                                    partition_info = await self.__get_partition_info(dev_path, size_kb)

                                    partition_info["is_current"] = (dev_path == current_partition)
                                    devices[dev_path] = partition_info
                            except (IOError, OSError):
                                continue
                        if dev_name.startswith("mmcblk0p10"):
                            dev_path = f"/dev/{dev_name}"
                            partition_info = await self.__get_partition_info(dev_path, size_kb)

                            partition_info["is_current"] = (dev_path == current_partition)
                            devices[dev_path] = partition_info
        except (IOError, OSError) as e:
            get_logger(0).error(f"Error reading partitions: {str(e)}")

        logger = get_logger(0)
        logger.info(f"Found {len(devices)} USB devices {devices}")
        return devices

    @aiotools.atomic_fg
    async def partition_connect(self) -> None:
        async with self.__state.busy():
            assert self.__state.vd_partition

            await aiotools.run_async(os.sync)

            path = self.__partition_device

            if path.startswith("/dev/"):

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




        logger = get_logger(0)
        trash_dirs = [".Trashes", "$RECYCLE.BIN", ".Trash-1000"]
        for trash_dir in trash_dirs:

            for root, dirs, _ in os.walk(mount_path):

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




        logger = get_logger(0)

        try:

            current_partition_device = self.__partition_device
            logger.info(f"current_partition_device: {current_partition_device}")


            real_device_path = os.path.realpath(device_path)


            new_uuid = await self.__get_device_uuid(real_device_path)

            if not new_uuid:
                logger.warning(f"Could not get UUID for {real_device_path}, skipping UUID update")
                return


            new_uuid_path = f"/dev/disk/by-uuid/{new_uuid}"


            if current_partition_device.startswith("/dev/disk/by-uuid/"):

                old_uuid = os.path.basename(current_partition_device)

                if old_uuid != new_uuid:
                    logger.info(f"UUID changed: {old_uuid} -> {new_uuid}, updating configuration")


                    boot_config = await self.__read_boot_yaml()


                    if "kvmd" not in boot_config:
                        boot_config["kvmd"] = {}
                    if "msd" not in boot_config["kvmd"]:
                        boot_config["kvmd"]["msd"] = {}
                    boot_config["kvmd"]["msd"]["partition_device"] = new_uuid_path


                    await self.__write_boot_yaml(boot_config)


                    self.__partition_device = new_uuid_path


                    self.__state.vd_partition.image = await self.__storage.make_image_by_path(new_uuid_path)

                    logger.info(f"Successfully updated partition_device to {new_uuid_path}")
                else:
                    logger.info(f"UUID unchanged: {new_uuid}")
            elif os.path.realpath(current_partition_device) == real_device_path:

                logger.info(f"Converting partition_device from {current_partition_device} to UUID path {new_uuid_path}")


                boot_config = await self.__read_boot_yaml()


                if "kvmd" not in boot_config:
                    boot_config["kvmd"] = {}
                if "msd" not in boot_config["kvmd"]:
                    boot_config["kvmd"]["msd"] = {}
                boot_config["kvmd"]["msd"]["partition_device"] = new_uuid_path


                await self.__write_boot_yaml(boot_config)


                self.__partition_device = new_uuid_path


                self.__state.vd_partition.image = await self.__storage.make_image_by_path(new_uuid_path)

                logger.info(f"Successfully converted partition_device to UUID path {new_uuid_path}")

        except Exception as e:
            logger.error(f"Failed to check and update UUID: {e}")


    @aiotools.atomic_fg
    async def partition_disconnect(self) -> None:
        async with self.__state.busy():
            assert self.__state.vd_partition
            path = self.__drive_partition.get_image_path()
            get_logger(0).info(f"path: {path}")
            if not path or path.strip() == "":


                path = os.path.realpath(self.__state.vd_partition.image.path)

            self.__drive_partition.set_image_path("")
            await asyncio.sleep(1)
            self.__state.vd_partition.connected = False


            remounted = False
            if path.startswith("/dev/"):
                mount_path = self.get_mount_path(path)
                if mount_path:
                    try:
                        get_logger(0).info(f"Mounting {path} to {mount_path}")
                        await aiohelpers.mount(path, mount_path, "rw",cmd = ["mount"])
                        remounted = True


                        await self.__clean_trash_dirs(mount_path)


                        await self.__check_and_update_uuid_if_changed(path)

                    except Exception as e:
                        get_logger(0).error(f"Failed to remount partition {path} to {mount_path}: {e}")


        if remounted:
            self.__notify_remount()


        await self.__reload_state()

    @aiotools.atomic_fg
    async def __do_format(self,path: str = "") -> None:

        if not path or path.strip() == "":
            path = self.__partition_device


        real_path = os.path.realpath(path)


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

            get_logger(0).info(f"Umounting {path}")
            await aiohelpers.umount(path)


            get_logger(0).info(f"Formatting {path}")
            if not await self.__run_command("mkfs.exfat", [real_path], "mkfs.exfat command failed"):
                raise Exception("Failed to format partition")


            if old_label:
                get_logger(0).info(f"Restoring volume label: {old_label}")
                if not await self.__run_command("exfatlabel", [real_path, old_label], "exfatlabel command failed"):
                    get_logger(0).warning("Failed to restore volume label, write GLKVM in label instead")

                    if not await self.__run_command("exfatlabel", [real_path, "GLKVM"], "exfatlabel command failed"):
                        get_logger(0).error("Failed to write GLKVM in label")


            new_uuid = await self.__get_device_uuid(real_path)

            if new_uuid:

                try:
                    boot_config = await self.__read_boot_yaml()


                    new_uuid_path = f"/dev/disk/by-uuid/{new_uuid}"


                    if "kvmd" not in boot_config:
                        boot_config["kvmd"] = {}
                    if "msd" not in boot_config["kvmd"]:
                        boot_config["kvmd"]["msd"] = {}
                    boot_config["kvmd"]["msd"]["partition_device"] = new_uuid_path


                    await self.__write_boot_yaml(boot_config)


                    self.__partition_device = new_uuid_path

                    get_logger(0).info(f"Updated partition_device to {new_uuid_path} in boot.yaml")
                except Exception as e:
                    get_logger(0).error(f"Failed to update boot.yaml with new UUID: {e}")

            else:
                get_logger(0).warning("Could not get new UUID after formatting, partition_device not updated")


            mount_path = self.get_mount_path(real_path)
            if mount_path:
                await aiohelpers.mount(real_path, mount_path, "rw", cmd=["mount"])
                remounted = True
        except Exception as e:
            get_logger(0).error(f"Failed to umount or format partition: {e}")
            raise


        if remounted:
            self.__notify_remount()

    @aiotools.atomic_fg
    async def partition_format(self, path: str = "") -> None:
        if path is None or path.strip() == "":
            async with self.__state.busy():
                await self.__do_format(self.__partition_device)
        else:
            await self.__do_format(path)

        await self.__reload_state()


    @contextlib.asynccontextmanager
    async def read_image(self, name: str) -> AsyncGenerator[MsdFileReader, None]:
        try:
            with self.__state._region:
                try:
                    async with self.__state._lock:  # pylint: disable=protected-access
                        self.__notifier.notify()
                        self.__STATE_check_disconnected()

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
        image: (Image | None) = None
        complete = False

        async def finish_writing() -> None:


            async with self.__state._lock:
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

                            await self.__close_writer()




        try:
            with self.__state._region:
                try:
                    async with self.__state._lock:  # pylint: disable=protected-access
                        self.__notifier.notify()
                        self.__STATE_check_disconnected()

                        image = await self.__STORAGE_create_new_image(name)

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
        async with self.__state.busy():
            assert self.__state.storage
            assert self.__state.vd
            self.__STATE_check_disconnected()
            image = await self.__STATE_get_storage_image(name)

            if self.__state.vd.image == image:
                self.__state.vd.image = None


            try:
                await image.remove(fatal=True)
            finally:

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



                    await inotify.watch_all_changes(*self.__storage.get_watchable_paths())
                    await inotify.watch_all_changes(*self.__drive.get_watchable_paths())

                    await inotify.watch_create_and_delete("/dev")



                    await self.__reload_state()

                    while self.__state.vd:  # Если живы после предыдущей проверки
                        need_restart = self.__reset
                        self.__reset = False
                        need_reload_state = False
                        for event in (await inotify.get_series(timeout=1)):

                            if (event.path.startswith("/dev") and event.name and
                                event.name.startswith("sd") and len(event.name) > 3):

                                logger.info("Detected USB device change: %s", event.path)
                                need_reload_state = True
                            elif not event.path.startswith("/dev"):

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


                            await self.__reload_parts_info()

            except Exception:
                logger.exception("Unexpected MSD watcher error")
                await asyncio.sleep(1)

    async def __reload_state(self) -> None:
        async with self.__state._lock:  # pylint: disable=protected-access
            await self.__unsafe_reload_state()
        self.__notifier.notify()

    async def __reload_parts_info(self) -> None:
        assert self.__writer
        async with self.__state._lock:
            await self.__storage.reload_parts_info()
        self.__notifier.notify()



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

                image=((await self.__storage.make_image_by_path(path_partition)) if path_partition else None),
                cdrom=self.__drive_partition.get_cdrom_flag(),
                rw=self.__drive_partition.get_rw_flag(),
            )

            await self.__storage.reload()

            if self.__state.vd is None and drive_state.image is None:


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

                self.__state.vd = _VirtualDriveState.from_drive_state(drive_state)
            else:
                if self.__state.vd is None:

                    self.__state.vd = _VirtualDriveState.from_drive_state(drive_state)

                image = self.__state.vd.image
                if image and (not image.in_storage or not (await image.exists())):

                    self.__state.vd.image = None

                    self.__state.vd.connected = False

                if drive_state_partition.image:
                    self.__state.vd_partition = _VirtualDriveState.from_drive_state(drive_state_partition)
                else:
                    if self.__state.vd_partition is None:
                        self.__state.vd_partition = _VirtualDriveState.from_drive_state(drive_state_partition)
                    image = self.__state.vd_partition.image
                    if image and (not image.in_storage or not (await image.exists())):
                        self.__state.vd_partition.image = None
                    self.__state.vd_partition.connected = False
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
