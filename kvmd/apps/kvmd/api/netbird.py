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
import subprocess
import re
from typing import Dict, Optional, List
import threading
import time
import json
import os
import ipaddress
from urllib.parse import urlparse

from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    UnavailableError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger

logger = get_logger()

class NetbirdApi:
    __config_path = "/etc/kvmd/user/netbird.json"
    def __init__(self) -> None:
        self._logger = logger
        self.login_status = None
        self._background_tasks: set = set()  # 防止后台任务被 GC 回收

    async def _run_command(self, cmd: str):
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd.split(),
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            stdout_str = stdout.decode().strip()
            stderr_str = stderr.decode().strip()

            if process.returncode != 0:
                self._logger.error(f'{cmd} error: {stderr_str}')
                return stderr_str
            else:
                self._logger.info(f'{cmd} success: {stdout_str}')
                return stdout_str
        except Exception as e:
            self._logger.error(f'{cmd} except: {e}')
            return str(e)

    async def is_netbird_running(self) -> bool:
        try:
            process = await asyncio.create_subprocess_exec(
                "ps", "-ef",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await process.communicate()
            for line in stdout.decode().splitlines():
                if "netbird" in line and "grep" not in line:
                    return True
            return False
        except Exception as e:
            self._logger.error(f"is_netbird_running except: {e}")
            return False

    _SETUP_KEY_PATTERN = re.compile(r'^[0-9A-Za-z\-]+$')

    def _validate_setup_key(self, key: str) -> bool:
        return bool(self._SETUP_KEY_PATTERN.match(key))

    async def _get_login_url(self, setup_key: Optional[str] = None):
        config = await self._read_config_file()
        management_url = config.get("management_url", "")
        cmd_args = ["netbird", "up", "--disable-dns"]
        if setup_key:
            cmd_args += ["--setup-key", setup_key]
        if management_url:
            cmd_args += ["--management-url", management_url]
        # key 不出现在日志里
        cmd = "netbird up --disable-dns" + (" --setup-key [REDACTED]" if setup_key else "") + (f" --management-url {management_url}" if management_url else "")

        process = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout = subprocess.PIPE,
            stderr = subprocess.STDOUT
        )

        ret = None

        while True:
            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=30.0)

                if not line:
                    break

                ret = line.decode().strip()
                if 'https://' in ret:
                    break

            except asyncio.TimeoutError:
                self._logger.error(f'{cmd} except: Timeout')
                break
            except Exception as e:
                self._logger.error(f'get_login_url except: {e}')
                break

        # 不主动终止子进程，让 netbird up 自然结束
        # 创建后台任务等待进程退出并清理资源
        async def _wait_process():
            try:
                # 继续读取剩余输出，防止管道阻塞
                while True:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=120.0)
                    if not line:
                        break
                await process.wait()
                self._logger.info(f'{cmd} process exited with code {process.returncode}')
            except asyncio.TimeoutError:
                self._logger.warning(f'{cmd} background wait timed out, killing process')
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            except Exception as e:
                self._logger.error(f'{cmd} background wait error: {e}')

        task = asyncio.create_task(_wait_process())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return ret

    async def netbird_is_running(self) -> bool:
        """
        检查 netbird 进程是否存在
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "pidof", "netbird",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return process.returncode == 0
        except Exception as e:
            self._logger.error(f"Error checking netbird process: {e}")
            return False

    async def _read_config_file(self) -> dict:
        config_path = self.__config_path
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
                config.setdefault("enable", False)
                config.setdefault("management_url", "")
                return config
        except Exception as e:
            self._logger.error(f"Failed to read config file {config_path}: {e}")
        return {"enable": False, "management_url": ""}

    async def _update_config_file(self, enable: Optional[bool] = None, management_url: Optional[str] = None) -> None:
        """
        更新Netbird配置文件

        Args:
            enable: True表示启用Netbird，False表示禁用，None表示不修改
            management_url: 自部署管理服务器URL，None表示不修改，空字符串表示使用官方默认
        """
        config_path = self.__config_path
        config_dir = os.path.dirname(config_path)

        # 确保目录存在
        try:
            os.makedirs(config_dir, exist_ok=True)
        except Exception as e:
            self._logger.error(f"Failed to create config directory {config_dir}: {e}")
            raise BadRequestError(f"Failed to create config directory: {e}")

        # 写入配置文件
        try:
            config = await self._read_config_file()
            if enable is not None:
                config["enable"] = enable
            if management_url is not None:
                config["management_url"] = management_url

            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)
            await asyncio.create_subprocess_shell("sync")

            self._logger.info(f"Updated Netbird config file: enable={config.get('enable')}, management_url={config.get('management_url')}")
        except Exception as e:
            self._logger.error(f"Failed to write config file {config_path}: {e}")
            raise BadRequestError(f"Failed to write config file: {e}")

    @exposed_http("POST", "/netbird/start")
    async def _netbird_start(self, _: Request) -> Response:
        """
        启动 Netbird 服务
        """
        try:
            # 写入配置
            await self._update_config_file(True)

            # 启动服务
            cmd = "/etc/init.d/S99netbird start"
            output = await self._run_command(cmd)
            # 等待服务启动
            await asyncio.sleep(2)
            # 检查服务是否真的启动了
            running = await self.netbird_is_running()
            return make_json_response({
                "success": running,
                "err_msg": "" if running else output,
                "running": running
            })
        except BadRequestError as e:
            return make_json_exception(e, 500)
        except Exception as e:
            self._logger.error(f"Error starting Netbird service: {e}")
            return make_json_exception(BadRequestError(), 500)

    @exposed_http("POST", "/netbird/stop")
    async def _netbird_stop(self, _: Request) -> Response:
        """
        停止 Netbird 服务
        """
        try:
            # 写入配置
            await self._update_config_file(False)

            # 停止服务
            cmd = "/etc/init.d/S99netbird stop"
            output = await self._run_command(cmd)
            running = await self.netbird_is_running()
            return make_json_response({
                "success": not running,
                "err_msg": "" if not running else output,
                "running": running
            })
        except BadRequestError as e:
            return make_json_exception(e, 500)
        except Exception as e:
            self._logger.error(f"Error stopping Netbird service: {e}")
            return make_json_exception(BadRequestError(), 500)

    @exposed_http("POST", "/netbird/login")
    async def _netbird_login(self, request: Request) -> Response:
        """
        Netbird 登录接口，支持两种方式：
          1. 传入 setup_key（格式：XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX）→ 直接用 setup key 连接，
             key 不会写入日志或磁盘。
          2. 不传 setup_key → 执行 netbird up，返回 OAuth 登录 URL 供用户在浏览器中完成授权。

        请求参数（query string 或 JSON body 均可）：
          - setup_key（可选）：Netbird setup key
        """
        if not await self.netbird_is_running():
            return make_json_response({"err_msg": "netbird process is not running", "success": False, "login_url": "", "login_type": ""})

        # 尝试从 query string 或 JSON body 中读取 setup_key
        setup_key: Optional[str] = request.query.get("setup_key", None)
        if setup_key is None:
            try:
                body = await request.json()
                setup_key = body.get("setup_key", None)
            except Exception:
                pass

        login_type = "setup_key" if setup_key is not None else "oauth"

        if setup_key is not None:
            setup_key = setup_key.strip()
            if not self._validate_setup_key(setup_key):
                return make_json_response({
                    "success": False,
                    "err_msg": "Invalid setup_key format. Only letters, digits and hyphens are allowed.",
                    "login_url": "",
                    "login_type": login_type,
                })

        try:
            ret = await self._get_login_url(setup_key)
            if ret and 'https://' in ret:
                return make_json_response({"success": True, "err_msg": "", "login_url": ret, "login_type": login_type})
            else:
                self.login_status = True
                return make_json_response({"success": True, "err_msg": "", "login_url": "", "login_type": login_type})
        except Exception as e:
            self._logger.error(f'except: {e}')
            return make_json_exception(BadRequestError(), 500)

    @exposed_http("POST", "/netbird/logout")
    async def _netbird_logout(self, _: Request) -> Response:
        if not await self.netbird_is_running():
            return make_json_response({"err_msg": "netbird process is not running", "success": False})

        try:
            cmd = 'netbird logout'
            cmd_ret = await self._run_command(cmd)
            self.login_status = False
            return make_json_response({"success": True, "err_msg": ""})
        except Exception as e:
            self._logger.error(f'except: {e}')
            return make_json_exception(BadRequestError(), 500)

    @exposed_http("GET", "/netbird/config")
    async def _netbird_get_config(self, _: Request) -> Response:
        try:
            config = await self._read_config_file()
            return make_json_response({
                "enable": config.get("enable", False),
                "management_url": config.get("management_url", ""),
            })
        except Exception as e:
            self._logger.error(f"Error reading Netbird config: {e}")
            return make_json_exception(BadRequestError(), 500)

    @exposed_http("POST", "/netbird/config")
    async def _netbird_set_config(self, request: Request) -> Response:
        """
        设置 Netbird management_url（支持自部署服务器）
        参数：management_url（query string），为空表示恢复官方默认服务器
        """
        try:
            management_url = request.query.get("management_url", None)
            if management_url is None:
                return make_json_response({
                    "success": False,
                    "err_msg": "management_url parameter is required",
                })

            management_url = management_url.strip()
            if management_url:
                if not management_url.startswith("https://"):
                    return make_json_response({
                        "success": False,
                        "err_msg": "Invalid management_url: must start with https:// or be empty",
                    })
                parsed = urlparse(management_url)
                hostname = parsed.hostname or ""
                try:
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                        return make_json_response({
                            "success": False,
                            "err_msg": "Invalid management_url: internal/reserved IP addresses are not allowed",
                        })
                except ValueError:
                    pass  # hostname is a domain name, not an IP address

            await self._update_config_file(management_url=management_url)
            return make_json_response({
                "success": True,
                "management_url": management_url,
            })
        except BadRequestError as e:
            return make_json_exception(e, 500)
        except Exception as e:
            self._logger.error(f"Error setting Netbird config: {e}")
            return make_json_exception(BadRequestError(), 500)

    @exposed_http("GET", "/netbird/get_info")
    async def _netbird_get_info(self, _: Request) -> Response:
        running = await self.netbird_is_running()

        if not running:
            return make_json_response({
                "running": False,
                "netbird_ip": "",
                "connected": False,
                "success": True,
                "err_msg": "",
            })

        cmd = 'netbird status --json'
        cmd_ret = await self._run_command(cmd)

        try:
            if 'Daemon status:' in cmd_ret:
                return make_json_response({
                    "running": True,
                    "netbird_ip": "",
                    "connected": False,
                    "success": False,
                    "err_msg": "netbird not logged in",
                })
            else:
                status, _ = json.JSONDecoder().raw_decode(cmd_ret.strip())
                netbird_ip = status.get("netbirdIp", "")
                management = status.get("management") or {}
                connected = management.get("connected", False)
                return make_json_response({
                    "running": True,
                    "netbird_ip": netbird_ip,
                    "connected": connected,
                    "success": True,
                    "err_msg": "",
                })
        except Exception as e:
            self._logger.error(f'except: {e}')
            return make_json_exception(UnavailableError(), 503)
