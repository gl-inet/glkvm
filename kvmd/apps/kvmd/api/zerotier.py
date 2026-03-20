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
from typing import Dict, Optional
import json
import os
import re

from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger

logger = get_logger()


class ZerotierApi:
    __config_path = "/etc/kvmd/user/zerotier.json"
    
    def __init__(self) -> None:
        self._logger = logger

    async def _run_command(self, cmd: str) -> str:
        """
        执行系统命令
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                self._logger.error(f"Command failed: {stderr.decode()}")
                raise BadRequestError(f"Command failed: {stderr.decode()}")
            return stdout.decode().strip()
        except Exception as e:
            self._logger.error(f"Error executing command: {e}")
            raise BadRequestError(f"Error executing command: {e}")

    async def _check_zerotierd_process(self) -> bool:
        """
        检查 zerotierd 进程是否存在
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "pgrep", "-f", "zerotier-one",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return process.returncode == 0
        except Exception as e:
            self._logger.error(f"Error checking zerotierd process: {e}")
            return False

    async def _read_config_file(self) -> Dict:
        """
        读取配置文件
        """
        config_path = self.__config_path
        
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
                return config
            else:
                # 如果配置文件不存在，返回默认配置
                return {
                    "enable": False,
                    "token": ""
                }
        except Exception as e:
            self._logger.error(f"Failed to read config file {config_path}: {e}")
            return {
                "enable": False,
                "token": ""
            }

    async def _update_config_file(self, enable: Optional[bool] = None, token: Optional[str] = None) -> None:
        """
        更新配置文件
        
        Args:
            enable: True表示启用，False表示禁用，None表示不更改
            token: 新的token值，None表示不更改
        """
        config_path = self.__config_path
        config_dir = os.path.dirname(config_path)
        
        # 确保目录存在
        try:
            os.makedirs(config_dir, exist_ok=True)
        except Exception as e:
            self._logger.error(f"Failed to create config directory {config_dir}: {e}")
            raise BadRequestError(f"Failed to create config directory: {e}")
        
        # 读取现有配置
        config = await self._read_config_file()
        
        # 更新配置
        if enable is not None:
            config["enable"] = enable
        if token is not None:
            config["token"] = token
        
        # 写入配置文件
        try:
            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)
            await asyncio.create_subprocess_shell("sync")
                
            self._logger.info(f"Updated zerotier config file: enable={config.get('enable')}")
        except Exception as e:
            self._logger.error(f"Failed to write config file {config_path}: {e}")
            raise BadRequestError(f"Failed to write config file: {e}")

    async def _parse_listnetworks(self) -> Optional[Dict]:
        """
        解析 zerotier-cli listnetworks 命令输出（JSON格式）
        返回网络信息字典，如果没有网络则返回None
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "zerotier-cli", "-j", "listnetworks",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                self._logger.error(f"zerotier-cli listnetworks failed: {stderr.decode()}")
                return None

            output = stdout.decode().strip()

            # 解析JSON输出
            networks = json.loads(output)

            # 如果没有网络，返回None
            if not networks or len(networks) == 0:
                return None

            # 返回第一个网络的信息
            network = networks[0]
            return {
                "nwid": network.get("nwid", ""),
                "name": network.get("name", ""),
                "mac": network.get("mac", ""),
                "status": network.get("status", ""),
                "type": network.get("type", ""),
                "dev": network.get("portDeviceName", ""),
                "ips": network.get("assignedAddresses", [])
            }

        except json.JSONDecodeError as e:
            self._logger.error(f"Error parsing zerotier JSON output: {e}")
            return None
        except Exception as e:
            self._logger.error(f"Error parsing zerotier listnetworks: {e}")
            return None

    async def _leave_all_networks(self) -> None:
        """
        断开所有已连接的 ZeroTier 网络
        通过停止服务、删除数据目录并重启服务来实现
        """
        try:
            self._logger.info("Leaving all networks by resetting ZeroTier service")

            # 1. 停止 ZeroTier 服务
            try:
                process = await asyncio.create_subprocess_shell(
                    "/etc/init.d/S99zerotier stop",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    self._logger.warning(f"Stop ZeroTier service failed: {stderr.decode()}")
                else:
                    self._logger.info(f"ZeroTier service stopped: {stdout.decode().strip()}")
            except Exception as e:
                self._logger.error(f"Error stopping ZeroTier service: {e}")

            # 等待服务完全停止
            await asyncio.sleep(1)

            # 2. 删除 ZeroTier 用户数据目录
            try:
                process = await asyncio.create_subprocess_shell(
                    "rm -rf /etc/kvmd/user/zerotier",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    self._logger.warning(f"Remove ZeroTier data directory failed: {stderr.decode()}")
                else:
                    self._logger.info("ZeroTier data directory removed")
            except Exception as e:
                self._logger.error(f"Error removing ZeroTier data directory: {e}")

            # 3. 重启 ZeroTier 服务
            try:
                process = await asyncio.create_subprocess_shell(
                    "/etc/init.d/S99zerotier start",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    self._logger.warning(f"Start ZeroTier service failed: {stderr.decode()}")
                else:
                    self._logger.info(f"ZeroTier service started: {stdout.decode().strip()}")
            except Exception as e:
                self._logger.error(f"Error starting ZeroTier service: {e}")

            # 等待服务完全启动
            await asyncio.sleep(4)

            self._logger.info("Network reset completed")

        except Exception as e:
            self._logger.error(f"Error leaving networks: {e}")

    @exposed_http("GET", "/zerotier/status")
    async def _status_handler(self, _: Request) -> Response:
        """
        获取 zerotier 服务状态
        通过 zerotier-cli listnetworks 获取详细的网络状态
        """
        try:
            # 读取配置文件获取启动状态
            config = await self._read_config_file()
            enabled = config.get("enable", False)

            # 检查进程状态
            process_running = await self._check_zerotierd_process()

            # 获取网络详细信息
            network_info = None
            if process_running:
                network_info = await self._parse_listnetworks()

            response_data = {
                "enabled": enabled,
                "process_running": process_running
            }

            # 如果有网络信息，添加详细状态
            if network_info:
                response_data.update({
                    "nwid": network_info["nwid"],
                    "name": network_info["name"],
                    "status": network_info["status"],
                    "dev": network_info["dev"],
                    "ips": network_info["ips"]
                })

            return make_json_response(response_data)
        except Exception as e:
            self._logger.error(f"Error checking zerotier status: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/zerotier/start")
    async def _start_handler(self, _: Request) -> Response:
        """
        启动 zerotier 服务
        """
        try:
            # 更新配置文件
            await self._update_config_file(enable=True)
            
            # 启动服务
            cmd = "/etc/init.d/S99zerotier start"
            output = await self._run_command(cmd)
            
            # 等待服务启动
            await asyncio.sleep(2)
            
            # 检查服务是否真的启动了
            process_running = await self._check_zerotierd_process()
            
            return make_json_response({
                "success": process_running,
                "output": output,
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error starting zerotier service: {e}")
            await self._update_config_file(enable=False)
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/zerotier/stop")
    async def _stop_handler(self, _: Request) -> Response:
        """
        停止 zerotier 服务
        """
        try:
            # 更新配置文件
            await self._update_config_file(enable=False)
            
            # 停止服务
            cmd = "/etc/init.d/S99zerotier stop"
            output = await self._run_command(cmd)
            
            # 等待服务停止
            await asyncio.sleep(2)
            
            # 检查服务是否真的停止了
            process_running = await self._check_zerotierd_process()
            
            return make_json_response({
                "success": not process_running,
                "output": output,
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error stopping zerotier service: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/zerotier/set_token")
    async def _set_token_handler(self, request: Request) -> Response:
        """
        设置 zerotier token
        接受参数：
        - token: 字符串，zerotier token（仅允许大小写字母和数字）
        """
        try:
            # 从请求中获取token参数
            token = request.query.get("token", None)

            # 检查token参数
            if token is None:
                return make_json_exception(BadRequestError("Token parameter is required"), 400)

            # Token 注入检测：只允许大小写字母和数字，防止命令注入攻击
            if not re.match(r'^[a-zA-Z0-9]+$', token):
                self._logger.warning(f"Invalid token format detected, possible injection attempt: {token}")
                return make_json_exception(
                    BadRequestError("Invalid token format. Only alphanumeric characters (a-z, A-Z, 0-9) are allowed."),
                    400
                )

            # 检查token长度（ZeroTier网络ID通常是16位十六进制）
            if len(token) < 8 or len(token) > 32:
                self._logger.warning(f"Token length out of acceptable range: {len(token)}")
                return make_json_exception(
                    BadRequestError("Invalid token length. Token must be between 8 and 32 characters."),
                    400
                )

            # 在设置新token之前，先断开所有已连接的网络
            self._logger.info("Leaving all existing networks before setting new token")
            await self._leave_all_networks()

            # 调用zerotier-cli join命令，最多重试3次
            max_retries = 3
            retry_delay = 1  # 秒

            for attempt in range(1, max_retries + 1):
                try:
                    join_cmd = f"zerotier-cli join {token}"
                    join_output = await self._run_command(join_cmd)
                    self._logger.info(f"Zerotier join command executed successfully on attempt {attempt}: {join_output}")

                    # 不再需要更新配置文件中的token
                    # await self._update_config_file(token=token)

                    return make_json_response({
                        "success": True,
                        "message": "Token updated successfully",
                        "join_output": join_output,
                        "attempts": attempt
                    })
                except Exception as join_error:
                    self._logger.warning(f"Zerotier join attempt {attempt}/{max_retries} failed: {join_error}")

                    if attempt < max_retries:
                        # 如果不是最后一次尝试，等待1秒后重试
                        self._logger.info(f"Retrying in {retry_delay} second(s)...")
                        await asyncio.sleep(retry_delay)
                    else:
                        # 最后一次尝试也失败了，返回错误
                        self._logger.error(f"All {max_retries} join attempts failed")
                        return make_json_exception(BadRequestError(f"Join command failed after {max_retries} attempts: {join_error}"), 502)

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting zerotier token: {e}")
            return make_json_exception(BadRequestError(), 502) 