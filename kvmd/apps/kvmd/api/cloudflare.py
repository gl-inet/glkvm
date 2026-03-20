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

from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger

logger = get_logger()


class CloudflareApi:
    __config_path = "/etc/kvmd/user/cloudflare.json"
    
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

    async def _check_cloudflared_process(self) -> bool:
        """
        检查 cloudflared 进程是否存在
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "pgrep", "-f", "cloudflared",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return process.returncode == 0
        except Exception as e:
            self._logger.error(f"Error checking cloudflared process: {e}")
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
                
            self._logger.info(f"Updated Cloudflare config file: enable={config.get('enable')}, token_set={bool(config.get('token'))}")
        except Exception as e:
            self._logger.error(f"Failed to write config file {config_path}: {e}")
            raise BadRequestError(f"Failed to write config file: {e}")

    @exposed_http("GET", "/cloudflare/status")
    async def _status_handler(self, _: Request) -> Response:
        """
        获取 Cloudflare 服务状态
        返回启动状态和进程状态
        """
        try:
            # 读取配置文件获取启动状态
            config = await self._read_config_file()
            enabled = config.get("enable", False)
            
            # 检查进程状态
            process_running = await self._check_cloudflared_process()
            
            return make_json_response({
                "enabled": enabled,
                "process_running": process_running,
                "token_set": bool(config.get("token"))
            })
        except Exception as e:
            self._logger.error(f"Error checking Cloudflare status: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/cloudflare/start")
    async def _start_handler(self, _: Request) -> Response:
        """
        启动 Cloudflare 服务
        """
        try:
            # 更新配置文件
            await self._update_config_file(enable=True)
            
            # 启动服务
            cmd = "/etc/init.d/S99cloudflare start"
            output = await self._run_command(cmd)
            
            # 等待服务启动
            await asyncio.sleep(2)
            
            # 检查服务是否真的启动了
            process_running = await self._check_cloudflared_process()
            
            return make_json_response({
                "success": process_running,
                "output": output,
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error starting Cloudflare service: {e}")
            await self._update_config_file(enable=False)
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/cloudflare/stop")
    async def _stop_handler(self, _: Request) -> Response:
        """
        停止 Cloudflare 服务
        """
        try:
            # 更新配置文件
            await self._update_config_file(enable=False)
            
            # 停止服务
            cmd = "/etc/init.d/S99cloudflare stop"
            output = await self._run_command(cmd)
            
            # 等待服务停止
            await asyncio.sleep(2)
            
            # 检查服务是否真的停止了
            process_running = await self._check_cloudflared_process()
            
            return make_json_response({
                "success": not process_running,
                "output": output,
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error stopping Cloudflare service: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/cloudflare/set_token")
    async def _set_token_handler(self, request: Request) -> Response:
        """
        设置 Cloudflare token
        接受参数：
        - token: 字符串，Cloudflare token
        """
        try:
            # 从请求中获取token参数
            token = request.query.get("token", None)
            
            # 检查token参数
            if token is None:
                return make_json_response({
                    "success": False,
                    "error": "Token parameter is required"
                })
            
            # 更新配置文件中的token
            await self._update_config_file(token=token)
            
            # 重启Cloudflare服务以应用新的token
            cmd = "/etc/init.d/S99cloudflare restart"
            output = await self._run_command(cmd)
            
            # 检查服务是否正常运行
            process_running = await self._check_cloudflared_process()
            
            return make_json_response({
                "success": True,
                "message": "Token updated successfully",
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting Cloudflare token: {e}")
            return make_json_exception(BadRequestError(), 502) 