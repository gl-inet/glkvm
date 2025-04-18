




















import asyncio
import subprocess
from typing import Dict, Optional, List
import threading
import time
import json
import os
import ipaddress

from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger

logger = get_logger()


class TailscaleApi:
    __config_path = "/etc/kvmd/user/tailscale.json"
    def __init__(self) -> None:
        self._logger = logger
        self._login_status = {
            "in_progress": False,
            "url": None,
            "completed": False,
            "success": False,
            "error": None,
            "timestamp": 0,
        }

    async def _run_command(self, cmd: str) -> str:
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                self._logger.error(f"Command failed: {stderr.decode()}")
                raise BadRequestError()
            return stdout.decode().strip()
        except Exception as e:
            self._logger.error(f"Error executing command: {e}")
            raise BadRequestError()

    async def _get_tailscale_status(self) -> Dict:
        """
        获取Tailscale的状态信息
        通过运行 tailscale status --json 获取
        """
        try:
            cmd = "tailscale status --json"
            output = await self._run_command(cmd)
            status_data = json.loads(output)
            return status_data
        except json.JSONDecodeError as e:
            self._logger.error(f"Failed to parse Tailscale status JSON: {e}")
            raise BadRequestError(f"Invalid JSON response from Tailscale: {e}")
        except Exception as e:
            self._logger.error(f"Error getting Tailscale status: {e}")
            raise BadRequestError(f"Failed to get Tailscale status: {e}")

    async def _start_login_process(self) -> str:
        """
        启动登录进程，获取URL后立即返回，但保持进程在后台运行
        """

        self._login_status = {
            "in_progress": True,
            "url": None,
            "completed": False,
            "success": False,
            "error": None,
            "timestamp": int(time.time()),
        }

        try:
            process = await asyncio.create_subprocess_exec(
                "tailscale", "login",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )


            url = None
            while not url and not process.stdout.at_eof():
                line = await process.stdout.readline()
                if not line:
                    continue

                line_str = line.decode().strip()
                self._logger.info(f"Tailscale login output: {line_str}")


                if "https://" in line_str:
                    for word in line_str.split():
                        if word.startswith("https://"):
                            url = word
                            break
                    if not url:
                        url = line_str

            if not url:
                self._login_status["in_progress"] = False
                self._login_status["error"] = "No login URL found in output"
                raise BadRequestError("No login URL found in output")


            self._login_status["url"] = url


            asyncio.create_task(self._wait_for_login_completion(process))

            return url

        except Exception as e:
            self._login_status["in_progress"] = False
            self._login_status["error"] = str(e)
            self._logger.error(f"Error starting Tailscale login: {e}")
            raise BadRequestError(str(e))

    async def _wait_for_login_completion(self, process) -> None:
        """
        等待登录进程完成，并更新状态
        """
        try:

            output_lines = []
            while not process.stdout.at_eof():
                line = await process.stdout.readline()
                if line:
                    line_str = line.decode().strip()
                    output_lines.append(line_str)
                    self._logger.info(f"Tailscale login output: {line_str}")


            exit_code = await process.wait()


            self._login_status["completed"] = True
            self._login_status["in_progress"] = False

            if exit_code == 0:
                self._login_status["success"] = True
                self._logger.info("Tailscale login process completed successfully")
            else:
                stderr_data = await process.stderr.read()
                stderr_str = stderr_data.decode()
                self._login_status["success"] = False
                self._login_status["error"] = f"Login failed with exit code {exit_code}: {stderr_str}"
                self._logger.error(f"Tailscale login failed: {stderr_str}")

        except Exception as e:
            self._login_status["completed"] = True
            self._login_status["in_progress"] = False
            self._login_status["success"] = False
            self._login_status["error"] = str(e)
            self._logger.error(f"Error while waiting for Tailscale login: {e}")

    async def _check_tailscald_process(self) -> bool:
        """
        检查 tailscald 进程是否存在
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "pgrep", "-f", "tailscaled",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return process.returncode == 0
        except Exception as e:
            self._logger.error(f"Error checking tailscald process: {e}")
            return False

    @exposed_http("GET", "/tailscale/status")
    async def _status_handler(self, _: Request) -> Response:
        try:
            running = await self._check_tailscald_process()
            return make_json_response({"running": running})
        except Exception as e:
            self._logger.error(f"Error checking Tailscale status: {e}")
            return make_json_exception(BadRequestError(), 502)

    async def _update_config_file(self, enable: bool) -> None:
        """
        更新Tailscale配置文件

        Args:
            enable: True表示启用Tailscale，False表示禁用
        """
        config_path = self.__config_path
        config_dir = os.path.dirname(config_path)


        try:
            os.makedirs(config_dir, exist_ok=True)
        except Exception as e:
            self._logger.error(f"无法创建配置目录 {config_dir}: {e}")
            raise BadRequestError(f"无法创建配置目录: {e}")


        try:
            config = {
                "enable": enable
            }

            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)

            self._logger.info(f"已更新Tailscale配置文件: enable={enable}")
        except Exception as e:
            self._logger.error(f"无法写入配置文件 {config_path}: {e}")
            raise BadRequestError(f"无法写入配置文件: {e}")

    @exposed_http("POST", "/tailscale/start")
    async def _start_handler(self, _: Request) -> Response:
        """
        启动 Tailscale 服务
        """
        try:

            await self._update_config_file(True)


            cmd = "/etc/init.d/S99tailscale start"
            output = await self._run_command(cmd)

            await asyncio.sleep(2)

            running = await self._check_tailscald_process()
            return make_json_response({
                "success": running,
                "output": output,
                "running": running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error starting Tailscale service: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/tailscale/stop")
    async def _stop_handler(self, _: Request) -> Response:
        """
        停止 Tailscale 服务
        """
        try:

            await self._update_config_file(False)


            cmd = "/etc/init.d/S99tailscale stop"
            output = await self._run_command(cmd)

            await asyncio.sleep(2)

            running = await self._check_tailscald_process()
            return make_json_response({
                "success": not running,
                "output": output,
                "running": running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error stopping Tailscale service: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("GET", "/tailscale/login_url")
    async def _login_url_handler(self, _: Request) -> Response:
        """
        获取Tailscale的登录URL
        在后台运行命令tailscale login，每隔一秒获取一次authurl
        直到10秒超时或者获取成功，然后结束后台进程并返回结果
        """
        try:

            status_data = await self._get_tailscale_status()


            auth_url = status_data.get("AuthURL", "")
            backend_state = status_data.get("BackendState", "Unknown")


            if auth_url:
                return make_json_response({
                    "url": auth_url,
                    "state": backend_state
                })


            self._logger.info("启动tailscale login命令获取登录URL")
            process = await asyncio.create_subprocess_exec(
                "tailscale", "login",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )


            auth_url = ""
            max_attempts = 10
            for attempt in range(max_attempts):
                self._logger.info(f"尝试获取AuthURL，第 {attempt+1}/{max_attempts} 次")


                try:
                    status_data = await self._get_tailscale_status()
                    auth_url = status_data.get("AuthURL", "")
                    backend_state = status_data.get("BackendState", "Unknown")


                    if auth_url:
                        self._logger.info(f"成功获取到AuthURL: {auth_url}")
                        break
                except Exception as e:
                    self._logger.error(f"检查AuthURL时出错: {e}")


                if attempt == max_attempts - 1 and not auth_url:
                    break


                await asyncio.sleep(1)


            try:
                self._logger.info("stop tailscale login")
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                self._logger.warning("tailscale login timeout, kill process")
                process.kill()
                await process.wait()


            return make_json_response({
                "url": auth_url,
                "state": backend_state
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error getting Tailscale login URL: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("GET", "/tailscale/login_status")
    async def _login_status_handler(self, _: Request) -> Response:
        """
        获取Tailscale的登录状态
        使用tailscale status --json获取BackendState字段
        """
        try:

            status_data = await self._get_tailscale_status()





















            response_data = {

                "status": status_data.get("BackendState", "Unknown"),
            }


            try:
                if "User" in status_data and status_data["User"]:

                    user_id = next(iter(status_data["User"]))
                    user_data = status_data["User"][user_id]
                    login_name = user_data.get("LoginName")

                    if login_name:
                        response_data["login_name"] = login_name
            except Exception as e:
                self._logger.warning(f"Error extracting login name: {e}")


            try:
                if "TailscaleIPs" in status_data and status_data["TailscaleIPs"]:
                    ips = status_data["TailscaleIPs"]
                    for ip in ips:
                        try:

                            ip_obj = ipaddress.ip_address(ip)

                            if isinstance(ip_obj, ipaddress.IPv4Address):
                                response_data["ipv4"] = ip
                            elif isinstance(ip_obj, ipaddress.IPv6Address):
                                response_data["ipv6"] = ip
                        except ValueError as e:

                            self._logger.warning(f"无效的IP地址 {ip}: {e}")
            except Exception as e:
                self._logger.warning(f"Error extracting TailscaleIPs: {e}")


            return make_json_response(response_data)
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error getting Tailscale login status: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/tailscale/logout")
    async def _logout_handler(self, _: Request) -> Response:
        """
        登出Tailscale账户
        调用tailscale logout命令并等待两秒
        """
        try:

            cmd = "tailscale logout"
            output = await self._run_command(cmd)


            await asyncio.sleep(2)


            status_data = await self._get_tailscale_status()


            is_logged_out = status_data.get("BackendState") == "NeedsLogin"

            return make_json_response({
                "success": is_logged_out,
                "output": output,
                "status": status_data.get("BackendState", "Unknown")
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error logging out from Tailscale: {e}")
            return make_json_exception(BadRequestError(), 502)