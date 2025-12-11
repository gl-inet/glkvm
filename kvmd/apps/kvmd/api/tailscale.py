




















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
                "pidof", "tailscaled",
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
            self._logger.error(f"Failed to create config directory {config_dir}: {e}")
            raise BadRequestError(f"Failed to create config directory: {e}")


        try:
            config = {
                "enable": enable
            }

            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)
            await asyncio.create_subprocess_shell("sync")

            self._logger.info(f"Updated Tailscale config file: enable={enable}")
        except Exception as e:
            self._logger.error(f"Failed to write config file {config_path}: {e}")
            raise BadRequestError(f"Failed to write config file: {e}")

    async def _read_config_file(self) -> Dict:
        """
        读取Tailscale配置文件
        """
        config_path = self.__config_path


        default_config = {
            "enable": False,
            "exit_node": False,
            "advertise_routes": "",
            "accept_routes": False,
            "accept_dns": False
        }

        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)

                    default_config["enable"] = config.get("enable", False)
                    default_config["exit_node"] = config.get("exit_node", False)
                    default_config["advertise_routes"] = config.get("advertise_routes", "")
                    default_config["accept_routes"] = config.get("accept_routes", False)
                    default_config["accept_dns"] = config.get("accept_dns", False)
            return default_config
        except Exception as e:
            self._logger.error(f"Failed to read config file {config_path}: {e}")
            return default_config

    async def _update_tailscale_config_file(self,
                                          enable: Optional[bool] = None,
                                          exit_node: Optional[bool] = None,
                                          advertise_routes: Optional[str] = None,
                                          accept_routes: Optional[bool] = None,
                                          accept_dns: Optional[bool] = None) -> None:
        """
        更新Tailscale配置文件，保存各种配置参数

        Args:
            enable: True表示启用Tailscale，False表示禁用，None表示不更改
            exit_node: 是否设置为exit node，None表示不更改
            advertise_routes: 要广播的路由，None表示不更改
            accept_routes: 是否接受路由，None表示不更改
            accept_dns: 是否接受DNS，None表示不更改
        """
        config_path = self.__config_path
        config_dir = os.path.dirname(config_path)


        try:
            os.makedirs(config_dir, exist_ok=True)
        except Exception as e:
            self._logger.error(f"Failed to create config directory {config_dir}: {e}")
            raise BadRequestError(f"Failed to create config directory: {e}")


        config = await self._read_config_file()


        if enable is not None:
            config["enable"] = enable
        if exit_node is not None:
            config["exit_node"] = exit_node
        if advertise_routes is not None:
            config["advertise_routes"] = advertise_routes
        if accept_routes is not None:
            config["accept_routes"] = accept_routes
        if accept_dns is not None:
            config["accept_dns"] = accept_dns


        try:
            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)
            await asyncio.create_subprocess_shell("sync")

            self._logger.info(f"Updated Tailscale config file: {config}")
        except Exception as e:
            self._logger.error(f"Failed to write config file {config_path}: {e}")
            raise BadRequestError(f"Failed to write config file: {e}")

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


            self._logger.info("Starting tailscale login command to get login URL")
            process = await asyncio.create_subprocess_exec(
                "tailscale", "login",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )


            auth_url = ""
            max_attempts = 10
            for attempt in range(max_attempts):
                self._logger.info(f"Attempting to get AuthURL, attempt {attempt+1}/{max_attempts}")


                try:
                    status_data = await self._get_tailscale_status()
                    auth_url = status_data.get("AuthURL", "")
                    backend_state = status_data.get("BackendState", "Unknown")


                    if auth_url:
                        self._logger.info(f"Successfully got AuthURL: {auth_url}")
                        break
                except Exception as e:
                    self._logger.error(f"Error checking AuthURL: {e}")


                if attempt == max_attempts - 1 and not auth_url:
                    break


                await asyncio.sleep(1)


            try:
                self._logger.info("Stopping tailscale login")
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                self._logger.warning("Tailscale login timeout, killing process")
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

            running = await self._check_tailscald_process()
            if not running:
                return make_json_exception(BadRequestError(), 502)


            status_data = await self._get_tailscale_status()





















            response_data = {

                "status": status_data.get("BackendState", "Unknown"),
            }


            try:
                if "User" in status_data and status_data["User"]:

                    if "Self" in status_data and status_data["Self"]:
                        user_id = str(status_data["Self"].get("UserID"))
                        user_data = status_data["User"][user_id]
                        login_name = user_data.get("LoginName")

                    if login_name:
                        response_data["login_name"] = login_name
            except Exception as e:
                self._logger.error(f"Error extracting login name: {e}")


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

                            self._logger.warning(f"Invalid IP address {ip}: {e}")
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

    async def _get_eth0_subnet(self) -> Optional[str]:
        """
        获取eth0接口的子网信息，格式为CIDR（例如：192.168.1.0/24）
        如果获取失败则返回None
        """
        try:

            cmd = "ip -json addr show eth0"
            output = await self._run_command(cmd)


            data = json.loads(output)
            if not data or not isinstance(data, list):
                self._logger.error("eth0 interface information not found")
                return None

            self._logger.info(f"eth0 interface information: {data}")


            for interface in data:

                if interface.get("ifname") == "eth0" and interface.get("addr_info"):

                    for addr_info in interface["addr_info"]:
                        if addr_info.get("family") == "inet":
                            ip_address = addr_info.get("local")
                            prefix_len = addr_info.get("prefixlen")

                            if ip_address and prefix_len:

                                network = ipaddress.IPv4Network(f"{ip_address}/{prefix_len}", strict=False)
                                return str(network)

            self._logger.warning("No IPv4 address found for eth0 interface")
            return None
        except json.JSONDecodeError as e:
            self._logger.error(f"Error parsing ip command output: {e}")
            return None
        except Exception as e:
            self._logger.error(f"Error getting eth0 subnet information: {e}")
            return None

    @exposed_http("POST", "/tailscale/config")
    async def _config_handler(self, request: Request) -> Response:
        """
        配置Tailscale的多个功能参数
        接受参数：
        - exit_node: 布尔值，为true时设置当前节点为exit node，为false时取消
        - advertise_routes: 字符串，要广播的路由，多个路由用逗号分隔
          特殊值："auto" - 自动获取eth0接口的子网
        - accept_routes: 布尔值，是否接受来自其他节点的路由
        - accept_dns: 布尔值，是否接受tailscale的DNS设置
        """
        try:

            exit_node = request.query.get("exit_node", None)
            advertise_routes = request.query.get("advertise_routes", None)
            accept_routes = request.query.get("accept_routes", None)
            accept_dns = request.query.get("accept_dns", None)


            cmd_parts = ["tailscale", "set"]


            exit_node_bool = None
            if exit_node is not None:

                exit_node_bool = exit_node.lower() in ("true", "1", "yes")
                cmd_parts.append(f"--advertise-exit-node={str(exit_node_bool).lower()}")


            actual_routes = None
            if advertise_routes is not None:
                if advertise_routes.lower() == "auto":

                    eth0_subnet = await self._get_eth0_subnet()
                    if eth0_subnet:
                        actual_routes = eth0_subnet
                        cmd_parts.append(f"--advertise-routes={eth0_subnet}")
                    else:
                        return make_json_response({
                            "success": False,
                            "error": "Failed to automatically get eth0 subnet information"
                        })
                elif advertise_routes.strip():
                    actual_routes = advertise_routes
                    cmd_parts.append(f"--advertise-routes={advertise_routes}")
                else:
                    actual_routes = ""
                    cmd_parts.append(f"--advertise-routes=")


            accept_routes_bool = None
            if accept_routes is not None:

                accept_routes_bool = accept_routes.lower() in ("true", "1", "yes")
                cmd_parts.append(f"--accept-routes={str(accept_routes_bool).lower()}")


            accept_dns_bool = None
            if accept_dns is not None:

                accept_dns_bool = accept_dns.lower() in ("true", "1", "yes")
                cmd_parts.append(f"--accept-dns={str(accept_dns_bool).lower()}")


            if len(cmd_parts) <= 2:
                return make_json_response({
                    "success": False,
                    "error": "At least one configuration parameter is required"
                })


            cmd = " ".join(cmd_parts)
            self._logger.info(f"Executing Tailscale command: {cmd}")

            output = await self._run_command(cmd)


            await asyncio.sleep(1)


            await self._update_tailscale_config_file(
                exit_node=exit_node_bool,
                advertise_routes=actual_routes,
                accept_routes=accept_routes_bool,
                accept_dns=accept_dns_bool
            )


            status_data = await self._get_tailscale_status()


            response = {
                "success": True,
                "output": output,
                "status": status_data.get("BackendState", "Unknown"),
                "applied_settings": {}
            }


            if actual_routes is not None:
                response["applied_settings"]["advertise_routes"] = actual_routes
            if exit_node_bool is not None:
                response["applied_settings"]["exit_node"] = exit_node_bool
            if accept_routes_bool is not None:
                response["applied_settings"]["accept_routes"] = accept_routes_bool
            if accept_dns_bool is not None:
                response["applied_settings"]["accept_dns"] = accept_dns_bool

            return make_json_response(response)
        except json.JSONDecodeError:
            self._logger.error("Invalid JSON request data")
            return make_json_exception(BadRequestError("Invalid request data format"), 400)
        except KeyError as e:
            self._logger.error(f"Missing required parameter: {e}")
            return make_json_exception(BadRequestError(f"Missing parameter: {e}"), 400)
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error configuring Tailscale parameters: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("GET", "/tailscale/config")
    async def _get_config_handler(self, _: Request) -> Response:
        """
        获取Tailscale的配置信息
        从配置文件中读取保存的配置参数
        """
        try:

            config = await self._read_config_file()

            return make_json_response(config)
        except Exception as e:
            self._logger.error(f"Error reading Tailscale config: {e}")
            return make_json_exception(BadRequestError(), 502)