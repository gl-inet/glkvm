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
import yaml
import json
import re
from typing import Dict, Any, Optional, Callable, List
import asyncio
from datetime import datetime
from .... import aiotools
from ....tools import run_command, run_shell

from aiohttp.web import Request, Response

from ....htserver import (
    BadGatewayError,
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....validators import ValidatorError
from ....validators.basic import valid_bool
from ....validators.kvm import valid_stream_quality

from .config_utils import (
    read_yaml as _read_yaml_util,
    write_yaml as _write_yaml_util,
    get_nested_value as _get_nested_value_util,
    set_nested_value as _set_nested_value_util,
)


from ....logging import get_logger
from ....utils import get_model_name

# 初始化日志记录器
logger = get_logger()

model_name = get_model_name()

class SystemApi:
    def __init__(
        self,
        get_wss_callback: Optional[Callable[[], List]] = None,
        close_ws_callback: Optional[Callable] = None,
        logout_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._logger = logger
        self._get_wss = get_wss_callback
        self._close_ws = close_ws_callback
        self._logout = logout_callback
        self._config_path = "/etc/kvmd/user/boot.yaml"
        self._privacy_path = "/etc/kvmd/user/privacy"
        self._user_config_path = "/etc/kvmd/user/config.json"
        self._network_config_path = "/etc/kvmd/user/network.json"
        self._ssl_dir = "/etc/kvmd/user/ssl"
        self._ssl_cert_path = "/etc/kvmd/user/ssl/server.crt"
        self._ssl_key_path = "/etc/kvmd/user/ssl/server.key"
        self._ssl_cert_default_path = "/etc/kvmd/user/ssl/server.crt.default"
        self._ssl_key_default_path = "/etc/kvmd/user/ssl/server.key.default"
        self._usb_pid_path = "/proc/gl-hw-info/usb_pid"
        self._capability_path = "/proc/gl-hw-info/capability"

        self.__otg_lock = asyncio.Lock()

        # 服务启动时强制重置隐私状态，确保开机默认关闭
        ##self._reset_privacy_state_on_startup()

        # 支持的参数验证器映射
        self._param_validators = {
            "kvmd/streamer/quality": valid_stream_quality,
            "kvmd/gpio/state/enabled": valid_bool,
            # 可以根据需要添加更多参数验证器
        }

    def _validate_hex_to_int(self, value: str, param_name: str) -> int:
        """验证并转换16进制字符串为整数"""
        try:
            # 移除0x前缀（如果有）并转换为小写
            clean_value = value.lower().replace("0x", "")
            # 转换为整数
            return int(clean_value, 16)
        except ValueError:
            raise BadRequestError(f"{param_name} must be a valid hexadecimal value")

    def _int_to_hex_str(self, value: int) -> str:
        """将整数转换为0x前缀的16进制字符串"""
        return f"0x{value:04X}"

    def _read_usb_pid(self) -> int:
        """从 /proc/gl-hw-info/usb_pid 读取 USB Product ID"""
        try:
            if os.path.exists(self._usb_pid_path):
                with open(self._usb_pid_path, "r") as f:
                    pid_str = f.read().strip()
                    # 将读取到的值转换为整数
                    return int(pid_str)
        except Exception as e:
            self._logger.warning(f"Failed to read USB PID from {self._usb_pid_path}: {e}")
        # 如果读取失败，返回默认值 260 (0x0104)
        return 260

    @exposed_http("GET", "/system/clients", allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def get_clients_handler(self, request: Request) -> Response:
        """获取当前连接的客户端数量"""
        try:
            if self._get_wss is None:
                return make_json_response({
                    "success": False,
                    "error": "WebSocket session callback not configured"
                }, status=500)
            
            wss = self._get_wss()
            clients = []
            unique_ips = set()
            streaming_count = 0
            
            for ws in wss:
                # 从会话 kwargs 中获取客户端 IP（在 WebSocket 连接时保存）
                remote = ws.kwargs.get("client_ip", "unknown")
                # 获取客户端浏览器信息
                user_agent = ws.kwargs.get("user_agent", "unknown")
                
                is_streaming = ws.kwargs.get("stream", False)
                if is_streaming:
                    streaming_count += 1

                # 直接从 kwargs 中获取连接建立时已解析好的信息
                device_type = ws.kwargs.get("device_type", "Unknown")
                browser = ws.kwargs.get("browser", "Unknown")

                unique_ips.add(remote)
                clients.append({
                    "remote": remote,
                    "user_agent": user_agent,
                    "device_type": device_type,
                    "browser": browser,
                    "is_streaming": is_streaming,
                    "id": id(ws)
                })
            
            return make_json_response({
                "success": True,
                "total_connections": len(wss),
                "unique_ips": len(unique_ips),
                "streaming_count": streaming_count,
                "clients": clients
            })
            
        except Exception as e:
            self._logger.error(f"Error getting clients info: {e}")
            return make_json_exception(BadRequestError(f"Error getting clients info: {str(e)}"), 502)

    @exposed_http("GET", "/system/capability")
    async def get_capability_handler(self, request: Request) -> Response:
        """获取系统硬件能力信息"""
        try:
            capabilities = {}
            if os.path.isdir(self._capability_path):
                for filename in os.listdir(self._capability_path):
                    file_path = os.path.join(self._capability_path, filename)
                    if os.path.isfile(file_path):
                        try:
                            with open(file_path, "r") as f:
                                capabilities[filename] = f.read().strip()
                        except Exception as e:
                            self._logger.warning(f"Failed to read capability file {filename}: {e}")

            return make_json_response({
                "success": True,
                "capability": capabilities
            })
        except Exception as e:
            self._logger.error(f"Error getting capabilities: {e}")
            return make_json_exception(BadRequestError(f"Error getting capabilities: {str(e)}"), 502)

    @exposed_http("DELETE", "/system/clients/{client_id}", allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def delete_client_handler(self, request: Request) -> Response:
        """断开指定的 WebSocket 连接并删除对应的 token (RESTful: DELETE /system/clients/{id})"""
        try:
            if self._get_wss is None or self._close_ws is None:
                return make_json_response({
                    "success": False,
                    "error": "WebSocket session callback not configured"
                }, status=500)
            
            # 从 URL 路径中获取 client_id
            client_id_str = request.match_info.get("client_id", "")
            if not client_id_str:
                return make_json_response({
                    "success": False,
                    "error": "Missing client_id parameter"
                }, status=400)
            
            try:
                client_id = int(client_id_str)
            except ValueError:
                return make_json_response({
                    "success": False,
                    "error": "Invalid client_id format, must be an integer"
                }, status=400)
            
            # 遍历找到对应的 session
            wss = self._get_wss()
            target_ws = None
            for ws in wss:
                if id(ws) == client_id:
                    target_ws = ws
                    break
            
            if target_ws is None:
                return make_json_response({
                    "success": False,
                    "error": f"Client with id {client_id} not found"
                }, status=404)
            
            # 获取 auth_token 并登出
            auth_token = target_ws.kwargs.get("auth_token", "")
            if auth_token and self._logout:
                try:
                    self._logout(auth_token)
                    self._logger.info(f"Logged out token for client {client_id}")
                except Exception as e:
                    self._logger.warning(f"Failed to logout token for client {client_id}: {e}")
            
            # 关闭 WebSocket 连接之前，先通知客户端被踢出
            try:
                await target_ws.send_event("kickout", {
                    "reason": "deleted_by_admin",
                })
            except Exception:
                pass

            # 关闭 WebSocket 连接
            await self._close_ws(target_ws)
            self._logger.info(f"Disconnected client {client_id}")
            
            # 重启相关进程
            restart_scripts = [
                "killall janus",
                "/etc/init.d/S99gl-pion restart",
                "/etc/init.d/S80ttyd restart",
            ]
            for script in restart_scripts:
                try:
                    returncode, _, stderr_text = await run_shell(script, timeout=30)
                    if returncode == 0:
                        self._logger.info(f"Successfully executed: {script}")
                    else:
                        self._logger.warning(f"Script {script} returned non-zero: {stderr_text}")
                except asyncio.TimeoutError:
                    self._logger.warning(f"Script {script} timed out")
                except Exception as e:
                    self._logger.warning(f"Failed to execute {script}: {e}")
            
            return make_json_response({
                "success": True,
                "disconnected_id": client_id,
                "token_deleted": bool(auth_token and self._logout)
            })
            
        except Exception as e:
            self._logger.error(f"Error disconnecting client: {e}")
            return make_json_exception(BadRequestError(f"Error disconnecting client: {str(e)}"), 502)

    async def _get_ethernet_service_id(self) -> Optional[str]:
        """获取以太网服务ID"""
        try:
            # 执行命令获取以太网服务ID
            returncode, stdout_text, stderr_text = await run_command(
                "connmanctl", "services", timeout=10
            )
            
            if returncode != 0:
                self._logger.error(f"connmanctl services command failed: {stderr_text}")
                return None
                
            # 解析输出，查找ethernet服务
            for line in stdout_text.split('\n'):
                if 'ethernet' in line.lower():
                    # 提取服务ID（第三列）
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
            
            return None
            
        except asyncio.TimeoutError:
            self._logger.error("connmanctl services command timeout")
            return None
        except Exception as e:
            self._logger.error(f"Error getting ethernet service ID: {e}")
            return None

    async def _parse_connman_output(self, output: str) -> Dict[str, Any]:
        """解析connmanctl输出"""
        config = {
            "is_dhcp": False,
            "ip_address": "",
            "netmask": "",
            "gateway": "",
            "dns_servers": [],
            "interface": "",
            "state": "",
            "mac_address": ""
        }

        try:
            lines = output.split('\n')
            ipv4_config_info = ""  # 保存IPv4.Configuration信息用于回退

            for line in lines:
                line = line.strip()

                # 解析状态
                if line.startswith('State = '):
                    config["state"] = line.split('=')[1].strip()

                # 解析以太网信息
                elif line.startswith('Ethernet = '):
                    ethernet_info = line.split('=', 1)[1].strip()
                    # 移除方括号并解析内容
                    ethernet_info = ethernet_info.strip('[ ]')
                    # 提取接口名称
                    interface_match = re.search(r'Interface=(\w+)', ethernet_info)
                    if interface_match:
                        config["interface"] = interface_match.group(1)
                    # 提取MAC地址
                    address_match = re.search(r'Address=([0-9A-Fa-f:]+)', ethernet_info)
                    if address_match:
                        config["mac_address"] = address_match.group(1)

                # 解析IPv4.Configuration信息来获取DHCP状态
                elif line.startswith('IPv4.Configuration = '):
                    ipv4_config_info = line.split('=', 1)[1].strip()
                    # 移除方括号并解析内容
                    ipv4_config_info = ipv4_config_info.strip('[ ]')
                    # 检查是否为DHCP
                    if 'Method=dhcp' in ipv4_config_info:
                        config["is_dhcp"] = True
                    elif 'Method=manual' in ipv4_config_info:
                        config["is_dhcp"] = False

                # 解析IPv4信息（用于获取当前的IP、子网掩码、网关）
                elif line.startswith('IPv4 = '):
                    ipv4_info = line.split('=', 1)[1].strip()
                    # 移除方括号并解析内容
                    ipv4_info = ipv4_info.strip('[ ]')

                    # 提取IP地址
                    ip_match = re.search(r'Address=([0-9.]+)', ipv4_info)
                    if ip_match:
                        config["ip_address"] = ip_match.group(1)

                    # 提取子网掩码
                    netmask_match = re.search(r'Netmask=([0-9.]+)', ipv4_info)
                    if netmask_match:
                        config["netmask"] = netmask_match.group(1)

                    # 提取网关
                    gateway_match = re.search(r'Gateway=([0-9.]+)', ipv4_info)
                    if gateway_match:
                        config["gateway"] = gateway_match.group(1)

                # 解析DNS服务器
                elif line.startswith('Nameservers = '):
                    nameservers_info = line.split('=', 1)[1].strip()
                    # 移除方括号并解析内容
                    nameservers_info = nameservers_info.strip('[ ]')
                    # 只提取IPv4 DNS服务器列表，过滤掉IPv6地址
                    ipv4_dns_match = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', nameservers_info)
                    config["dns_servers"] = ipv4_dns_match

            # 如果IPv4中缺少字段，从IPv4.Configuration中回退获取
            if ipv4_config_info:
                # 如果IP地址为空，从IPv4.Configuration中获取
                if not config["ip_address"]:
                    ip_match = re.search(r'Address=([0-9.]+)', ipv4_config_info)
                    if ip_match:
                        config["ip_address"] = ip_match.group(1)

                # 如果子网掩码为空，从IPv4.Configuration中获取
                if not config["netmask"]:
                    netmask_match = re.search(r'Netmask=([0-9.]+)', ipv4_config_info)
                    if netmask_match:
                        config["netmask"] = netmask_match.group(1)

                # 如果网关为空，从IPv4.Configuration中获取
                if not config["gateway"]:
                    gateway_match = re.search(r'Gateway=([0-9.]+)', ipv4_config_info)
                    if gateway_match:
                        config["gateway"] = gateway_match.group(1)

            return config

        except Exception as e:
            self._logger.error(f"Error parsing connmanctl output: {e}")
            return config

    @exposed_http("GET", "/system/get_network_config")
    async def get_network_config_handler(self, request: Request) -> Response:
        """获取网络配置处理器"""
        try:
            # 获取以太网服务ID
            service_id = await self._get_ethernet_service_id()
            if not service_id:
                raise BadRequestError("Ethernet service not found")
            
            # 获取详细的网络配置
            returncode, stdout_text, stderr_text = await run_command(
                "connmanctl", "services", service_id, timeout=10
            )
            
            if returncode != 0:
                self._logger.error(f"connmanctl services {service_id} command failed: {stderr_text}")
                raise BadRequestError("connmanctl services command failed")
            
            # 解析输出
            config = await self._parse_connman_output(stdout_text)
            
            return make_json_response({
                "success": True,
                "config": config
            })
            
        except asyncio.TimeoutError:
            return make_json_exception(BadRequestError("connmanctl services command timeout"), 502)
        except BadRequestError as e:
            return make_json_exception(e, 502)
        except Exception as e:
            self._logger.error(f"Error getting network config: {e}")
            return make_json_exception(BadRequestError(f"Error getting network config: {str(e)}"), 502)

    @exposed_http("POST", "/system/set_network_config")
    async def set_network_config_handler(self, request: Request) -> Response:
        """设置网络配置处理器"""
        try:
            # 获取以太网服务ID
            service_id = await self._get_ethernet_service_id()
            if not service_id:
                raise BadRequestError("Ethernet service not found")
            
            # 获取请求参数
            mode = request.query.get("mode")  # dhcp 或 static
            ip_address = request.query.get("ip_address")
            netmask = request.query.get("netmask")
            gateway = request.query.get("gateway")
            dns_servers = request.query.get("dns_servers")  # 逗号分隔的DNS服务器列表
            
            if not mode:
                raise BadRequestError("mode parameter is required, must be 'dhcp' or 'static'")
            
            if mode not in ["dhcp", "static"]:
                raise BadRequestError("mode parameter must be 'dhcp' or 'static'")
            
            # 验证静态IP配置参数
            if mode == "static":
                if not ip_address or not netmask or not gateway:
                    raise BadRequestError("Static IP mode requires ip_address, netmask and gateway parameters")
                
                # 简单的IP地址格式验证
                if not self._validate_ipv4_address(ip_address):
                    raise BadRequestError("ip_address format is invalid")
                if not self._validate_ipv4_address(netmask):
                    raise BadRequestError("netmask format is invalid")
                if not self._validate_ipv4_address(gateway):
                    raise BadRequestError("gateway format is invalid")
            
            # 配置IP设置
            if mode == "dhcp":
                # 切换到DHCP模式
                returncode, _, stderr_text = await run_command(
                    "connmanctl", "config", service_id, "--ipv4", "dhcp", timeout=30
                )
                
                if returncode != 0:
                    self._logger.error(f"Failed to set DHCP mode: {stderr_text}")
                    raise BadRequestError(f"Failed to set DHCP mode: {stderr_text}")
                
                # 配置DNS服务器
                returncode, _, stderr_text = await run_command(
                    "connmanctl", "config", service_id, "--nameservers", "", timeout=30
                )
                
                if returncode != 0:
                    self._logger.error(f"Failed to set DHCP DNS: {stderr_text}")
                    raise BadRequestError(f"Failed to set DHCP DNS: {stderr_text}")
                
                self._logger.info("Successfully switched to DHCP mode")
                
            else:  # static mode
                # 配置静态IP
                returncode, _, stderr_text = await run_command(
                    "connmanctl", "config", service_id, "--ipv4", "manual", ip_address, netmask, gateway,
                    timeout=30
                )
                
                if returncode != 0:
                    self._logger.error(f"Failed to set static IP: {stderr_text}")
                    raise BadRequestError(f"Failed to set static IP: {stderr_text}")
                
                self._logger.info(f"Successfully set static IP: {ip_address}/{netmask}, gateway: {gateway}")
            
            # 配置DNS服务器
            if dns_servers is not None:
                if dns_servers.strip():
                    # 配置指定的DNS服务器
                    dns_list = [dns.strip() for dns in dns_servers.split(",") if dns.strip()]
                    
                    # 验证DNS服务器地址
                    for dns in dns_list:
                        if not self._validate_ipv4_address(dns):
                            raise BadRequestError(f"Invalid DNS server address format: {dns}")
                    
                    # 配置DNS服务器
                    returncode, _, stderr_text = await run_command(
                        "connmanctl", "config", service_id, "nameservers", *dns_list, timeout=30
                    )
                    
                    if returncode != 0:
                        self._logger.error(f"Failed to set DNS servers: {stderr_text}")
                        raise BadRequestError(f"Failed to set DNS servers: {stderr_text}")
                    
                    self._logger.info(f"Successfully set DNS servers: {', '.join(dns_list)}")
                else:
                    # 配置为使用DHCP的DNS（清空DNS设置）
                    returncode, _, stderr_text = await run_command(
                        "connmanctl", "config", service_id, "nameservers", timeout=30
                    )
                    
                    if returncode != 0:
                        self._logger.error(f"Failed to set DHCP DNS: {stderr_text}")
                        raise BadRequestError(f"Failed to set DHCP DNS: {stderr_text}")
                    
                    self._logger.info("Successfully set to use DHCP DNS")
            
            # 等待配置生效
            await asyncio.sleep(2)
            
            # 保存网络配置到文件
            network_config = {
                "mode": mode,
            }
            
            if mode == "static":
                network_config.update({
                    "ip_address": ip_address,
                    "netmask": netmask,
                    "gateway": gateway
                })
            
            # 保存DNS配置
            if dns_servers is not None:
                if dns_servers.strip():
                    # 保存指定的DNS服务器
                    dns_list = [dns.strip() for dns in dns_servers.split(",") if dns.strip()]
                    network_config["dns_servers"] = dns_list
                    network_config["use_dhcp_dns"] = False
                else:
                    # 使用DHCP的DNS
                    network_config["dns_servers"] = []
                    network_config["use_dhcp_dns"] = True
            
            # 写入配置文件
            await self._write_network_config(network_config)
            self._logger.info(f"Network configuration saved to {self._network_config_path}")
            
            # 获取更新后的网络配置
            # updated_config = await self._get_current_network_config(service_id)
            
            return make_json_response({
                "success": True,
                # "config": updated_config
            })
            
        except asyncio.TimeoutError:
            return make_json_exception(BadRequestError("connmanctl services command timeout"), 502)
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting network config: {e}")
            return make_json_exception(BadRequestError(f"Error setting network config: {str(e)}"), 502)

    def _validate_ipv4_address(self, ip: str) -> bool:
        """验证IPv4地址格式"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False

    async def _get_current_network_config(self, service_id: str) -> Dict[str, Any]:
        """获取当前网络配置（内部方法）"""
        try:
            returncode, stdout_text, _ = await run_command(
                "connmanctl", "services", service_id, timeout=10
            )
            
            if returncode == 0:
                return await self._parse_connman_output(stdout_text)
            else:
                return {}
        except Exception:
            return {}

    async def _read_yaml(self) -> Dict:
        """读取YAML配置文件（委托给 config_utils）"""
        try:
            return await _read_yaml_util(self._config_path)
        except Exception as e:
            raise BadRequestError(f"Cannot read config file: {e}")

    async def _write_yaml(self, data: Dict) -> None:
        """写入YAML配置文件（委托给 config_utils）"""
        try:
            await _write_yaml_util(data, self._config_path)
        except Exception as e:
            raise BadRequestError(f"Cannot write config file: {e}")

    def _read_privacy_state(self) -> Dict[str, bool]:
        """读取隐私状态文件"""
        state = {
            "privacy_enable": False,
            "privacy_restore": False,
        }

        try:
            if not os.path.exists(self._privacy_path):
                return state

            with open(self._privacy_path, "r") as f:
                content = f.read().strip()

            if not content:
                return state

            # 单整数位掩码：bit1(2)=privacy_enable, bit0(1)=privacy_restore
            privacy_flags = int(content, 10)
            return {
                "privacy_enable": bool(privacy_flags & 0x2),
                "privacy_restore": bool(privacy_flags & 0x1),
            }
        except ValueError:
            self._logger.warning(f"Invalid privacy bitmask in {self._privacy_path}, keep default")
            return state
        except Exception as e:
            self._logger.warning(f"Cannot read privacy file {self._privacy_path}: {e}")
            return state

    async def _write_privacy_state(self, state: Dict[str, bool]) -> None:
        """写入隐私状态文件，供其他进程实时读取"""
        try:
            os.makedirs(os.path.dirname(self._privacy_path), exist_ok=True)
            tmp_path = f"{self._privacy_path}.tmp"
            privacy_flags = (
                (0x2 if state.get("privacy_enable", False) else 0)
                | (0x1 if state.get("privacy_restore", False) else 0)
            )
            with open(tmp_path, "w") as f:
                f.write(f"{privacy_flags}\n")
            os.replace(tmp_path, self._privacy_path)
            await run_shell("sync")
        except Exception as e:
            self._logger.error(f"Cannot write privacy file {self._privacy_path}: {e}")
            raise BadRequestError("Cannot write privacy state")

    def _reset_privacy_state_on_startup(self) -> None:
        """启动时重置隐私状态为 0，确保默认值一致"""
        try:
            os.makedirs(os.path.dirname(self._privacy_path), exist_ok=True)
            tmp_path = f"{self._privacy_path}.tmp"
            with open(tmp_path, "w") as f:
                f.write("0\n")
            os.replace(tmp_path, self._privacy_path)
            self._logger.info(f"Reset privacy state to 0 on startup: {self._privacy_path}")
        except Exception as e:
            self._logger.warning(f"Failed to reset privacy state on startup: {e}")

    def _get_nested_value(self, data: Dict, path: str, default: Any = None) -> Any:
        """获取嵌套字典中的值（委托给 config_utils）"""
        return _get_nested_value_util(data, path, default)

    def _set_nested_value(self, data: Dict, path: str, value: Any) -> None:
        """设置嵌套字典中的值（委托给 config_utils）"""
        _set_nested_value_util(data, path, value)

    @exposed_http("GET", "/system/get_param")
    async def get_param_handler(self, request: Request) -> Response:
        """获取系统参数处理器"""
        try:
            data = await self._read_yaml()
            privacy_state = self._read_privacy_state()

            # 从 /proc/gl-hw-info/usb_pid 读取 product_id，如果读取失败则使用配置文件中的值
            usb_pid_from_proc = self._read_usb_pid()

            # 提取所有参数，并设置默认值
            return make_json_response({
                "success": True,
                "absolute_mouse": self._get_nested_value(data, "kvmd/hid/mouse/absolute", True),
                "msd_partition": self._get_nested_value(data, "kvmd/msd/partition_device", "/dev/block/by-name/media"),
                # 新增 OTG 相关参数
                "otg_manufacturer": self._get_nested_value(data, "otg/manufacturer", "Glinet"),
                "otg_product": self._get_nested_value(data, "otg/product", "Glinet Composite Device"),
                "otg_vendor_id": self._int_to_hex_str(self._get_nested_value(data, "otg/vendor_id", 14571)),
                "otg_product_id": self._int_to_hex_str(self._get_nested_value(data, "otg/product_id", usb_pid_from_proc)),
                "otg_serial": self._get_nested_value(data, "otg/serial", ""),
                "cdrom_vendor": self._get_nested_value(data, "otg/devices/msd/default/inquiry_string/cdrom/vendor", "Glinet"),
                "flash_vendor": self._get_nested_value(data, "otg/devices/msd/default/inquiry_string/flash/vendor", "Glinet"),
                "mic_name": self._get_nested_value(data, "otg/devices/audio/product", "Comet Microphone"),
                "default_product_id": self._int_to_hex_str(usb_pid_from_proc),
                "default_vendor_id": self._int_to_hex_str(14571),

                # 新增隐私屏参数
                "privacy_enable": privacy_state["privacy_enable"],
                "privacy_restore": privacy_state["privacy_restore"],
            })

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error getting system parameters: {e}")
            return make_json_exception(BadRequestError("Error getting system parameters"), 502)

    @exposed_http("GET", "/system/gui_get_param", allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def gui_get_param_handler(self, request: Request) -> Response:
        """GUI 获取系统参数处理器"""
        return await self.get_param_handler(request)

    @exposed_http("POST", "/system/set_param")
    async def set_param_handler(self, request: Request) -> Response:
        """设置系统参数处理器"""
        try:
            # 获取请求参数
            absolute_mouse = request.query.get("absolute_mouse")
            msd_partition = request.query.get("msd_partition")
            # 新增 OTG 相关参数
            otg_manufacturer = request.query.get("otg_manufacturer")
            otg_product = request.query.get("otg_product")
            otg_vendor_id = request.query.get("otg_vendor_id")
            otg_product_id = request.query.get("otg_product_id")
            otg_serial = request.query.get("otg_serial")
            cdrom_vendor = request.query.get("cdrom_vendor")
            flash_vendor = request.query.get("flash_vendor")
            mic_name = request.query.get("mic_name")
            
            privacy_enable = request.query.get("privacy_enable")
            privacy_restore = request.query.get("privacy_restore")

            # 读取当前配置
            data = await self._read_yaml()
            
            # 标记是否修改了 OTG 相关参数（需要重启 UDC 才能生效）
            otg_changed = False
            
            # 更新配置
            if absolute_mouse is not None:
                try:
                    absolute_mouse = valid_bool(absolute_mouse)
                    self._set_nested_value(data, "kvmd/hid/mouse/absolute", absolute_mouse)
                except ValidatorError as e:
                    raise BadRequestError(f"absolute_mouse parameter validation failed: {str(e)}")

            if msd_partition is not None:
                if not msd_partition.strip():
                    raise BadRequestError("msd_partition parameter cannot be empty")
                self._set_nested_value(data, "kvmd/msd/partition_device", msd_partition)

            # 设置 OTG 相关参数
            if otg_manufacturer is not None:
                self._set_nested_value(data, "otg/manufacturer", otg_manufacturer)
                otg_changed = True
            if otg_product is not None:
                self._set_nested_value(data, "otg/product", otg_product)
                otg_changed = True
            if otg_vendor_id is not None:
                int_vendor_id = self._validate_hex_to_int(otg_vendor_id, "otg_vendor_id")
                self._set_nested_value(data, "otg/vendor_id", int_vendor_id)
                otg_changed = True
            if otg_product_id is not None:
                int_product_id = self._validate_hex_to_int(otg_product_id, "otg_product_id")
                self._set_nested_value(data, "otg/product_id", int_product_id)
                otg_changed = True
            if otg_serial is not None:
                self._set_nested_value(data, "otg/serial", otg_serial)
                otg_changed = True

            if cdrom_vendor is not None:
                self._set_nested_value(data, "otg/devices/msd/default/inquiry_string/cdrom/vendor", cdrom_vendor)
                otg_changed = True
            if flash_vendor is not None:
                self._set_nested_value(data, "otg/devices/msd/default/inquiry_string/flash/vendor", flash_vendor)
                otg_changed = True

            if mic_name is not None:
                # 麦克风名字必须是非空的字符串
                if not mic_name.strip():
                    raise BadRequestError("mic_name parameter cannot be empty")
                self._set_nested_value(data, "otg/devices/audio/product", mic_name)

            # 写入配置
            await self._write_yaml(data)

            # 如果修改了 OTG 描述符参数，通过 stop+start 重建 OTG gadget 以应用配置
            if otg_changed:
                self._logger.info("OTG config changed, restarting OTG gadget to apply ...")
                await self.__restart_otg()

            if privacy_enable is not None or privacy_restore is not None:
                async with self.__otg_lock:
                    privacy_state = self._read_privacy_state()
                    if privacy_enable is not None:
                        privacy_state["privacy_enable"] = valid_bool(privacy_enable)
                    if privacy_restore is not None:
                        privacy_state["privacy_restore"] = valid_bool(privacy_restore)
                    await self._write_privacy_state(privacy_state)
            else:
                privacy_state = self._read_privacy_state()

            # 从 /proc/gl-hw-info/usb_pid 读取 product_id
            usb_pid_from_proc = self._read_usb_pid()

            # 返回更新后的值
            return make_json_response({
                "success": True,
                "absolute_mouse": self._get_nested_value(data, "kvmd/hid/mouse/absolute", True),
                "msd_partition": self._get_nested_value(data, "kvmd/msd/partition_device", "/dev/block/by-name/media"),
                "otg_manufacturer": self._get_nested_value(data, "otg/manufacturer", "Glinet"),
                "otg_product": self._get_nested_value(data, "otg/product", "Glinet Composite Device"),
                "otg_vendor_id": self._int_to_hex_str(self._get_nested_value(data, "otg/vendor_id", 14571)),
                "otg_product_id": self._int_to_hex_str(self._get_nested_value(data, "otg/product_id", usb_pid_from_proc)),
                "otg_serial": self._get_nested_value(data, "otg/serial", ""),
                "cdrom_vendor": self._get_nested_value(data, "otg/devices/msd/default/inquiry_string/cdrom/vendor", "Glinet"),
                "flash_vendor": self._get_nested_value(data, "otg/devices/msd/default/inquiry_string/flash/vendor", "Glinet"),
                "mic_name": self._get_nested_value(data, "otg/devices/audio/product", "Comet Microphone"),
                "privacy_enable": privacy_state["privacy_enable"],
                "privacy_restore": privacy_state["privacy_restore"],
            })

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting system parameters: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/system/gui_set_param", allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def gui_set_param_handler(self, request: Request) -> Response:
        """GUI 设置系统参数处理器"""
        return await self.set_param_handler(request)

    # ===== OTG Function Toggle (link/unlink via kvmd-otgconf)

    # 参数名 -> (yaml路径, 默认值, otgconf function名)
    _OTG_FUNC_MAP = {
        "enable_keyboard": ("otg/devices/hid/keyboard/start", True,  "hid.usb0"),
        "enable_mouse":    ("otg/devices/hid/mouse/start",    True,  "hid.usb1"),
        "enable_mouse_alt":("otg/devices/hid/mouse_alt/start",True,  "hid.usb2"),
        "start_cdrom":     ("otg/devices/msd/start_cdrom",    False, "mass_storage.0"),
        "start_flash":     ("otg/devices/msd/start_flash",    False, "mass_storage.1"),
        "enable_mic":      ("otg/devices/audio/start",        False, "uac1.usb0" if model_name == "rmq1" else "uac2.usb0"),
    }

    @exposed_http("GET", "/system/otg_functions")
    async def get_otg_functions_handler(self, request: Request) -> Response:
        """获取 OTG function（HID/MSD/麦克风）的启用状态"""
        try:
            data = await self._read_yaml()
            return make_json_response({
                key: self._get_nested_value(data, yaml_path, default)
                for key, (yaml_path, default, _) in self._OTG_FUNC_MAP.items()
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error getting OTG functions: {e}")
            return make_json_exception(BadRequestError("Error getting OTG functions"), 502)

    @exposed_http("POST", "/system/otg_functions")
    async def set_otg_functions_handler(self, request: Request) -> Response:
        """设置 OTG function（HID/MSD/麦克风）的启用状态，使用 kvmd-otgconf link/unlink"""
        try:
            async with self.__otg_lock:
                data = await self._read_yaml()
                funcs_to_enable: set[str] = set()
                funcs_to_disable: set[str] = set()

                for key, (yaml_path, default, func_name) in self._OTG_FUNC_MAP.items():
                    raw = request.query.get(key)
                    if raw is None:
                        continue
                    val = valid_bool(raw)
                    self._set_nested_value(data, yaml_path, val)
                    (funcs_to_enable if val else funcs_to_disable).add(func_name)

                # rmq1: mic 开关联动 rndis（特殊 side-effect）
                if model_name == "rmq1" and request.query.get("enable_mic") is not None:
                    self._set_nested_value(
                        data, "otg/devices/rndis/enabled",
                        not self._get_nested_value(data, "otg/devices/audio/start", False),
                    )

                await self._write_yaml(data)

                if funcs_to_enable or funcs_to_disable:
                    self._logger.info("OTG functions changed, applying via kvmd-otgconf ...")
                    await self.__change_otg_functions(funcs_to_enable, funcs_to_disable)

                return make_json_response({
                    key: self._get_nested_value(data, yaml_path, default)
                    for key, (yaml_path, default, _) in self._OTG_FUNC_MAP.items()
                })

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting OTG functions: {e}")
            return make_json_exception(BadRequestError("Error setting OTG functions"), 502)

    async def _read_user_config(self) -> Dict:
        """读取用户JSON配置文件"""
        try:
            if os.path.exists(self._user_config_path):
                with open(self._user_config_path, "r") as f:
                    return json.load(f) or {}
            return {}
        except Exception as e:
            self._logger.error(f"Error getting user config: {e}")
            raise BadRequestError("Error reading user config")

    async def _write_user_config(self, data: Dict) -> None:
        """写入用户JSON配置文件"""
        try:
            os.makedirs(os.path.dirname(self._user_config_path), exist_ok=True)
            with open(self._user_config_path, "w") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            await run_shell("sync")
        except Exception as e:
            self._logger.error(f"Cannot write user config file {self._user_config_path}: {e}")
            raise BadRequestError(f"Cannot write user config file: {e}")

    async def _read_network_config(self) -> Dict:
        """读取网络配置文件"""
        try:
            if os.path.exists(self._network_config_path):
                with open(self._network_config_path, "r") as f:
                    return json.load(f) or {}
            return {}
        except Exception as e:
            self._logger.error(f"Cannot read network config file {self._network_config_path}: {e}")
            return {}

    async def _write_network_config(self, data: Dict) -> None:
        """写入网络配置文件"""
        try:
            os.makedirs(os.path.dirname(self._network_config_path), exist_ok=True)
            with open(self._network_config_path, "w") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            await run_shell("sync")
        except Exception as e:
            self._logger.error(f"Cannot write network config file {self._network_config_path}: {e}")
            raise BadRequestError(f"Cannot write network config file: {e}")

    def _get_gmt_zone_from_offset(self, offset_minutes: int) -> str:
        """根据UTC偏移分钟获取对应的GMT时区路径"""
        offset_hours = offset_minutes // 60
        if offset_hours > 0:
            return f"Etc/GMT+{offset_hours}"
        elif offset_hours < 0:
            return f"Etc/GMT-{abs(offset_hours)}"
        else:
            return "Etc/GMT"

    def _get_offset_from_gmt_zone(self, gmt_zone: str) -> int:
        """根据GMT时区路径获取UTC偏移分钟"""
        import re
        if gmt_zone == "Etc/GMT":
            return 0
        
        # 匹配GMT+数字或GMT-数字
        match = re.match(r'.*GMT([+-])(\d+)', gmt_zone)
        if match:
            sign, hours_str = match.groups()
            hours = int(hours_str)
            # GMT+X表示UTC-X，GMT-X表示UTC+X
            if sign == '+':
                return hours * 60  # GMT+8 -> UTC-8
            else:
                return -hours * 60   # GMT-8 -> UTC+8
        return 0

    def _get_current_timezone_name(self) -> str:
        """从/etc/localtime符号链接获取当前IANA时区名称"""
        try:
            if os.path.exists("/etc/localtime"):
                link_target = os.readlink("/etc/localtime")
                if "/zoneinfo/" in link_target:
                    zone_path = link_target.split("/zoneinfo/")[-1]
                    # 去掉posix/前缀
                    if zone_path.startswith("posix/"):
                        zone_path = zone_path[len("posix/"):]
                    return zone_path
        except OSError:
            pass
        return "Etc/GMT"

    def _get_utc_offset_minutes(self) -> int:
        """获取当前系统时区的UTC偏移分钟数"""
        try:
            now = datetime.now()
            utc_now = datetime.utcnow()
            delta = now - utc_now
            return int(delta.total_seconds() / 60)
        except Exception:
            return 0

    @exposed_http("GET", "/system/time")
    async def get_time_handler(self, request: Request) -> Response:
        """获取系统时间和时区处理器"""
        try:
            # 获取系统当前时间戳（秒）
            current_timestamp = int(datetime.now().timestamp())

            # 获取IANA时区名称
            timezone_name = self._get_current_timezone_name()

            # 获取时区偏移量（分钟）
            if timezone_name.startswith("Etc/GMT"):
                timezone_offset = self._get_offset_from_gmt_zone(timezone_name)
            else:
                timezone_offset = self._get_utc_offset_minutes()

            return make_json_response({
                "success": True,
                "time": current_timestamp,
                "time_zone": timezone_offset,
                "timezone_name": timezone_name
            })

        except Exception as e:
            self._logger.error(f"Error getting system time: {e}")
            return make_json_exception(BadRequestError(f"Error getting system time: {str(e)}"), 502)

    @exposed_http("POST", "/system/time")
    async def set_time_handler(self, request: Request) -> Response:
        """设置系统时间和时区处理器"""
        try:
            # 获取请求参数
            time_param = request.query.get("time")
            time_zone_param = request.query.get("time_zone")
            
            # 验证参数
            if not time_param and not time_zone_param:
                raise BadRequestError("At least one parameter (time or time_zone) is required")
            
            # 设置时区
            if time_zone_param:
                try:
                    # 验证时区偏移量格式并转换为整数
                    try:
                        timezone_offset = int(time_zone_param)
                    except ValueError:
                        raise BadRequestError("time_zone parameter must be a valid integer (minutes offset from UTC)")
                    
                    # 验证时区偏移量范围（-12小时到+14小时）
                    if timezone_offset < -840 or timezone_offset > 840:
                        raise BadRequestError("time_zone parameter out of valid range (-840 to 840 minutes)")
                    
                    # 将偏移量转换为GMT时区路径
                    gmt_zone = self._get_gmt_zone_from_offset(timezone_offset)
                    
                    # 设置/etc/localtime符号链接，使用posix路径避免夏令时
                    posix_zoneinfo_path = f"/usr/share/zoneinfo/posix/{gmt_zone}"
                    zoneinfo_path = f"/usr/share/zoneinfo/{gmt_zone}"
                    
                    # 优先使用posix路径，如果不存在则使用普通路径
                    target_path = posix_zoneinfo_path if os.path.exists(posix_zoneinfo_path) else zoneinfo_path
                    
                    if os.path.exists(target_path):
                        try:
                            # 删除现有的localtime文件/链接
                            if os.path.exists("/etc/localtime"):
                                os.remove("/etc/localtime")
                            # 创建新的符号链接
                            os.symlink(target_path, "/etc/localtime")
                            await aiotools.run_async(os.sync)
                            self._logger.info(f"Created /etc/localtime symlink to: {target_path}")
                        except Exception as e:
                            self._logger.warning(f"Failed to create /etc/localtime symlink: {e}")
                    else:
                        self._logger.warning(f"GMT timezone file not found: {target_path}")
                    
                    self._logger.info(f"Successfully set timezone to: {gmt_zone} (offset: {timezone_offset} minutes)")
                    
                except ValueError as e:
                    raise BadRequestError(f"Invalid time_zone parameter: {str(e)}")
            
            # 设置系统时间
            if time_param:
                try:
                    try:
                        timestamp = int(time_param)
                    except ValueError:
                        raise BadRequestError("time parameter must be a valid Unix timestamp (integer)")
                    
                    if timestamp < 0 or timestamp > 2147483647:  # 32位时间戳范围
                        raise BadRequestError("time parameter out of valid range")
                    
                    # 使用date -s "@timestamp"直接设置Unix时间戳
                    returncode, _, stderr_text = await run_command(
                        "date", "-s", f"@{timestamp}", timeout=30
                    )
                    
                    if returncode != 0:
                        self._logger.error(f"Failed to set time with date -s @{timestamp}: {stderr_text}")
                        raise BadRequestError(f"Failed to set time with date -s @{timestamp}: {stderr_text}")
                    
                    # 同步硬件时钟
                    try:
                        await run_command("hwclock", "-w", timeout=10)
                        self._logger.info("Hardware clock synchronized")
                    except Exception as e:
                        self._logger.warning(f"Failed to sync hardware clock: {e}")
                    
                    # 将时间戳转换为可读格式用于日志
                    dt = datetime.fromtimestamp(timestamp)
                    self._logger.info(f"Successfully set time to timestamp: {timestamp} ({dt.strftime('%Y-%m-%d %H:%M:%S')})")
                    
                except Exception as e:
                    raise BadRequestError(f"Failed to set time with date -s @{timestamp}: {e}")
            
            return make_json_response()
            
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting system time: {e}")
            return make_json_exception(BadRequestError(f"Error setting system time: {str(e)}"), 502)

    # ===================== Timezone by city APIs =====================

    _ZONEINFO_BASE = "/usr/share/zoneinfo"
    _TIMEZONE_REGIONS = (
        "Africa", "America", "Antarctica", "Arctic", "Asia",
        "Atlantic", "Australia", "Europe", "Indian", "Pacific",
    )
    _timezone_list_cache: Optional[List[str]] = None

    def _build_timezone_list(self) -> List[str]:
        """扫描zoneinfo目录，构建有效IANA时区列表并缓存"""
        if SystemApi._timezone_list_cache is not None:
            return SystemApi._timezone_list_cache

        result: List[str] = []
        base = self._ZONEINFO_BASE
        for region in self._TIMEZONE_REGIONS:
            region_dir = os.path.join(base, region)
            if not os.path.isdir(region_dir):
                continue
            for root, _dirs, files in os.walk(region_dir):
                for fname in sorted(files):
                    full = os.path.join(root, fname)
                    # 跳过非文件（符号链接也算）
                    rel = os.path.relpath(full, base)
                    result.append(rel)
        result.sort()
        SystemApi._timezone_list_cache = result
        return result

    @staticmethod
    def _is_valid_tz_name(tz: str) -> bool:
        """验证时区名称是否安全（防路径穿越）"""
        # 不允许空、以/开头、包含..、包含连续/
        if not tz or tz.startswith("/") or ".." in tz or "//" in tz:
            return False
        # 只允许字母、数字、下划线、连字符、加号、斜杠
        if not re.match(r'^[A-Za-z0-9_/+\-]+$', tz):
            return False
        return True

    @exposed_http("GET", "/system/timezone/list")
    async def get_timezone_list_handler(self, request: Request) -> Response:
        """获取可用的IANA时区列表"""
        try:
            region = request.query.get("region")
            tz_list = self._build_timezone_list()

            if region:
                # 按地区过滤
                if region not in self._TIMEZONE_REGIONS:
                    raise BadRequestError(
                        f"Invalid region: {region}. Valid regions: {', '.join(self._TIMEZONE_REGIONS)}"
                    )
                tz_list = [tz for tz in tz_list if tz.startswith(region + "/")]

            return make_json_response({
                "success": True,
                "timezones": tz_list,
                "count": len(tz_list)
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error listing timezones: {e}")
            return make_json_exception(BadRequestError(f"Error listing timezones: {str(e)}"), 502)

    @exposed_http("POST", "/system/timezone")
    async def set_timezone_handler(self, request: Request) -> Response:
        """按IANA城市名称设置系统时区"""
        try:
            tz_name = request.query.get("timezone", "").strip()
            if not tz_name:
                raise BadRequestError("timezone parameter is required (e.g. Asia/Shanghai)")

            # 安全校验
            if not self._is_valid_tz_name(tz_name):
                raise BadRequestError(f"Invalid timezone name: {tz_name}")

            # 检查时区文件是否存在
            tz_file = os.path.join(self._ZONEINFO_BASE, tz_name)
            if not os.path.isfile(tz_file):
                raise BadRequestError(f"Timezone not found: {tz_name}")

            # 确认路径没有逃逸出zoneinfo目录
            real_base = os.path.realpath(self._ZONEINFO_BASE)
            real_tz = os.path.realpath(tz_file)
            if not real_tz.startswith(real_base + "/"):
                raise BadRequestError(f"Invalid timezone path: {tz_name}")

            # 设置/etc/localtime符号链接
            try:
                if os.path.exists("/etc/localtime") or os.path.islink("/etc/localtime"):
                    os.remove("/etc/localtime")
                os.symlink(tz_file, "/etc/localtime")
                await aiotools.run_async(os.sync)
                self._logger.info(f"Set timezone to {tz_name} -> {tz_file}")
            except OSError as e:
                self._logger.error(f"Failed to set /etc/localtime: {e}")
                raise BadRequestError(f"Failed to set timezone: {e}")

            return make_json_response({
                "success": True,
                "timezone": tz_name
            })

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting timezone: {e}")
            return make_json_exception(BadRequestError(f"Error setting timezone: {str(e)}"), 502)

    @exposed_http("GET", "/system/get_config")
    async def get_config_handler(self, request: Request) -> Response:
        """获取用户配置处理器"""
        try:
            config = await self._read_user_config()
            return make_json_response({
                "success": True,
                "config": config
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error getting user config: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/system/set_config")
    async def set_config_handler(self, request: Request) -> Response:
        """设置用户配置处理器"""
        try:
            # 读取请求体中的JSON数据
            data = await request.json()
            
            if not isinstance(data, dict):
                raise BadRequestError("Configuration data must be in JSON object format")
                
            # 写入配置文件
            await self._write_user_config(data)
            
            return make_json_response({
                "success": True,
                "config": data
            })
        except json.JSONDecodeError:
            return make_json_exception(BadRequestError("Invalid JSON format"), 400)
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting user config: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("GET", "/system/get_firewall_config")
    async def get_firewall_config_handler(self, request: Request) -> Response:
        firewall_conf_path = "/etc/glinet/firewall.conf"
        try:
            if os.path.exists(firewall_conf_path):
                with open(firewall_conf_path, "r") as f:
                    config = f.read()
                    config_json = json.loads(config)
                    enable = config_json.get("enable", True)
                    enable_v6 = config_json.get("enable_v6", True)
                    whitelist = config_json.get("whitelist", {})

                return make_json_response({
                    "success": True,
                    "enable": enable,
                    "enable_v6": enable_v6,
                    "whitelist": whitelist
                })

        except Exception as e:
            self._logger.error(f"Error getting firewall status: {e}")
            return make_json_exception(BadRequestError(f"Error getting firewall status: {str(e)}"), 502)

    @exposed_http("POST", "/system/set_firewall_config")
    async def set_firewall_rules_handler(self, request: Request) -> Response:
        firewall_conf_path = "/etc/glinet/firewall.conf"
        try:
            data = await request.json()
            whitelist = data.get("whitelist")
            enable = data.get("enable", True)
            enable_v6 = data.get("enable_v6", True)

            if not isinstance(whitelist, dict):
                raise BadRequestError("Whitelist format is invalid.")

            # 当开启 IPv4 防火墙时，whitelist 中必须包含 wwan0
            if enable and not isinstance(whitelist.get("wwan0"), list):
                raise BadRequestError("Whitelist must contain a valid 'wwan0' list when IPv4 firewall is enabled.")

            # 当开启 IPv6 防火墙时，whitelist 中必须包含 wwan0_v6
            if enable_v6 and not isinstance(whitelist.get("wwan0_v6"), list):
                raise BadRequestError("Whitelist must contain a valid 'wwan0_v6' list when IPv6 firewall is enabled.")

            # 构建新的配置
            config_json = {
                "enable": enable,
                "enable_v6": enable_v6,
                "whitelist": whitelist
            }

            # 写入配置文件(不关心已有配置，直接暴力覆盖)
            with open(firewall_conf_path, "w") as f:
                json.dump(config_json, f, indent=4, ensure_ascii=False)

            await asyncio.create_subprocess_shell("sync")
            # 任一开启则 restart，全关则 stop
            if enable or enable_v6:
                await asyncio.create_subprocess_shell("/etc/init.d/S99firewall restart")
            else:
                await asyncio.create_subprocess_shell("/etc/init.d/S99firewall stop")

            return make_json_response({
                "success": True,
                "enable": enable,
                "enable_v6": enable_v6,
                "whitelist": whitelist
            })

        except json.JSONDecodeError:
            return make_json_exception(BadRequestError("Invalid JSON format"), 400)
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting firewall whitelist: {e}")
            return make_json_exception(BadRequestError(f"Error setting firewall whitelist: {str(e)}"), 502)

    @exposed_http("GET", "/system/get_hostname")
    async def get_hostname_handler(self, request: Request) -> Response:
        #获取系统 hostname 处理器
        try:
            if os.path.exists("/etc/hostname"):
                with open("/etc/hostname", "r") as f:
                    hostname = f.read().strip()
            else:
                # 如果文件不存在，使用默认值
                hostname = "glkvm"
            
            return make_json_response({
                "success": True,
                "hostname": hostname
            })
            
        except Exception as e:
            self._logger.error(f"Error getting hostname: {e}")
            return make_json_exception(BadRequestError(f"Error getting hostname: {str(e)}"), 502)

    @exposed_http("POST", "/system/set_hostname")
    async def set_hostname_handler(self, request: Request) -> Response:
        #设置系统 hostname 处理器
        try:
            hostname = request.query.get("hostname")
            
            if not hostname:
                raise BadRequestError("hostname parameter is required")
            
            # 验证 hostname 格式
            if not self._validate_hostname(hostname):
                raise BadRequestError("Invalid hostname format. Hostname must contain only letters, numbers, and hyphens, and cannot start or end with a hyphen.")
            
            # 写入 /etc/hostname 文件
            try:
                with open("/etc/hostname", "w") as f:
                    f.write(hostname + "\n")
                await run_shell("sync")
                self._logger.info(f"Successfully set hostname to: {hostname}")
            except Exception as e:
                self._logger.error(f"Failed to write hostname to /etc/hostname: {e}")
                raise BadRequestError(f"Failed to write hostname: {str(e)}")
            
            await run_command("hostname", hostname)
            await aiotools.run_async(os.sync)
            
            # 重启 gl_mdns 服务使 mDNS 改动生效
            try:
                returncode, _, stderr_text = await run_command(
                    "/usr/bin/gl_mdns", "system", "restart", timeout=30
                )
                
                if returncode != 0:
                    self._logger.warning(f"Failed to restart gl_mdns: {stderr_text}")
                    # 不抛出异常，因为 hostname 已经设置成功，gl_mdns 重启失败不是致命错误
                else:
                    self._logger.info("Successfully restarted gl_mdns service")
                    
            except asyncio.TimeoutError:
                self._logger.warning("gl_mdns restart timeout")
            except Exception as e:
                self._logger.warning(f"Error restarting gl_mdns: {e}")
            
            return make_json_response({
                "success": True,
                "hostname": hostname
            })
            
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting hostname: {e}")
            return make_json_exception(BadRequestError(f"Error setting hostname: {str(e)}"), 502)

    def _validate_hostname(self, hostname: str) -> bool:
        import re

        if not hostname:
            return False

        # hostname 长度限制 (1-63 字符)
        if len(hostname) > 63:
            return False

        # hostname 只能包含字母、数字和连字符
        # 不能以连字符开始或结束
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$'

        return bool(re.match(pattern, hostname))

    @exposed_http("GET", "/system/ssh_key")
    async def get_ssh_key_handler(self, request: Request) -> Response:
        """获取SSH公钥"""
        try:
            ssh_key_path = "/root/.ssh/authorized_keys"

            if os.path.exists(ssh_key_path):
                with open(ssh_key_path, "r") as f:
                    ssh_key = f.read()
            else:
                ssh_key = ""

            return make_json_response({
                "success": True,
                "ssh_key": ssh_key
            })

        except Exception as e:
            self._logger.error(f"Error getting SSH key: {e}")
            return make_json_exception(BadRequestError(f"Error getting SSH key: {str(e)}"), 502)

    @exposed_http("POST", "/system/ssh_key")
    async def set_ssh_key_handler(self, request: Request) -> Response:
        """设置SSH公钥"""
        try:
            # 从请求体读取SSH公钥
            ssh_key = await request.text()

            # 创建.ssh目录（如果不存在）
            ssh_dir = "/root/.ssh"
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

            # 写入authorized_keys文件
            ssh_key_path = os.path.join(ssh_dir, "authorized_keys")
            with open(ssh_key_path, "w") as f:
                f.write(ssh_key)

            # 设置正确的权限
            os.chmod(ssh_key_path, 0o600)

            # 同步到磁盘
            await run_shell("sync")

            self._logger.info(f"Successfully updated SSH key at {ssh_key_path}")

            return make_json_response({
                "success": True
            })

        except Exception as e:
            self._logger.error(f"Error setting SSH key: {e}")
            return make_json_exception(BadRequestError(f"Error setting SSH key: {str(e)}"), 502)

    async def _restart_nginx(self) -> None:
        """重启 Nginx 服务"""
        try:
            # 等待一小段时间确保响应已发送
            await asyncio.sleep(0.5)

            self._logger.info("Restarting Nginx service...")

            returncode, _, stderr_text = await run_command(
                "/etc/init.d/S99kvmd-nginx", "restart", timeout=30
            )

            if returncode != 0:
                self._logger.error(f"Failed to restart Nginx: {stderr_text}")
            else:
                self._logger.info("Successfully restarted Nginx service")

        except asyncio.TimeoutError:
            self._logger.error("Nginx restart timeout")
        except Exception as e:
            self._logger.error(f"Error restarting Nginx: {e}")

    async def _generate_self_signed_certificate(self) -> tuple[str, str]:
        """生成自签名 ECC 证书

        Returns:
            tuple[str, str]: (证书内容, 私钥内容)
        """
        import tempfile
        import os

        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                key_path = os.path.join(temp_dir, "server.key")
                cert_path = os.path.join(temp_dir, "server.crt")

                # 生成 ECC 私钥
                self._logger.info("Generating self-signed ECC certificate...")
                returncode, _, stderr_text = await run_command(
                    "openssl", "ecparam", "-out", key_path, "-name", "prime256v1", "-genkey",
                    timeout=10
                )

                if returncode != 0:
                    raise RuntimeError(f"Failed to generate ECC key: {stderr_text}")

                # 生成自签名证书
                returncode, _, stderr_text = await run_command(
                    "openssl", "req", "-new", "-x509", "-sha256", "-nodes",
                    "-key", key_path, "-out", cert_path, "-days", "3650",
                    "-subj", "/C=US/O=GLKVM/OU=GLKVM/CN=localhost",
                    timeout=10
                )

                if returncode != 0:
                    raise RuntimeError(f"Failed to generate self-signed certificate: {stderr_text}")

                # 读取生成的证书和私钥
                with open(cert_path, 'r') as f:
                    cert_data = f.read()
                with open(key_path, 'r') as f:
                    key_data = f.read()

                self._logger.info("Self-signed certificate generated successfully")
                return (cert_data, key_data)

        except asyncio.TimeoutError:
            self._logger.error("Certificate generation timeout")
            raise RuntimeError("Certificate generation timeout")
        except Exception as e:
            self._logger.error(f"Error generating certificate: {e}")
            raise RuntimeError(f"Error generating certificate: {str(e)}")

    def _certificates_match(self, cert1: str, key1: str, cert2: str, key2: str) -> bool:
        """比较两组证书是否相同

        Args:
            cert1: 第一个证书内容
            key1: 第一个私钥内容
            cert2: 第二个证书内容
            key2: 第二个私钥内容

        Returns:
            bool: 是否匹配
        """
        # 标准化内容：去除首尾空白符，统一换行符
        def normalize(content: str) -> str:
            return content.strip().replace('\r\n', '\n').replace('\r', '\n')

        try:
            return (normalize(cert1) == normalize(cert2) and
                    normalize(key1) == normalize(key2))
        except Exception as e:
            self._logger.error(f"Error comparing certificates: {e}")
            return False

    async def _ensure_default_certificates(self) -> None:
        """确保默认证书存在且有效

        如果默认证书不存在:
        - 如果当前证书存在，复制当前证书为默认证书
        - 如果当前证书也不存在，生成新的自签名证书作为默认证书

        如果默认证书存在但无效（格式错误、过期、证书密钥不匹配等）:
        - 重新生成默认证书
        """
        try:
            # 检查默认证书是否存在
            default_cert_exists = os.path.exists(self._ssl_cert_default_path)
            default_key_exists = os.path.exists(self._ssl_key_default_path)

            # 如果默认证书存在，验证其有效性
            if default_cert_exists and default_key_exists:
                try:
                    with open(self._ssl_cert_default_path, 'r') as f:
                        default_cert = f.read()
                    with open(self._ssl_key_default_path, 'r') as f:
                        default_key = f.read()

                    # 验证证书格式
                    is_valid, msg = await self._validate_ssl_certificate(default_cert)
                    if not is_valid:
                        self._logger.warning(f"Default certificate is invalid: {msg}, will regenerate")
                    else:
                        # 验证私钥格式
                        is_valid, msg = await self._validate_ssl_key(default_key)
                        if not is_valid:
                            self._logger.warning(f"Default key is invalid: {msg}, will regenerate")
                        else:
                            # 验证证书和私钥是否匹配
                            is_valid, msg = await self._validate_cert_key_match(default_cert, default_key)
                            if not is_valid:
                                self._logger.warning(f"Default certificate and key do not match: {msg}, will regenerate")
                            else:
                                # 所有验证都通过，默认证书有效
                                self._logger.debug("Default certificates exist and are valid")
                                return
                except Exception as e:
                    self._logger.warning(f"Error validating default certificates: {e}, will regenerate")

                # 如果验证失败，删除无效的默认证书，后续会重新生成
                self._logger.info("Removing invalid default certificates")
                try:
                    if os.path.exists(self._ssl_cert_default_path):
                        os.remove(self._ssl_cert_default_path)
                    if os.path.exists(self._ssl_key_default_path):
                        os.remove(self._ssl_key_default_path)
                except Exception as e:
                    self._logger.warning(f"Failed to remove invalid default certificates: {e}")

            # 检查当前证书是否存在
            current_cert_exists = os.path.exists(self._ssl_cert_path)
            current_key_exists = os.path.exists(self._ssl_key_path)

            # 确保 SSL 目录存在
            os.makedirs(self._ssl_dir, mode=0o755, exist_ok=True)

            if current_cert_exists and current_key_exists:
                # 复制当前证书为默认证书
                self._logger.info("Creating default certificates from current certificates")
                with open(self._ssl_cert_path, 'r') as f:
                    cert_data = f.read()
                with open(self._ssl_key_path, 'r') as f:
                    key_data = f.read()
            else:
                # 生成新的自签名证书
                self._logger.info("Generating new self-signed certificates as default")
                cert_data, key_data = await self._generate_self_signed_certificate()

            # 写入默认证书
            with open(self._ssl_cert_default_path, 'w') as f:
                f.write(cert_data)
            os.chmod(self._ssl_cert_default_path, 0o644)

            with open(self._ssl_key_default_path, 'w') as f:
                f.write(key_data)
            os.chmod(self._ssl_key_default_path, 0o600)

            # 同步到磁盘
            await run_shell("sync")

            self._logger.info("Default certificates created successfully")

        except Exception as e:
            self._logger.warning(f"Failed to ensure default certificates: {e}")

    async def _validate_ssl_certificate(self, cert_data: str) -> tuple[bool, str]:
        """验证 SSL 证书格式"""
        try:
            # 创建临时文件保存证书
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(cert_data)
                temp_cert_path = f.name

            try:
                # 使用 openssl 验证证书
                returncode, _, stderr_text = await run_command(
                    "openssl", "x509", "-in", temp_cert_path, "-noout", "-text",
                    timeout=10
                )

                if returncode != 0:
                    return False, f"Invalid certificate format: {stderr_text}"

                return True, "Certificate is valid"

            finally:
                # 清理临时文件
                if os.path.exists(temp_cert_path):
                    os.remove(temp_cert_path)

        except asyncio.TimeoutError:
            return False, "Certificate validation timeout"
        except Exception as e:
            return False, f"Error validating certificate: {str(e)}"

    async def _validate_ssl_key(self, key_data: str) -> tuple[bool, str]:
        """验证 SSL 私钥格式（支持 RSA 和 ECC）"""
        try:
            # 创建临时文件保存密钥
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
                f.write(key_data)
                temp_key_path = f.name

            try:
                # 首先尝试作为 RSA 密钥验证
                returncode, _, _ = await run_command(
                    "openssl", "rsa", "-in", temp_key_path, "-noout", "-check",
                    timeout=10
                )

                if returncode == 0:
                    return True, "RSA private key is valid"

                # 如果 RSA 验证失败，尝试作为 ECC 密钥验证
                returncode, _, stderr_text = await run_command(
                    "openssl", "ec", "-in", temp_key_path, "-noout", "-check",
                    timeout=10
                )

                if returncode == 0:
                    return True, "EC private key is valid"

                return False, f"Invalid private key format: {stderr_text}"

            finally:
                # 清理临时文件
                if os.path.exists(temp_key_path):
                    os.remove(temp_key_path)

        except asyncio.TimeoutError:
            return False, "Private key validation timeout"
        except Exception as e:
            return False, f"Error validating private key: {str(e)}"

    async def _validate_cert_key_match(self, cert_data: str, key_data: str) -> tuple[bool, str]:
        """验证证书和私钥是否匹配"""
        try:
            import tempfile

            # 创建临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(cert_data)
                temp_cert_path = f.name

            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
                f.write(key_data)
                temp_key_path = f.name

            try:
                # 获取证书的公钥
                returncode, cert_pubkey, _ = await run_command(
                    "openssl", "x509", "-in", temp_cert_path, "-noout", "-pubkey",
                    timeout=10
                )
                if returncode != 0:
                     return False, "Failed to get certificate public key"

                # 获取私钥对应的公钥
                returncode, key_pubkey, _ = await run_command(
                    "openssl", "pkey", "-in", temp_key_path, "-pubout",
                    timeout=10
                )
                if returncode != 0:
                     return False, "Failed to get private key public key"

                # 比较两个公钥
                if cert_pubkey == key_pubkey:
                    return True, "Certificate and private key match"
                else:
                    return False, "Certificate and private key do not match"

            finally:
                # 清理临时文件
                if os.path.exists(temp_cert_path):
                    os.remove(temp_cert_path)
                if os.path.exists(temp_key_path):
                    os.remove(temp_key_path)

        except asyncio.TimeoutError:
            return False, "Certificate and key match validation timeout"
        except Exception as e:
            return False, f"Error validating certificate and key match: {str(e)}"

    async def _validate_ca_certificate(self, ca_data: str) -> tuple[bool, str]:
        """验证 CA 证书链格式（可能包含多个证书）"""
        try:
            # 创建临时文件保存 CA 证书
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(ca_data)
                temp_ca_path = f.name

            try:
                # 使用 openssl 验证 CA 证书链
                # 使用 -inform PEM 明确指定格式
                returncode, p7_data, stderr_text = await run_command(
                    "openssl", "crl2pkcs7", "-nocrl", "-certfile", temp_ca_path,
                    timeout=10
                )

                if returncode != 0:
                    return False, f"Invalid CA certificate format: {stderr_text}"

                # 验证 PKCS7 格式
                returncode, _, stderr_text = await run_command(
                    "openssl", "pkcs7", "-print_certs", "-noout",
                    input=p7_data.encode(),
                    timeout=10
                )

                if returncode != 0:
                    return False, f"Invalid CA certificate chain: {stderr_text}"

                return True, "CA certificate chain is valid"

            finally:
                # 清理临时文件
                if os.path.exists(temp_ca_path):
                    os.remove(temp_ca_path)

        except asyncio.TimeoutError:
            return False, "CA certificate validation timeout"
        except Exception as e:
            return False, f"Error validating CA certificate: {str(e)}"

    async def _regenerate_and_save_default_certificates(self) -> tuple[str, str]:
        """重新生成并保存默认证书

        Returns:
            tuple[str, str]: (证书内容, 私钥内容)
        """
        # 重新生成默认证书
        default_cert, default_key = await self._generate_self_signed_certificate()

        # 保存新生成的默认证书
        with open(self._ssl_cert_default_path, 'w') as f:
            f.write(default_cert)
        os.chmod(self._ssl_cert_default_path, 0o644)

        with open(self._ssl_key_default_path, 'w') as f:
            f.write(default_key)
        os.chmod(self._ssl_key_default_path, 0o600)

        self._logger.info("Default certificates regenerated successfully")
        return default_cert, default_key

    @exposed_http("GET", "/system/ssl_cert")
    async def get_ssl_cert_handler(self, request: Request) -> Response:
        """获取 SSL 证书和私钥，并返回是否为默认证书"""
        try:
            ssl_cert = ""
            ssl_key = ""
            is_default = True

            # 读取证书文件
            if os.path.exists(self._ssl_cert_path):
                with open(self._ssl_cert_path, "r") as f:
                    ssl_cert = f.read()

            # 读取私钥文件
            if os.path.exists(self._ssl_key_path):
                with open(self._ssl_key_path, "r") as f:
                    ssl_key = f.read()

            # 检查是否为默认证书
            if (os.path.exists(self._ssl_cert_default_path) and
                os.path.exists(self._ssl_key_default_path) and
                ssl_cert and ssl_key):
                # 读取默认证书
                with open(self._ssl_cert_default_path, "r") as f:
                    default_cert = f.read()
                with open(self._ssl_key_default_path, "r") as f:
                    default_key = f.read()

                # 比较当前证书和默认证书
                is_default = self._certificates_match(ssl_cert, ssl_key, default_cert, default_key)

            return make_json_response({
                "success": True,
                "ssl_cert": ssl_cert,
                "ssl_key": ssl_key,
                "is_default": is_default
            })

        except Exception as e:
            self._logger.error(f"Error getting SSL certificate: {e}")
            return make_json_exception(BadRequestError(f"Error getting SSL certificate: {str(e)}"), 502)

    @exposed_http("POST", "/system/ssl_cert")
    async def set_ssl_cert_handler(self, request: Request) -> Response:
        """设置 SSL 证书和私钥，如果请求体为空则恢复默认证书"""
        try:
            # 确保默认证书存在
            await self._ensure_default_certificates()

            # 从请求体读取 JSON 数据
            data = await request.json()

            # 获取参数
            ssl_cert = data.get("ssl_cert")
            ssl_key = data.get("ssl_key")
            ssl_ca = data.get("ssl_ca")  # 可选的 CA 证书链

            # 检查是否为恢复默认证书的请求（body 为空或只有空值）
            if not ssl_cert and not ssl_key:
                self._logger.info("Restoring default SSL certificates")

                # 检查默认证书是否存在
                if not os.path.exists(self._ssl_cert_default_path) or not os.path.exists(self._ssl_key_default_path):
                    raise BadRequestError("Default certificates do not exist")

                # 读取默认证书
                with open(self._ssl_cert_default_path, 'r') as f:
                    default_cert = f.read()
                with open(self._ssl_key_default_path, 'r') as f:
                    default_key = f.read()

                # 验证默认证书格式
                is_valid, msg = await self._validate_ssl_certificate(default_cert)
                if not is_valid:
                    self._logger.warning(f"Default certificate is invalid: {msg}, regenerating...")
                    default_cert, default_key = await self._regenerate_and_save_default_certificates()
                # 验证私钥格式（仅在证书有效时验证）
                elif not (is_valid := await self._validate_ssl_key(default_key))[0]:
                    self._logger.warning(f"Default key is invalid: {is_valid[1]}, regenerating...")
                    default_cert, default_key = await self._regenerate_and_save_default_certificates()
                # 验证证书和私钥是否匹配（仅在前两项都有效时验证）
                elif not (is_valid := await self._validate_cert_key_match(default_cert, default_key))[0]:
                    self._logger.warning(f"Default certificate and key do not match: {is_valid[1]}, regenerating...")
                    default_cert, default_key = await self._regenerate_and_save_default_certificates()

                # 创建 SSL 目录（如果不存在）
                os.makedirs(self._ssl_dir, mode=0o755, exist_ok=True)

                # 将默认证书写入当前证书路径
                with open(self._ssl_cert_path, "w") as f:
                    f.write(default_cert.rstrip() + "\n")
                os.chmod(self._ssl_cert_path, 0o644)

                with open(self._ssl_key_path, "w") as f:
                    f.write(default_key.rstrip() + "\n")
                os.chmod(self._ssl_key_path, 0o600)

                # 同步到磁盘
                await run_shell("sync")

                self._logger.info("Successfully restored default SSL certificates")

                # 创建异步任务在后台重启 Nginx，不等待完成
                asyncio.create_task(self._restart_nginx())

                # 立即返回响应给前端
                return make_json_response({
                    "success": True,
                    "message": "Default SSL certificate and key restored successfully, Nginx will be restarted"
                })

            # 验证必需参数
            if not ssl_cert:
                raise BadRequestError("ssl_cert parameter is required")
            if not ssl_key:
                raise BadRequestError("ssl_key parameter is required")

            # 验证证书格式
            is_valid, msg = await self._validate_ssl_certificate(ssl_cert)
            if not is_valid:
                raise BadRequestError(f"Certificate validation failed: {msg}")

            self._logger.info(f"Certificate validation: {msg}")

            # 验证私钥格式
            is_valid, msg = await self._validate_ssl_key(ssl_key)
            if not is_valid:
                raise BadRequestError(f"Private key validation failed: {msg}")

            self._logger.info(f"Private key validation: {msg}")

            # 验证证书和私钥是否匹配
            is_valid, msg = await self._validate_cert_key_match(ssl_cert, ssl_key)
            if not is_valid:
                raise BadRequestError(f"Certificate and key match validation failed: {msg}")

            self._logger.info(f"Certificate and key match validation: {msg}")

            # 如果提供了 CA 证书，验证其格式
            if ssl_ca:
                is_valid, msg = await self._validate_ca_certificate(ssl_ca)
                if not is_valid:
                    raise BadRequestError(f"CA certificate validation failed: {msg}")

                self._logger.info(f"CA certificate validation: {msg}")

            # 创建 SSL 目录（如果不存在）
            os.makedirs(self._ssl_dir, mode=0o755, exist_ok=True)

            # 保存证书文件
            # 如果提供了 CA 证书，将服务器证书和 CA 证书链合并
            if ssl_ca:
                # 确保证书之间有换行符
                cert_content = ssl_cert.rstrip() + "\n" + ssl_ca.rstrip() + "\n"
            else:
                cert_content = ssl_cert.rstrip() + "\n"

            with open(self._ssl_cert_path, "w") as f:
                f.write(cert_content)

            # 设置证书文件权限（644 - 可读）
            os.chmod(self._ssl_cert_path, 0o644)

            # 保存私钥文件
            with open(self._ssl_key_path, "w") as f:
                f.write(ssl_key.rstrip() + "\n")

            # 设置私钥文件权限（600 - 仅 root 可读写）
            os.chmod(self._ssl_key_path, 0o600)

            # 同步到磁盘
            await run_shell("sync")

            self._logger.info(f"Successfully saved SSL certificate to {self._ssl_cert_path} and key to {self._ssl_key_path}")

            # 创建异步任务在后台重启 Nginx，不等待完成
            asyncio.create_task(self._restart_nginx())

            # 立即返回响应给前端
            return make_json_response({
                "success": True,
                "message": "SSL certificate and key saved successfully, Nginx will be restarted"
            })

        except json.JSONDecodeError:
            return make_json_exception(BadRequestError("Invalid JSON format"), 400)
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting SSL certificate: {e}")
            return make_json_exception(BadRequestError(f"Error setting SSL certificate: {str(e)}"), 502)

    # ===== OTG Restart

    async def __restart_otg(self) -> None:
        """通过 kvmd-otg stop + start 子进程完整重建 OTG gadget"""
        self._logger.info("Restarting OTG gadget: stop + start ...")

        # stop
        returncode, _, stderr = await run_command("kvmd-otg", "stop", timeout=30)
        if returncode != 0:
            self._logger.error("kvmd-otg stop failed: %s", stderr)
            raise BadRequestError(f"kvmd-otg stop failed: {stderr}")

        # start
        returncode, _, stderr = await run_command("kvmd-otg", "start", timeout=30)
        if returncode != 0:
            self._logger.error("kvmd-otg start failed: %s", stderr)
            raise BadRequestError(f"kvmd-otg start failed: {stderr}")

        self._logger.info("OTG gadget restarted successfully")

    async def __change_otg_functions(self, enable: set[str], disable: set[str]) -> None:
        """通过 kvmd-otgconf link/unlink 指定 function，无需重建整个 gadget"""
        args: list[str] = []
        if enable:
            args += ["-e"] + sorted(enable)
        if disable:
            args += ["-d"] + sorted(disable)
        if not args:
            return
        returncode, _, stderr = await run_command("kvmd-otgconf", *args, timeout=30)
        if returncode != 0:
            self._logger.warning("kvmd-otgconf failed (rc=%d): %s", returncode, stderr)
            raise BadRequestError(f"kvmd-otgconf failed: {stderr}")
        else:
            self._logger.info("OTG functions updated successfully")

    @exposed_http("POST", "/system/reinit_udc")
    async def reinit_udc_handler(self, request: Request) -> Response:
        """重新初始化 OTG gadget（通过 stop+start 完整重建）"""
        try:
            async with self.__otg_lock:
                await self.__restart_otg()

            return make_json_response({
                "success": True,
                "message": "OTG gadget restarted successfully"
            })

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error restarting OTG gadget: {e}")
            return make_json_exception(BadRequestError(f"Error restarting OTG gadget: {str(e)}"), 502)

    # ===== NTP

    _NTP_CONF_PATH = "/etc/ntp.conf"

    def _parse_ntp_servers(self, content: str) -> list:
        """从 ntp.conf 内容中解析 server 列表"""
        servers = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("server "):
                parts = line.split()
                if len(parts) >= 2:
                    servers.append(parts[1])
        return servers

    def _build_ntp_conf(self, servers: list) -> str:
        """根据 server 列表生成完整的 ntp.conf 内容"""
        lines = ["restrict default ignore", ""]
        for s in servers:
            lines.append(f"server {s} iburst")
        lines.append("")
        for s in servers:
            lines.append(f"restrict {s} nomodify notrap noquery")
        lines.append("")
        return "\n".join(lines)

    @exposed_http("GET", "/system/ntp")
    async def get_ntp_handler(self, request: Request) -> Response:
        """获取当前 NTP 服务器列表"""
        try:
            if not os.path.exists(self._NTP_CONF_PATH):
                return make_json_response({"ntp_servers": []})
            with open(self._NTP_CONF_PATH, "r") as f:
                content = f.read()
            servers = self._parse_ntp_servers(content)
            return make_json_response({"ntp_servers": servers})
        except Exception as e:
            self._logger.error(f"Error getting NTP servers: {e}")
            return make_json_exception(BadRequestError(f"Error getting NTP servers: {str(e)}"), 502)

    @exposed_http("POST", "/system/ntp")
    async def set_ntp_handler(self, request: Request) -> Response:
        """设置 NTP 服务器列表（全量替换），重写 /etc/ntp.conf 并重启 ntpd

        请求体格式：
        {
            "ntp_servers": ["pool.ntp.org", "ntp.aliyun.com", ...]
        }

        前端先通过 GET /system/ntp 获取当前列表，在本地做增/删/改后，
        将期望的完整列表 POST 回来即可。
        """
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise BadRequestError("Request body must be a JSON object")
            servers = data.get("ntp_servers")

            if not isinstance(servers, list):
                raise BadRequestError("ntp_servers must be a list")
            if len(servers) == 0:
                raise BadRequestError("ntp_servers must not be empty")
            if len(servers) > 10:
                raise BadRequestError("ntp_servers must not exceed 10 entries")

            import re as _re
            valid_host = _re.compile(
                r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
                r"|^(?:\d{1,3}\.){3}\d{1,3}$"
            )
            cleaned = []
            for s in servers:
                if not isinstance(s, str) or not s.strip():
                    raise BadRequestError("Each NTP server must be a non-empty string")
                s = s.strip()
                if not valid_host.fullmatch(s):
                    raise BadRequestError(f"Invalid NTP server address: {s!r}")
                cleaned.append(s)

            # 写入 /etc/ntp.conf
            conf_content = self._build_ntp_conf(cleaned)
            with open(self._NTP_CONF_PATH, "w") as f:
                f.write(conf_content)
            self._logger.info(f"Wrote /etc/ntp.conf with servers: {cleaned}")

            # 同时写入持久化路径，升级后由 S49ntp 恢复
            _NTP_USER_CONF = "/etc/kvmd/user/ntp.conf"
            os.makedirs(os.path.dirname(_NTP_USER_CONF), exist_ok=True)
            with open(_NTP_USER_CONF, "w") as f:
                f.write(conf_content)
                
            # sync 文件系统
            await run_shell("sync")

            # 重启 ntpd
            returncode, _, stderr_text = await run_command(
                "/etc/init.d/S49ntp", "restart", timeout=30
            )
            if returncode != 0:
                self._logger.warning(f"ntpd restart returned non-zero: {stderr_text}")

            return make_json_response({"success": True})

        except json.JSONDecodeError:
            return make_json_exception(BadRequestError("Invalid JSON format"), 400)
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting NTP servers: {e}")
            return make_json_exception(BadRequestError(f"Error setting NTP servers: {str(e)}"), 502)
