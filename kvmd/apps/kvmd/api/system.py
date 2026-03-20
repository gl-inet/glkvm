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

        self._user_config_path = "/etc/kvmd/user/config.json"
        self._network_config_path = "/etc/kvmd/user/network.json"
        self._ssl_dir = "/etc/kvmd/user/ssl"
        self._ssl_cert_path = "/etc/kvmd/user/ssl/server.crt"
        self._ssl_key_path = "/etc/kvmd/user/ssl/server.key"
        self._ssl_cert_default_path = "/etc/kvmd/user/ssl/server.crt.default"
        self._ssl_key_default_path = "/etc/kvmd/user/ssl/server.key.default"
        self._usb_pid_path = "/proc/gl-hw-info/usb_pid"
        self._capability_path = "/proc/gl-hw-info/capability"

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

            # 从 /proc/gl-hw-info/usb_pid 读取 product_id，如果读取失败则使用配置文件中的值
            usb_pid_from_proc = self._read_usb_pid()

            # 提取所有参数，并设置默认值
            return make_json_response({
                "success": True,
                "absolute_mouse": self._get_nested_value(data, "kvmd/hid/mouse/absolute", True),
                "msd_partition": self._get_nested_value(data, "kvmd/msd/partition_device", "/dev/block/by-name/media"),
                "msd_type": self._get_nested_value(data, "kvmd/msd/type", "otg"),
                # 新增 OTG 相关参数
                "otg_manufacturer": self._get_nested_value(data, "otg/manufacturer", "Glinet"),
                "otg_product": self._get_nested_value(data, "otg/product", "Glinet Composite Device"),
                "otg_vendor_id": self._int_to_hex_str(self._get_nested_value(data, "otg/vendor_id", 14571)),
                "otg_product_id": self._int_to_hex_str(self._get_nested_value(data, "otg/product_id", usb_pid_from_proc)),
                "otg_serial": self._get_nested_value(data, "otg/serial", ""),
                "cdrom_vendor": self._get_nested_value(data, "otg/devices/msd/default/inquiry_string/cdrom/vendor", "Glinet"),
                "flash_vendor": self._get_nested_value(data, "otg/devices/msd/default/inquiry_string/flash/vendor", "Glinet"),
                # 新增麦克风参数
                "enable_mic": self._get_nested_value(data, "otg/devices/audio/enabled", False),
                "mic_name": self._get_nested_value(data, "otg/devices/audio/product", "Comet Microphone"),
                "default_product_id": self._int_to_hex_str(usb_pid_from_proc),
                "default_vendor_id": self._int_to_hex_str(14571),
            })

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error getting system parameters: {e}")
            return make_json_exception(BadRequestError("Error getting system parameters"), 502)

    @exposed_http("POST", "/system/set_param")
    async def set_param_handler(self, request: Request) -> Response:
        """设置系统参数处理器"""
        try:
            # 获取请求参数
            absolute_mouse = request.query.get("absolute_mouse")
            msd_partition = request.query.get("msd_partition")
            msd_type = request.query.get("msd_type")
            # 新增 OTG 相关参数
            otg_manufacturer = request.query.get("otg_manufacturer")
            otg_product = request.query.get("otg_product")
            otg_vendor_id = request.query.get("otg_vendor_id")
            otg_product_id = request.query.get("otg_product_id")
            otg_serial = request.query.get("otg_serial")
            cdrom_vendor = request.query.get("cdrom_vendor")
            flash_vendor = request.query.get("flash_vendor")
            # 新增麦克风参数
            enable_mic = request.query.get("enable_mic")
            mic_name = request.query.get("mic_name")

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

            if msd_type is not None:
                if msd_type not in ["otg","disabled"]:
                    raise BadRequestError("msd_type param invalid, must be 'otg' or 'disabled'")
                self._set_nested_value(data, "kvmd/msd/type", msd_type)

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

            # 设置麦克风参数
            if enable_mic is not None:
                enable_mic = valid_bool(enable_mic)
                self._set_nested_value(data, "otg/devices/audio/enabled", enable_mic)
                if model_name == "rmq1":
                    self._set_nested_value(data, "otg/devices/rndis/enabled", not enable_mic)

            if mic_name is not None:
                # 麦克风名字必须是非空的字符串
                if not mic_name.strip():
                    raise BadRequestError("mic_name parameter cannot be empty")
                self._set_nested_value(data, "otg/devices/audio/product", mic_name)

            # 写入配置
            await self._write_yaml(data)

            # 如果修改了 OTG 参数，通过 stop+start 重建 OTG gadget 以应用配置
            if otg_changed:
                self._logger.info("OTG config changed, restarting OTG gadget to apply ...")
                await self.__restart_otg()

            # 从 /proc/gl-hw-info/usb_pid 读取 product_id
            usb_pid_from_proc = self._read_usb_pid()

            # 返回更新后的值
            return make_json_response({
                "success": True,
                "absolute_mouse": self._get_nested_value(data, "kvmd/hid/mouse/absolute", True),
                "msd_partition": self._get_nested_value(data, "kvmd/msd/partition_device", "/dev/block/by-name/media"),
                "msd_type": self._get_nested_value(data, "kvmd/msd/type", "otg"),
                "otg_manufacturer": self._get_nested_value(data, "otg/manufacturer", "Glinet"),
                "otg_product": self._get_nested_value(data, "otg/product", "Glinet Composite Device"),
                "otg_vendor_id": self._int_to_hex_str(self._get_nested_value(data, "otg/vendor_id", 14571)),
                "otg_product_id": self._int_to_hex_str(self._get_nested_value(data, "otg/product_id", usb_pid_from_proc)),
                "otg_serial": self._get_nested_value(data, "otg/serial", ""),
                "cdrom_vendor": self._get_nested_value(data, "otg/devices/msd/default/inquiry_string/cdrom/vendor", "Glinet"),
                "flash_vendor": self._get_nested_value(data, "otg/devices/msd/default/inquiry_string/flash/vendor", "Glinet"),
                "enable_mic": self._get_nested_value(data, "otg/devices/audio/enabled", False),
                "mic_name": self._get_nested_value(data, "otg/devices/audio/product", "Comet Microphone")
            })
            
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting system parameters: {e}")
            return make_json_exception(BadRequestError(), 502)

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

    @exposed_http("GET", "/system/time")
    async def get_time_handler(self, request: Request) -> Response:
        """获取系统时间和时区处理器"""
        try:
            # 获取系统当前时间戳（秒）
            current_timestamp = int(datetime.now().timestamp())
            
            # 获取系统时区路径
            gmt_zone = "Etc/GMT"
            try:
                if os.path.exists("/etc/localtime"):
                    try:
                        link_target = os.readlink("/etc/localtime")
                        if "/zoneinfo/" in link_target:
                            zone_path = link_target.split("/zoneinfo/")[-1]
                            # 检查是否为GMT格式的时区
                            if zone_path.startswith("Etc/GMT") or zone_path.startswith("posix/Etc/GMT"):
                                gmt_zone = zone_path.replace("posix/", "")
                            else:
                                # 如果不是GMT格式，默认使用GMT
                                gmt_zone = "Etc/GMT"
                        else:
                            gmt_zone = "Etc/GMT"
                    except OSError:
                        gmt_zone = "Etc/GMT"
                        
            except Exception as e:
                self._logger.warning(f"Failed to get timezone: {e}")
                gmt_zone = "Etc/GMT"
            
            # 获取时区偏移量（分钟）
            timezone_offset = self._get_offset_from_gmt_zone(gmt_zone)
            
            return make_json_response({
                "success": True,
                "time": current_timestamp,
                "time_zone": timezone_offset
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

    @exposed_http("POST", "/system/reinit_udc")
    async def reinit_udc_handler(self, request: Request) -> Response:
        """重新初始化 OTG gadget（通过 stop+start 完整重建）"""
        try:
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

