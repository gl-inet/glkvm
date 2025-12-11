





















import os
import yaml
import json
import subprocess
import re
from typing import Dict, Any, Optional
import asyncio
from datetime import datetime
from .... import aiotools

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
from ....logging import get_logger



logger = get_logger()


class SystemApi:
    def __init__(self) -> None:
        self._logger = logger
        self._config_path = "/etc/kvmd/user/boot.yaml"
        self._user_config_path = "/etc/kvmd/user/config.json"
        self._network_config_path = "/etc/kvmd/user/network.json"
        self._ssl_dir = "/etc/kvmd/user/ssl"
        self._ssl_cert_path = "/etc/kvmd/user/ssl/server.crt"
        self._ssl_key_path = "/etc/kvmd/user/ssl/server.key"
        self._usb_pid_path = "/proc/gl-hw-info/usb_pid"


        self._param_validators = {
            "kvmd/streamer/quality": valid_stream_quality,
            "kvmd/gpio/state/enabled": valid_bool,

        }


    def _validate_hex_to_int(self, value: str, param_name: str) -> int:
        """验证并转换16进制字符串为整数"""
        try:

            clean_value = value.lower().replace("0x", "")

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

                    return int(pid_str)
        except Exception as e:
            self._logger.warning(f"Failed to read USB PID from {self._usb_pid_path}: {e}")

        return 260

    async def _get_ethernet_service_id(self) -> Optional[str]:
        """获取以太网服务ID"""
        try:

            process = await asyncio.create_subprocess_exec(
                "connmanctl", "services",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

            if process.returncode != 0:
                stderr_text = stderr.decode() if stderr else ""
                self._logger.error(f"connmanctl services command failed: {stderr_text}")
                return None


            stdout_text = stdout.decode() if stdout else ""
            for line in stdout_text.split('\n'):
                if 'ethernet' in line.lower():

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
            ipv4_config_info = ""

            for line in lines:
                line = line.strip()


                if line.startswith('State = '):
                    config["state"] = line.split('=')[1].strip()


                elif line.startswith('Ethernet = '):
                    ethernet_info = line.split('=', 1)[1].strip()

                    ethernet_info = ethernet_info.strip('[ ]')

                    interface_match = re.search(r'Interface=(\w+)', ethernet_info)
                    if interface_match:
                        config["interface"] = interface_match.group(1)

                    address_match = re.search(r'Address=([0-9A-Fa-f:]+)', ethernet_info)
                    if address_match:
                        config["mac_address"] = address_match.group(1)


                elif line.startswith('IPv4.Configuration = '):
                    ipv4_config_info = line.split('=', 1)[1].strip()

                    ipv4_config_info = ipv4_config_info.strip('[ ]')

                    if 'Method=dhcp' in ipv4_config_info:
                        config["is_dhcp"] = True
                    elif 'Method=manual' in ipv4_config_info:
                        config["is_dhcp"] = False


                elif line.startswith('IPv4 = '):
                    ipv4_info = line.split('=', 1)[1].strip()

                    ipv4_info = ipv4_info.strip('[ ]')


                    ip_match = re.search(r'Address=([0-9.]+)', ipv4_info)
                    if ip_match:
                        config["ip_address"] = ip_match.group(1)


                    netmask_match = re.search(r'Netmask=([0-9.]+)', ipv4_info)
                    if netmask_match:
                        config["netmask"] = netmask_match.group(1)


                    gateway_match = re.search(r'Gateway=([0-9.]+)', ipv4_info)
                    if gateway_match:
                        config["gateway"] = gateway_match.group(1)


                elif line.startswith('Nameservers = '):
                    nameservers_info = line.split('=', 1)[1].strip()

                    nameservers_info = nameservers_info.strip('[ ]')

                    ipv4_dns_match = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', nameservers_info)
                    config["dns_servers"] = ipv4_dns_match


            if ipv4_config_info:

                if not config["ip_address"]:
                    ip_match = re.search(r'Address=([0-9.]+)', ipv4_config_info)
                    if ip_match:
                        config["ip_address"] = ip_match.group(1)


                if not config["netmask"]:
                    netmask_match = re.search(r'Netmask=([0-9.]+)', ipv4_config_info)
                    if netmask_match:
                        config["netmask"] = netmask_match.group(1)


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

            service_id = await self._get_ethernet_service_id()
            if not service_id:
                raise BadRequestError("Ethernet service not found")


            process = await asyncio.create_subprocess_exec(
                "connmanctl", "services", service_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

            if process.returncode != 0:
                stderr_text = stderr.decode() if stderr else ""
                self._logger.error(f"connmanctl services {service_id} command failed: {stderr_text}")
                raise BadRequestError("connmanctl services command failed")


            stdout_text = stdout.decode() if stdout else ""
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

            service_id = await self._get_ethernet_service_id()
            if not service_id:
                raise BadRequestError("Ethernet service not found")


            mode = request.query.get("mode")
            ip_address = request.query.get("ip_address")
            netmask = request.query.get("netmask")
            gateway = request.query.get("gateway")
            dns_servers = request.query.get("dns_servers")

            if not mode:
                raise BadRequestError("mode parameter is required, must be 'dhcp' or 'static'")

            if mode not in ["dhcp", "static"]:
                raise BadRequestError("mode parameter must be 'dhcp' or 'static'")


            if mode == "static":
                if not ip_address or not netmask or not gateway:
                    raise BadRequestError("Static IP mode requires ip_address, netmask and gateway parameters")


                if not self._validate_ipv4_address(ip_address):
                    raise BadRequestError("ip_address format is invalid")
                if not self._validate_ipv4_address(netmask):
                    raise BadRequestError("netmask format is invalid")
                if not self._validate_ipv4_address(gateway):
                    raise BadRequestError("gateway format is invalid")


            if mode == "dhcp":

                process = await asyncio.create_subprocess_exec(
                    "connmanctl", "config", service_id, "--ipv4", "dhcp",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

                if process.returncode != 0:
                    stderr_text = stderr.decode() if stderr else ""
                    self._logger.error(f"Failed to set DHCP mode: {stderr_text}")
                    raise BadRequestError(f"Failed to set DHCP mode: {stderr_text}")


                process = await asyncio.create_subprocess_exec(
                    "connmanctl", "config", service_id, "--nameservers", "",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

                if process.returncode != 0:
                    stderr_text = stderr.decode() if stderr else ""
                    self._logger.error(f"Failed to set DHCP DNS: {stderr_text}")
                    raise BadRequestError(f"Failed to set DHCP DNS: {stderr_text}")

                self._logger.info("Successfully switched to DHCP mode")

            else:

                process = await asyncio.create_subprocess_exec(
                    "connmanctl", "config", service_id, "--ipv4", "manual", ip_address, netmask, gateway,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

                if process.returncode != 0:
                    stderr_text = stderr.decode() if stderr else ""
                    self._logger.error(f"Failed to set static IP: {stderr_text}")
                    raise BadRequestError(f"Failed to set static IP: {stderr_text}")

                self._logger.info(f"Successfully set static IP: {ip_address}/{netmask}, gateway: {gateway}")


            if dns_servers is not None:
                if dns_servers.strip():

                    dns_list = [dns.strip() for dns in dns_servers.split(",") if dns.strip()]


                    for dns in dns_list:
                        if not self._validate_ipv4_address(dns):
                            raise BadRequestError(f"Invalid DNS server address format: {dns}")


                    dns_cmd = ["connmanctl", "config", service_id, "nameservers"] + dns_list
                    process = await asyncio.create_subprocess_exec(
                        *dns_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )

                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

                    if process.returncode != 0:
                        stderr_text = stderr.decode() if stderr else ""
                        self._logger.error(f"Failed to set DNS servers: {stderr_text}")
                        raise BadRequestError(f"Failed to set DNS servers: {stderr_text}")

                    self._logger.info(f"Successfully set DNS servers: {', '.join(dns_list)}")
                else:

                    dns_cmd = ["connmanctl", "config", service_id, "nameservers"]
                    process = await asyncio.create_subprocess_exec(
                        *dns_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )

                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

                    if process.returncode != 0:
                        stderr_text = stderr.decode() if stderr else ""
                        self._logger.error(f"Failed to set DHCP DNS: {stderr_text}")
                        raise BadRequestError(f"Failed to set DHCP DNS: {stderr_text}")

                    self._logger.info("Successfully set to use DHCP DNS")


            await asyncio.sleep(2)


            network_config = {
                "mode": mode,
            }

            if mode == "static":
                network_config.update({
                    "ip_address": ip_address,
                    "netmask": netmask,
                    "gateway": gateway
                })


            if dns_servers is not None:
                if dns_servers.strip():

                    dns_list = [dns.strip() for dns in dns_servers.split(",") if dns.strip()]
                    network_config["dns_servers"] = dns_list
                    network_config["use_dhcp_dns"] = False
                else:

                    network_config["dns_servers"] = []
                    network_config["use_dhcp_dns"] = True


            await self._write_network_config(network_config)
            self._logger.info(f"Network configuration saved to {self._network_config_path}")




            return make_json_response({
                "success": True,

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
            process = await asyncio.create_subprocess_exec(
                "connmanctl", "services", service_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

            if process.returncode == 0:
                stdout_text = stdout.decode() if stdout else ""
                return await self._parse_connman_output(stdout_text)
            else:
                return {}
        except Exception:
            return {}

    async def _read_yaml(self) -> Dict:
        """读取YAML配置文件"""
        try:
            if os.path.exists(self._config_path):
                with open(self._config_path, "r") as f:
                    return yaml.safe_load(f) or {}
            return {}
        except Exception as e:
            self._logger.error(f"Cannot read config file {self._config_path}: {e}")
            raise BadRequestError(f"Cannot read config file: {e}")

    async def _write_yaml(self, data: Dict) -> None:
        """写入YAML配置文件"""
        try:
            os.makedirs(os.path.dirname(self._config_path), exist_ok=True)
            with open(self._config_path, "w") as f:
                yaml.dump(data, f, default_flow_style=False)
            await asyncio.create_subprocess_shell("sync")
        except Exception as e:
            self._logger.error(f"Cannot write config file {self._config_path}: {e}")
            raise BadRequestError(f"Cannot write config file: {e}")

    def _get_nested_value(self, data: Dict, path: str, default: Any = None) -> Any:
        """获取嵌套字典中的值"""
        keys = path.split("/")
        current = data
        for key in keys:
            if not isinstance(current, dict):
                return default
            current = current.get(key)
        return current if current is not None else default

    def _set_nested_value(self, data: Dict, path: str, value: Any) -> None:
        """设置嵌套字典中的值"""
        keys = path.split("/")
        current = data
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value

    @exposed_http("GET", "/system/get_param")
    async def get_param_handler(self, request: Request) -> Response:
        """获取系统参数处理器"""
        try:
            data = await self._read_yaml()


            usb_pid_from_proc = self._read_usb_pid()


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

                "enable_mic": self._get_nested_value(data, "otg/devices/audio/enabled", False),
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

            absolute_mouse = request.query.get("absolute_mouse")
            msd_partition = request.query.get("msd_partition")
            msd_type = request.query.get("msd_type")

            otg_manufacturer = request.query.get("otg_manufacturer")
            otg_product = request.query.get("otg_product")
            otg_vendor_id = request.query.get("otg_vendor_id")
            otg_product_id = request.query.get("otg_product_id")
            otg_serial = request.query.get("otg_serial")

            enable_mic = request.query.get("enable_mic")


            data = await self._read_yaml()


            if absolute_mouse is not None:
                try:
                    absolute_mouse = valid_bool(absolute_mouse)
                    self._set_nested_value(data, "kvmd/hid/mouse/absolute", absolute_mouse)
                except ValidatorError as e:
                    raise BadRequestError(f"absolute_mouse parameter validation failed: {str(e)}")

            if msd_partition is not None:
                self._set_nested_value(data, "kvmd/msd/partition_device", msd_partition)

            if msd_type is not None:
                if msd_type not in ["otg","disabled"]:
                    raise BadRequestError("msd_type param invalid, must be 'otg' or 'disabled'")
                self._set_nested_value(data, "kvmd/msd/type", msd_type)


            if otg_manufacturer is not None:
                self._set_nested_value(data, "otg/manufacturer", otg_manufacturer)
            if otg_product is not None:
                self._set_nested_value(data, "otg/product", otg_product)
            if otg_vendor_id is not None:
                int_vendor_id = self._validate_hex_to_int(otg_vendor_id, "otg_vendor_id")
                self._set_nested_value(data, "otg/vendor_id", int_vendor_id)
            if otg_product_id is not None:
                int_product_id = self._validate_hex_to_int(otg_product_id, "otg_product_id")
                self._set_nested_value(data, "otg/product_id", int_product_id)
            if otg_serial is not None:
                self._set_nested_value(data, "otg/serial", otg_serial)


            if enable_mic is not None:
                enable_mic = valid_bool(enable_mic)
                self._set_nested_value(data, "otg/devices/audio/enabled", enable_mic)


            await self._write_yaml(data)


            usb_pid_from_proc = self._read_usb_pid()


            return make_json_response({
                "success": True,
                "absolute_mouse": self._get_nested_value(data, "kvmd/hid/mouse/absolute", True),
                "msd_partition": self._get_nested_value(data, "kvmd/msd/partition_device", "/dev/block/by-name/media"),
                "msd_type": self._get_nested_value(data, "kvmd/msd/type", "otg"),
                "otg_manufacturer": self._get_nested_value(data, "otg/manufacturer", "Glinet"),
                "otg_product": self._get_nested_value(data, "otg/product", "Glinet Composite Device"),
                "otg_vendor_id": self._int_to_hex_str(self._get_nested_value(data, "otg/vendor_id", 14571)),
                "otg_product_id": self._int_to_hex_str(self._get_nested_value(data, "otg/product_id", usb_pid_from_proc)),
                "otg_serial": self._get_nested_value(data, "otg/serial", "")
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
            await asyncio.create_subprocess_shell("sync")
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
            await asyncio.create_subprocess_shell("sync")
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


        match = re.match(r'.*GMT([+-])(\d+)', gmt_zone)
        if match:
            sign, hours_str = match.groups()
            hours = int(hours_str)

            if sign == '+':
                return hours * 60
            else:
                return -hours * 60
        return 0

    @exposed_http("GET", "/system/time")
    async def get_time_handler(self, request: Request) -> Response:
        """获取系统时间和时区处理器"""
        try:

            current_timestamp = int(datetime.now().timestamp())


            gmt_zone = "Etc/GMT"
            try:
                if os.path.exists("/etc/localtime"):
                    try:
                        link_target = os.readlink("/etc/localtime")
                        if "/zoneinfo/" in link_target:
                            zone_path = link_target.split("/zoneinfo/")[-1]

                            if zone_path.startswith("Etc/GMT") or zone_path.startswith("posix/Etc/GMT"):
                                gmt_zone = zone_path.replace("posix/", "")
                            else:

                                gmt_zone = "Etc/GMT"
                        else:
                            gmt_zone = "Etc/GMT"
                    except OSError:
                        gmt_zone = "Etc/GMT"

            except Exception as e:
                self._logger.warning(f"Failed to get timezone: {e}")
                gmt_zone = "Etc/GMT"


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

            time_param = request.query.get("time")
            time_zone_param = request.query.get("time_zone")


            if not time_param and not time_zone_param:
                raise BadRequestError("At least one parameter (time or time_zone) is required")


            if time_zone_param:
                try:

                    try:
                        timezone_offset = int(time_zone_param)
                    except ValueError:
                        raise BadRequestError("time_zone parameter must be a valid integer (minutes offset from UTC)")


                    if timezone_offset < -840 or timezone_offset > 840:
                        raise BadRequestError("time_zone parameter out of valid range (-840 to 840 minutes)")


                    gmt_zone = self._get_gmt_zone_from_offset(timezone_offset)


                    posix_zoneinfo_path = f"/usr/share/zoneinfo/posix/{gmt_zone}"
                    zoneinfo_path = f"/usr/share/zoneinfo/{gmt_zone}"


                    target_path = posix_zoneinfo_path if os.path.exists(posix_zoneinfo_path) else zoneinfo_path

                    if os.path.exists(target_path):
                        try:

                            if os.path.exists("/etc/localtime"):
                                os.remove("/etc/localtime")

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


            if time_param:
                try:
                    try:
                        timestamp = int(time_param)
                    except ValueError:
                        raise BadRequestError("time parameter must be a valid Unix timestamp (integer)")

                    if timestamp < 0 or timestamp > 2147483647:
                        raise BadRequestError("time parameter out of valid range")


                    process = await asyncio.create_subprocess_exec(
                        "date", "-s", f"@{timestamp}",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )

                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

                    if process.returncode != 0:
                        stderr_text = stderr.decode() if stderr else ""
                        self._logger.error(f"Failed to set time with date -s @{timestamp}: {stderr_text}")
                        raise BadRequestError(f"Failed to set time with date -s @{timestamp}: {stderr_text}")


                    try:
                        process = await asyncio.create_subprocess_exec(
                            "hwclock", "-w",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )

                        await asyncio.wait_for(process.communicate(), timeout=10)
                        self._logger.info("Hardware clock synchronized")
                    except Exception as e:
                        self._logger.warning(f"Failed to sync hardware clock: {e}")


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

            data = await request.json()

            if not isinstance(data, dict):
                raise BadRequestError("Configuration data must be in JSON object format")


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

    @exposed_http("GET", "/system/get_hostname")
    async def get_hostname_handler(self, request: Request) -> Response:

        try:
            if os.path.exists("/etc/hostname"):
                with open("/etc/hostname", "r") as f:
                    hostname = f.read().strip()
            else:

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

        try:
            hostname = request.query.get("hostname")

            if not hostname:
                raise BadRequestError("hostname parameter is required")


            if not self._validate_hostname(hostname):
                raise BadRequestError("Invalid hostname format. Hostname must contain only letters, numbers, and hyphens, and cannot start or end with a hyphen.")


            try:
                with open("/etc/hostname", "w") as f:
                    f.write(hostname + "\n")
                await asyncio.create_subprocess_shell("sync")
                self._logger.info(f"Successfully set hostname to: {hostname}")
            except Exception as e:
                self._logger.error(f"Failed to write hostname to /etc/hostname: {e}")
                raise BadRequestError(f"Failed to write hostname: {str(e)}")

            await asyncio.create_subprocess_shell("hostname " + hostname)
            await aiotools.run_async(os.sync)


            try:
                process = await asyncio.create_subprocess_exec(
                    "/usr/bin/gl_mdns", "system", "restart",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

                if process.returncode != 0:
                    stderr_text = stderr.decode() if stderr else ""
                    self._logger.warning(f"Failed to restart gl_mdns: {stderr_text}")

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


        if len(hostname) > 63:
            return False



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

            ssh_key = await request.text()


            ssh_dir = "/root/.ssh"
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)


            ssh_key_path = os.path.join(ssh_dir, "authorized_keys")
            with open(ssh_key_path, "w") as f:
                f.write(ssh_key)


            os.chmod(ssh_key_path, 0o600)


            await asyncio.create_subprocess_shell("sync")

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

            await asyncio.sleep(0.5)

            self._logger.info("Restarting Nginx service...")

            process = await asyncio.create_subprocess_exec(
                "/etc/init.d/S99kvmd-nginx", "restart",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            _, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

            if process.returncode != 0:
                stderr_text = stderr.decode() if stderr else ""
                self._logger.error(f"Failed to restart Nginx: {stderr_text}")
            else:
                self._logger.info("Successfully restarted Nginx service")

        except asyncio.TimeoutError:
            self._logger.error("Nginx restart timeout")
        except Exception as e:
            self._logger.error(f"Error restarting Nginx: {e}")

    async def _validate_ssl_certificate(self, cert_data: str) -> tuple[bool, str]:
        """验证 SSL 证书格式"""
        try:

            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(cert_data)
                temp_cert_path = f.name

            try:

                process = await asyncio.create_subprocess_exec(
                    "openssl", "x509", "-in", temp_cert_path, "-noout", "-text",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

                if process.returncode != 0:
                    stderr_text = stderr.decode() if stderr else ""
                    return False, f"Invalid certificate format: {stderr_text}"

                return True, "Certificate is valid"

            finally:

                if os.path.exists(temp_cert_path):
                    os.remove(temp_cert_path)

        except asyncio.TimeoutError:
            return False, "Certificate validation timeout"
        except Exception as e:
            return False, f"Error validating certificate: {str(e)}"

    async def _validate_ssl_key(self, key_data: str) -> tuple[bool, str]:
        """验证 SSL 私钥格式（支持 RSA 和 ECC）"""
        try:

            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
                f.write(key_data)
                temp_key_path = f.name

            try:

                process = await asyncio.create_subprocess_exec(
                    "openssl", "rsa", "-in", temp_key_path, "-noout", "-check",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

                if process.returncode == 0:
                    return True, "RSA private key is valid"


                process = await asyncio.create_subprocess_exec(
                    "openssl", "ec", "-in", temp_key_path, "-noout", "-check",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

                if process.returncode == 0:
                    return True, "EC private key is valid"

                stderr_text = stderr.decode() if stderr else ""
                return False, f"Invalid private key format: {stderr_text}"

            finally:

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


            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(cert_data)
                temp_cert_path = f.name

            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
                f.write(key_data)
                temp_key_path = f.name

            try:

                process = await asyncio.create_subprocess_exec(
                    "openssl", "x509", "-in", temp_cert_path, "-noout", "-pubkey",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                cert_pubkey, _ = await asyncio.wait_for(process.communicate(), timeout=10)


                process = await asyncio.create_subprocess_exec(
                    "openssl", "pkey", "-in", temp_key_path, "-pubout",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                key_pubkey, _ = await asyncio.wait_for(process.communicate(), timeout=10)


                if cert_pubkey == key_pubkey:
                    return True, "Certificate and private key match"
                else:
                    return False, "Certificate and private key do not match"

            finally:

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

            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(ca_data)
                temp_ca_path = f.name

            try:


                process = await asyncio.create_subprocess_exec(
                    "openssl", "crl2pkcs7", "-nocrl", "-certfile", temp_ca_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                p7_data, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

                if process.returncode != 0:
                    stderr_text = stderr.decode() if stderr else ""
                    return False, f"Invalid CA certificate format: {stderr_text}"


                process = await asyncio.create_subprocess_exec(
                    "openssl", "pkcs7", "-print_certs", "-noout",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=p7_data),
                    timeout=10
                )

                if process.returncode != 0:
                    stderr_text = stderr.decode() if stderr else ""
                    return False, f"Invalid CA certificate chain: {stderr_text}"

                return True, "CA certificate chain is valid"

            finally:

                if os.path.exists(temp_ca_path):
                    os.remove(temp_ca_path)

        except asyncio.TimeoutError:
            return False, "CA certificate validation timeout"
        except Exception as e:
            return False, f"Error validating CA certificate: {str(e)}"

    @exposed_http("GET", "/system/ssl_cert")
    async def get_ssl_cert_handler(self, request: Request) -> Response:
        """获取 SSL 证书和私钥"""
        try:
            ssl_cert = ""
            ssl_key = ""


            if os.path.exists(self._ssl_cert_path):
                with open(self._ssl_cert_path, "r") as f:
                    ssl_cert = f.read()


            if os.path.exists(self._ssl_key_path):
                with open(self._ssl_key_path, "r") as f:
                    ssl_key = f.read()

            return make_json_response({
                "success": True,
                "ssl_cert": ssl_cert,
                "ssl_key": ssl_key
            })

        except Exception as e:
            self._logger.error(f"Error getting SSL certificate: {e}")
            return make_json_exception(BadRequestError(f"Error getting SSL certificate: {str(e)}"), 502)

    @exposed_http("POST", "/system/ssl_cert")
    async def set_ssl_cert_handler(self, request: Request) -> Response:
        """设置 SSL 证书和私钥"""
        try:

            data = await request.json()


            ssl_cert = data.get("ssl_cert")
            ssl_key = data.get("ssl_key")
            ssl_ca = data.get("ssl_ca")


            if not ssl_cert:
                raise BadRequestError("ssl_cert parameter is required")
            if not ssl_key:
                raise BadRequestError("ssl_key parameter is required")


            is_valid, msg = await self._validate_ssl_certificate(ssl_cert)
            if not is_valid:
                raise BadRequestError(f"Certificate validation failed: {msg}")

            self._logger.info(f"Certificate validation: {msg}")


            is_valid, msg = await self._validate_ssl_key(ssl_key)
            if not is_valid:
                raise BadRequestError(f"Private key validation failed: {msg}")

            self._logger.info(f"Private key validation: {msg}")


            is_valid, msg = await self._validate_cert_key_match(ssl_cert, ssl_key)
            if not is_valid:
                raise BadRequestError(f"Certificate and key match validation failed: {msg}")

            self._logger.info(f"Certificate and key match validation: {msg}")


            if ssl_ca:
                is_valid, msg = await self._validate_ca_certificate(ssl_ca)
                if not is_valid:
                    raise BadRequestError(f"CA certificate validation failed: {msg}")

                self._logger.info(f"CA certificate validation: {msg}")


            os.makedirs(self._ssl_dir, mode=0o755, exist_ok=True)



            if ssl_ca:

                cert_content = ssl_cert.rstrip() + "\n" + ssl_ca.rstrip() + "\n"
            else:
                cert_content = ssl_cert.rstrip() + "\n"

            with open(self._ssl_cert_path, "w") as f:
                f.write(cert_content)


            os.chmod(self._ssl_cert_path, 0o644)


            with open(self._ssl_key_path, "w") as f:
                f.write(ssl_key.rstrip() + "\n")


            os.chmod(self._ssl_key_path, 0o600)


            await asyncio.create_subprocess_shell("sync")

            self._logger.info(f"Successfully saved SSL certificate to {self._ssl_cert_path} and key to {self._ssl_key_path}")


            asyncio.create_task(self._restart_nginx())


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

