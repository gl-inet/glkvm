





















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


        self._param_validators = {
            "kvmd/streamer/quality": valid_stream_quality,
            "kvmd/gpio/state/enabled": valid_bool,

        }


        self._timezone_map = {

            "Pacific/Kiritimati": -840,
            "Pacific/Tongatapu": -780,
            "Pacific/Auckland": -720,
            "Pacific/Noumea": -660,
            "Australia/Sydney": -600,
            "Asia/Tokyo": -540,
            "Asia/Shanghai": -480,
            "Asia/Bangkok": -420,
            "Asia/Dhaka": -360,
            "Asia/Karachi": -300,
            "Asia/Dubai": -240,
            "Europe/Moscow": -180,
            "Europe/Berlin": -120,
            "Europe/Paris": -60,
            "UTC": 0,
            "Atlantic/Azores": 60,
            "Atlantic/South_Georgia": 120,
            "America/Sao_Paulo": 180,
            "America/New_York": 240,
            "America/Chicago": 300,
            "America/Denver": 360,
            "America/Los_Angeles": 420,
            "America/Anchorage": 480,
            "America/Adak": 540,
            "Pacific/Honolulu": 600,
            "Pacific/Midway": 660,
            "Pacific/Kwajalein": 720,
        }


        self._offset_to_timezone_map = {v: k for k, v in self._timezone_map.items()}

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

    async def _get_ethernet_service_id(self) -> Optional[str]:
        """获取以太网服务ID"""
        try:

            result = subprocess.run(
                ["connmanctl", "services"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self._logger.error(f"connmanctl services command failed: {result.stderr}")
                return None


            for line in result.stdout.split('\n'):
                if 'ethernet' in line.lower():

                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]

            return None

        except subprocess.TimeoutExpired:
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


                elif line.startswith('IPv4 = '):
                    ipv4_info = line.split('=', 1)[1].strip()

                    ipv4_info = ipv4_info.strip('[ ]')

                    if 'Method=dhcp' in ipv4_info:
                        config["is_dhcp"] = True
                    elif 'Method=manual' in ipv4_info:
                        config["is_dhcp"] = False


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


            result = subprocess.run(
                ["connmanctl", "services", service_id],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self._logger.error(f"connmanctl services {service_id} command failed: {result.stderr}")
                raise BadRequestError("connmanctl services command failed")


            config = await self._parse_connman_output(result.stdout)

            return make_json_response({
                "success": True,
                "config": config
            })

        except subprocess.TimeoutExpired:
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

                result = subprocess.run(
                    ["connmanctl", "config", service_id, "--ipv4", "dhcp"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode != 0:
                    self._logger.error(f"Failed to set DHCP mode: {result.stderr}")
                    raise BadRequestError(f"Failed to set DHCP mode: {result.stderr}")


                result = subprocess.run(
                    ["connmanctl", "config", service_id, "--nameservers", ""],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode != 0:
                    self._logger.error(f"Failed to set DHCP DNS: {result.stderr}")
                    raise BadRequestError(f"Failed to set DHCP DNS: {result.stderr}")

                self._logger.info("Successfully switched to DHCP mode")

            else:

                result = subprocess.run(
                    ["connmanctl", "config", service_id, "--ipv4", "manual", ip_address, netmask, gateway],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode != 0:
                    self._logger.error(f"Failed to set static IP: {result.stderr}")
                    raise BadRequestError(f"Failed to set static IP: {result.stderr}")

                self._logger.info(f"Successfully set static IP: {ip_address}/{netmask}, gateway: {gateway}")


            if dns_servers is not None:
                if dns_servers.strip():

                    dns_list = [dns.strip() for dns in dns_servers.split(",") if dns.strip()]


                    for dns in dns_list:
                        if not self._validate_ipv4_address(dns):
                            raise BadRequestError(f"Invalid DNS server address format: {dns}")


                    dns_cmd = ["connmanctl", "config", service_id, "nameservers"] + dns_list
                    result = subprocess.run(
                        dns_cmd,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if result.returncode != 0:
                        self._logger.error(f"Failed to set DNS servers: {result.stderr}")
                        raise BadRequestError(f"Failed to set DNS servers: {result.stderr}")

                    self._logger.info(f"Successfully set DNS servers: {', '.join(dns_list)}")
                else:

                    dns_cmd = ["connmanctl", "config", service_id, "nameservers"]
                    result = subprocess.run(
                        dns_cmd,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if result.returncode != 0:
                        self._logger.error(f"Failed to set DHCP DNS: {result.stderr}")
                        raise BadRequestError(f"Failed to set DHCP DNS: {result.stderr}")

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

        except subprocess.TimeoutExpired:
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
            result = subprocess.run(
                ["connmanctl", "services", service_id],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return await self._parse_connman_output(result.stdout)
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


            return make_json_response({
                "success": True,
                "absolute_mouse": self._get_nested_value(data, "kvmd/hid/mouse/absolute", True),
                "msd_partition": self._get_nested_value(data, "kvmd/msd/partition_device", "/dev/block/by-name/media"),
                "msd_type": self._get_nested_value(data, "kvmd/msd/type", "otg"),

                "otg_manufacturer": self._get_nested_value(data, "otg/manufacturer", "Glinet"),
                "otg_product": self._get_nested_value(data, "otg/product", "Glinet Composite Device"),
                "otg_vendor_id": self._int_to_hex_str(self._get_nested_value(data, "otg/vendor_id", 7531)),
                "otg_product_id": self._int_to_hex_str(self._get_nested_value(data, "otg/product_id", 260)),
                "otg_serial": self._get_nested_value(data, "otg/serial", "CAFEBABE"),

                "enable_mic": self._get_nested_value(data, "otg/devices/audio/enabled", False)
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


            return make_json_response({
                "success": True,
                "absolute_mouse": self._get_nested_value(data, "kvmd/hid/mouse/absolute", True),
                "msd_partition": self._get_nested_value(data, "kvmd/msd/partition_device", "/dev/block/by-name/media"),
                "msd_type": self._get_nested_value(data, "kvmd/msd/type", "otg"),
                "otg_manufacturer": self._get_nested_value(data, "otg/manufacturer", "Glinet"),
                "otg_product": self._get_nested_value(data, "otg/product", "Glinet Composite Device"),
                "otg_vendor_id": self._int_to_hex_str(self._get_nested_value(data, "otg/vendor_id", 7531)),
                "otg_product_id": self._int_to_hex_str(self._get_nested_value(data, "otg/product_id", 260)),
                "otg_serial": self._get_nested_value(data, "otg/serial", "CAFEBABE")
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

    def _get_timezone_offset_minutes(self, timezone_name: str) -> int:
        """获取时区相对于UTC的分钟偏移量"""
        try:
            return self._timezone_map.get(timezone_name, 0)
        except Exception:
            return 0

    def _offset_minutes_to_timezone(self, offset_minutes: int) -> str:
        """将分钟偏移量转换为最接近的时区名称"""
        try:
            return self._offset_to_timezone_map.get(offset_minutes, "UTC")
        except Exception:
            return "UTC"

    @exposed_http("GET", "/system/time")
    async def get_time_handler(self, request: Request) -> Response:
        """获取系统时间和时区处理器"""
        try:

            current_timestamp = int(datetime.now().timestamp())


            timezone_name = "UTC"
            try:
                if os.path.exists("/etc/localtime"):
                    try:
                        link_target = os.readlink("/etc/localtime")
                        if "/zoneinfo/" in link_target:
                            timezone_name = link_target.split("/zoneinfo/")[-1]
                        else:
                            timezone_name = "UTC"
                    except OSError:
                        timezone_name = "UTC"

            except Exception as e:
                self._logger.warning(f"Failed to get timezone: {e}")
                timezone_name = "UTC"


            if timezone_name not in self._timezone_map:

                timezone_name = "UTC"


            timezone_offset = self._get_timezone_offset_minutes(timezone_name)

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


                    timezone_name = self._offset_minutes_to_timezone(timezone_offset)


                    zoneinfo_path = f"/usr/share/zoneinfo/{timezone_name}"
                    if os.path.exists(zoneinfo_path):
                        try:

                            if os.path.exists("/etc/localtime"):
                                os.remove("/etc/localtime")

                            os.symlink(zoneinfo_path, "/etc/localtime")
                            await aiotools.run_async(os.sync)
                            self._logger.info(f"Created /etc/localtime symlink to: {zoneinfo_path}")
                        except Exception as e:
                            self._logger.warning(f"Failed to create /etc/localtime symlink: {e}")
                    else:
                        self._logger.warning(f"Timezone file not found: {zoneinfo_path}")

                    self._logger.info(f"Successfully set timezone to: {timezone_name} (offset: {timezone_offset} minutes)")

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


                    result = subprocess.run(
                        ["date", "-s", f"@{timestamp}"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if result.returncode != 0:
                        self._logger.error(f"Failed to set time with date -s @{timestamp}: {result.stderr}")
                        raise BadRequestError(f"Failed to set time with date -s @{timestamp}: {result.stderr}")


                    try:
                        subprocess.run(
                            ["hwclock", "-w"],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
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
