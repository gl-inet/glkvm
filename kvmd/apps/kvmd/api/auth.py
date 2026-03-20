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


import base64
import secrets
import time
import ipaddress

from ....utils import parse_user_agent

from aiohttp.web import Request
from aiohttp.web import Response

from ....htserver import UnauthorizedError
from ....htserver import ForbiddenError
from ....htserver import HttpExposed
from ....htserver import exposed_http
from ....htserver import make_json_response
from ....htserver import set_request_auth_info
from ....htserver import get_request_unix_credentials
from ....htserver import get_request_exe_path

from ....logging import get_logger

from ..auth import RateLimitError

from ....validators.auth import valid_user
from ....validators.auth import valid_passwd
from ....validators.auth import valid_expire
from ....validators.auth import valid_auth_token

from ..auth import AuthManager

from .config_utils import set_yaml_value as _set_yaml_value


# =====
_COOKIE_AUTH_TOKEN = "auth_token"


def _is_local_network(ip_str: str) -> bool:
    """Check if IP address is from local/private network"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check if it's a private IP address
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


async def _check_xhdr(auth_manager: AuthManager, _: HttpExposed, req: Request) -> bool:
    user = req.headers.get("X-KVMD-User", "")
    if user:
        user = valid_user(user)
        passwd = req.headers.get("X-KVMD-Passwd", "")
        set_request_auth_info(req, f"{user} (xhdr)")
        if (await auth_manager.authorize(user, valid_passwd(passwd))):
            return True
        raise ForbiddenError()
    return False


async def _check_token(auth_manager: AuthManager, _: HttpExposed, req: Request) -> bool:
    token = req.cookies.get(_COOKIE_AUTH_TOKEN, "")
    if token:
        user = auth_manager.check(valid_auth_token(token))
        if user:
            set_request_auth_info(req, f"{user} (token)")
            return True
        set_request_auth_info(req, "- (token)")
        raise ForbiddenError()
    return False


async def _check_basic(auth_manager: AuthManager, _: HttpExposed, req: Request) -> bool:
    basic_auth = req.headers.get("Authorization", "")
    if basic_auth and basic_auth[:6].lower() == "basic ":
        try:
            (user, passwd) = base64.b64decode(basic_auth[6:]).decode("utf-8").split(":")
        except Exception:
            raise UnauthorizedError()
        user = valid_user(user)
        set_request_auth_info(req, f"{user} (basic)")
        if (await auth_manager.authorize(user, valid_passwd(passwd))):
            return True
        raise ForbiddenError()
    return False


async def _check_header_token(auth_manager: AuthManager, _: HttpExposed, req: Request) -> bool:
    token = req.headers.get("Token", "")
    
    if token:
        user = auth_manager.check(valid_auth_token(token))
        if user:
            set_request_auth_info(req, f"{user} (header-token)")
            return True
        set_request_auth_info(req, "- (header-token)")
        raise ForbiddenError()
    return False


async def _check_query_token(auth_manager: AuthManager, _: HttpExposed, req: Request) -> bool:
    token = req.query.get("auth_token", "")
    if token:
        user = auth_manager.check(valid_auth_token(token))
        if user:
            set_request_auth_info(req, f"{user} (query-token)")
            return True
        set_request_auth_info(req, "- (query-token)")
        raise ForbiddenError()
    return False


async def _check_usc(auth_manager: AuthManager, exposed: HttpExposed, req: Request) -> bool:
    if exposed.allow_usc:
        creds = get_request_unix_credentials(req)
        if creds is not None:
            user = auth_manager.check_unix_credentials(creds)
            if user:
                set_request_auth_info(req, f"{user}[{creds.uid}] (unix)")
                return True
        raise UnauthorizedError()
    return False


async def _check_exe_path(auth_manager: AuthManager, exposed: HttpExposed, req: Request) -> bool:
    """检查调用进程的可执行路径是否在白名单中。
    当接口设置了 allowed_exe_paths 时，具有排他性：
    只有白名单内的进程（必须通过 Unix Socket 连接）才能访问，
    其他任何方式（包括 HTTP）均被拒绝。
    """
    if exposed.allowed_exe_paths:
        exe_path = get_request_exe_path(req)
        if exe_path and exe_path in exposed.allowed_exe_paths:
            set_request_auth_info(req, f"exe:{exe_path}")
            return True
        # allowed_exe_paths 非空但未匹配（含 HTTP 请求），强制拒绝
        raise ForbiddenError()
    return False


async def check_request_auth(auth_manager: AuthManager, exposed: HttpExposed, req: Request) -> None:
    # 首先检查进程可执行路径白名单（无需认证）
    if (await _check_exe_path(auth_manager, exposed, req)):
        return
    if not auth_manager.is_auth_required(exposed):
        return
    for checker in [_check_xhdr, _check_header_token, _check_query_token, _check_token, _check_basic, _check_usc]:
        if (await checker(auth_manager, exposed, req)):
            return
    raise UnauthorizedError()


class AuthApi:
    def __init__(self, auth_manager: AuthManager) -> None:
        self.__auth_manager = auth_manager

    # =====

    @exposed_http("POST", "/auth/login", auth_required=False, allow_usc=False)
    async def __login_handler(self, req: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            credentials = await req.post()

            # Get client IP for rate limiting
            client_ip = self.__auth_manager._get_client_ip(dict(req.headers))

            try:
                user = valid_user(credentials.get("user", ""))
                passwd = valid_passwd(credentials.get("passwd", ""))
                expire = valid_expire(credentials.get("expire", "0"))

                # 解析 User-Agent：设备类型 & 浏览器（始终执行，与是否启用两步登录无关）
                user_agent = req.headers.get("User-Agent", "")
                device_type, browser = parse_user_agent(user_agent)
                get_logger(0).info(
                    "Login request from %s | device=%s, browser=%s | UA: %s",
                    client_ip, device_type, browser, user_agent,
                )

                # Check if two-step login is enabled
                if self.__auth_manager.is_two_step_login_enabled():
                    two_step_token = await self.__auth_manager.pre_login(
                        user=user,
                        passwd=passwd,
                        expire=expire,
                        client_ip=client_ip,
                        user_agent=user_agent,
                    )
                    if two_step_token:
                        return make_json_response({
                            "two_step_required": True,
                            "two_step_token": two_step_token,
                            "expires_in": self.__auth_manager.get_two_step_expire(),
                        })
                    raise ForbiddenError()
                else:
                    # Original single-step login
                    token = await self.__auth_manager.login(
                        user=user,
                        passwd=passwd,
                        expire=expire,
                        client_ip=client_ip,
                    )
                    if token:
                        return make_json_response({"token": token}, set_cookies={_COOKIE_AUTH_TOKEN: token})
                    raise ForbiddenError()
            except RateLimitError as ex:
                # Return 429 Too Many Requests for rate limiting
                return make_json_response({
                    "error": "RateLimitError",
                    "error_msg": str(ex),
                    "remaining_time": ex.remaining_time
                }, status=429)
        return make_json_response()

    @exposed_http("POST", "/auth/logout", allow_usc=False)
    async def __logout_handler(self, req: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            # 从每个来源获取 token，如果有提供就注销
            header_token = req.headers.get("Token", "")
            query_token = req.query.get("auth_token", "")
            cookie_token = req.cookies.get(_COOKIE_AUTH_TOKEN, "")

            if header_token:
                self.__auth_manager.logout(valid_auth_token(header_token))
            if query_token:
                self.__auth_manager.logout(valid_auth_token(query_token))
            if cookie_token:
                self.__auth_manager.logout(valid_auth_token(cookie_token))
        return make_json_response()

    # XXX: This handle is used for access control so it should NEVER allow access by socket credentials
    @exposed_http("GET", "/auth/check", allow_usc=False)
    async def __check_handler(self, _: Request) -> Response:
        return make_json_response()

    @exposed_http("POST", "/auth/two_step_complete", auth_required=False, allow_usc=False)
    async def __two_step_complete_handler(self, req: Request) -> Response:
        """两步登录第二步：用临时 token 换取正式 token"""
        if self.__auth_manager.is_auth_enabled():
            data = await req.post()
            two_step_token = data.get("two_step_token", "").strip()

            if not two_step_token:
                return make_json_response({
                    "error": "BadRequest",
                    "error_msg": "Missing two_step_token parameter"
                }, status=400)

            token, status = self.__auth_manager.complete_two_step_login(two_step_token)
            if status == "ok":
                return make_json_response({"token": token}, set_cookies={_COOKIE_AUTH_TOKEN: token})
            elif status == "pending":
                return make_json_response({"status": "pending"})
            else:
                # "expired" or "invalid"
                raise ForbiddenError()
        return make_json_response()

    @exposed_http("GET", "/auth/two_step_pending", auth_required=False, allow_usc=False, allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def __two_step_pending_handler(self, _: Request) -> Response:
        #获取待审批的两步登录信息
        pending = self.__auth_manager.get_pending_two_step_session()
        if pending:
            return make_json_response({"pending": True, **pending})
        return make_json_response({"pending": False})

    @exposed_http("POST", "/auth/two_step_approve", auth_required=False, allow_usc=False, allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def __two_step_approve_handler(self, req: Request) -> Response:
        #批准两步登录请求
        data = await req.post()
        two_step_token = data.get("two_step_token", "").strip()

        if not two_step_token:
            return make_json_response({
                "approved": False,
                "error": "Missing two_step_token parameter"
            }, status=400)

        approved = self.__auth_manager.approve_two_step_session(two_step_token)
        return make_json_response({"approved": approved})

    @exposed_http("POST", "/auth/two_step_reject", auth_required=False, allow_usc=False, allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def __two_step_reject_handler(self, req: Request) -> Response:
        #拒绝两步登录请求
        data = await req.post()
        two_step_token = data.get("two_step_token", "").strip()

        if not two_step_token:
            return make_json_response({
                "rejected": False,
                "error": "Missing two_step_token parameter"
            }, status=400)

        rejected = self.__auth_manager.reject_two_step_session(two_step_token)
        return make_json_response({"rejected": rejected})

    @exposed_http("GET", "/auth/two_step_login", auth_required=True, allow_usc=False, allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def __two_step_login_get_handler(self, _: Request) -> Response:
        """查询两步登录功能的启用状态"""
        return make_json_response({
            "enabled": self.__auth_manager.is_two_step_login_enabled()
        })

    @exposed_http("POST", "/auth/two_step_login", auth_required=True, allow_usc=False, allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def __two_step_login_put_handler(self, req: Request) -> Response:
        """动态启用或关闭两步登录功能"""
        data = await req.json()
        enabled = data.get("enabled")
        if not isinstance(enabled, bool):
            return make_json_response({
                "error": "BadRequest",
                "error_msg": "Missing or invalid 'enabled' field (must be JSON boolean)"
            }, status=400)
        self.__auth_manager.set_two_step_login_enabled(enabled)
        # 持久化到 boot.yaml，重启后状态不丢失
        await _set_yaml_value("kvmd/auth/two_step_login/enabled", enabled)
        return make_json_response({"enabled": enabled})

    @exposed_http("GET", "/auth/rate_limit_status")
    async def __rate_limit_status_handler(self, req: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            client_ip = req.query.get("client_ip")
            if not client_ip:
                # If no specific client_ip provided, use requesting client's IP
                client_ip = self.__auth_manager._get_client_ip(dict(req.headers))

            status = self.__auth_manager.get_rate_limit_status(client_ip)
            return make_json_response(status)
        return make_json_response({"enabled": False})

    @exposed_http("GET", "/auth/locked_clients")
    async def __locked_clients_handler(self, _: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            locked_clients = self.__auth_manager.get_all_locked_clients()
            return make_json_response({"locked_clients": locked_clients})
        return make_json_response({"enabled": False, "locked_clients": {}})

    @exposed_http("POST", "/auth/unlock_client")
    async def __unlock_client_handler(self, req: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            data = await req.post()
            client_ip = data.get("client_ip", "").strip()
            if not client_ip:
                return make_json_response({
                    "error": "BadRequest",
                    "error_msg": "Missing client_ip parameter"
                }, status=400)

            unlocked = self.__auth_manager.unlock_client(client_ip)
            return make_json_response({
                "unlocked": unlocked,
                "client_ip": client_ip
            })
        return make_json_response({"enabled": False})

    @exposed_http("GET", "/same_check", auth_required=False, allow_usc=False)
    async def __same_check_handler(self, req: Request) -> Response:
        # Get client IP address
        client_ip = self.__auth_manager._get_client_ip(dict(req.headers))

        # Check if request is from local network
        if not _is_local_network(client_ip):
            return make_json_response({
                "result": False,
                "error": "Access denied: only local network access allowed"
            }, status=403)

        # Get MAC address from query parameter
        client_mac = req.query.get("mac", "").strip()

        if not client_mac:
            return make_json_response({
                "result": False,
                "error": "Missing MAC address parameter"
            }, status=400)

        try:
            # Read device MAC from /proc/gl-hw-info/device_mac
            with open("/proc/gl-hw-info/device_mac", "r") as f:
                device_mac = f.read().strip()

            # Normalize MAC addresses for comparison (convert to lowercase, remove spaces)
            client_mac_normalized = client_mac.lower().replace(" ", "")
            device_mac_normalized = device_mac.lower().replace(" ", "")

            # Compare MAC addresses
            is_same = (client_mac_normalized == device_mac_normalized)

            return make_json_response({
                "result": is_same
            })
        except FileNotFoundError:
            return make_json_response({
                "result": False,
                "error": "Device MAC file not found"
            }, status=500)
        except Exception:
            return make_json_response({
                "result": False,
                "error": "Internal server error"
            }, status=500)
