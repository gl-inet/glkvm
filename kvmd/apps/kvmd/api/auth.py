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

from aiohttp.web import Request
from aiohttp.web import Response

from ....htserver import UnauthorizedError
from ....htserver import ForbiddenError
from ....htserver import HttpExposed
from ....htserver import exposed_http
from ....htserver import make_json_response
from ....htserver import set_request_auth_info
from ....htserver import get_request_unix_credentials

from ..auth import RateLimitError

from ....validators.auth import valid_user
from ....validators.auth import valid_passwd
from ....validators.auth import valid_expire
from ....validators.auth import valid_auth_token

from ..auth import AuthManager


# =====
_COOKIE_AUTH_TOKEN = "auth_token"


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


async def check_request_auth(auth_manager: AuthManager, exposed: HttpExposed, req: Request) -> None:
    if not auth_manager.is_auth_required(exposed):
        return
    for checker in [_check_xhdr, _check_header_token, _check_token, _check_basic, _check_usc]:
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


            client_ip = self.__auth_manager._get_client_ip(dict(req.headers))

            try:
                token = await self.__auth_manager.login(
                    user=valid_user(credentials.get("user", "")),
                    passwd=valid_passwd(credentials.get("passwd", "")),
                    expire=valid_expire(credentials.get("expire", "0")),
                    client_ip=client_ip,
                )
                if token:
                    return make_json_response({"token": token}, set_cookies={_COOKIE_AUTH_TOKEN: token})
                raise ForbiddenError()
            except RateLimitError as ex:

                return make_json_response({
                    "error": "RateLimitError",
                    "error_msg": str(ex),
                    "remaining_time": ex.remaining_time
                }, status=429)
        return make_json_response()

    @exposed_http("POST", "/auth/logout", allow_usc=False)
    async def __logout_handler(self, req: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            token = valid_auth_token(req.cookies.get(_COOKIE_AUTH_TOKEN, ""))
            self.__auth_manager.logout(token)
        return make_json_response()


    @exposed_http("GET", "/auth/check", allow_usc=False)
    async def __check_handler(self, _: Request) -> Response:
        return make_json_response()

    @exposed_http("GET", "/auth/rate_limit_status")
    async def __rate_limit_status_handler(self, req: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            client_ip = req.query.get("client_ip")
            if not client_ip:

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
