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



from aiohttp.web import Request
from aiohttp.web import Response

from ....htserver import UnauthorizedError
from ....htserver import ForbiddenError
from ....htserver import HttpExposed
from ....htserver import exposed_http
from ....htserver import make_json_response
from ....htserver import make_json_exception
from ....htserver import set_request_auth_info

from ....validators.auth import valid_user
from ....validators.auth import valid_passwd
from ....validators.auth import valid_auth_token

from ..init import InitManager


# 在设备第一次启动的时候,要求用户设置密码进行初始化
# 设置完之后不在允许访问这个API
class InitApi:
    def __init__(self, init_manager: InitManager) -> None:
        self.__init_manager = init_manager

    # =====

    @exposed_http("GET", "/init/init", auth_required=False)
    async def __init_handler(self, req: Request) -> Response:
        if not self.__init_manager.is_inited():
            unsafe_password = req.query.get("password", "")
            safe_password = valid_passwd(unsafe_password)
            if unsafe_password != safe_password:
                return make_json_exception(ForbiddenError(),403)
            self.__init_manager.init(safe_password)
            return make_json_response()
        else:
            return make_json_exception(ForbiddenError(),403)

    @exposed_http("GET", "/init/is_inited", auth_required=False)
    async def __is_inited_handler(self, req: Request) -> Response:
        country_code = self.__init_manager.get_country_code()
            
        if not self.__init_manager.is_inited():
            return make_json_response({
                "is_inited": False,
                "country_code": country_code
            })
        else:
            return make_json_response({
                "is_inited": True,
                "country_code": country_code
            })
    
    @exposed_http("POST", "/init/change_password")
    async def __change_password_handler(self, req: Request) -> Response:
        # if not self.__init_manager.is_inited():
        #     return make_json_exception(ForbiddenError(), 403)
        
        user = req.query.get("user")
        old_password = req.query.get("old_password")
        new_password = req.query.get("new_password")
        
        try:
            self.__init_manager.change_password(user, old_password, new_password)
            return make_json_response()
        except Exception as e:
            return make_json_exception(ForbiddenError(), 403)
