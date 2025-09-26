






















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




class InitApi:
    def __init__(self, init_manager: InitManager) -> None:
        self.__init_manager = init_manager



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



        user = req.query.get("user")
        old_password = req.query.get("old_password")
        new_password = req.query.get("new_password")

        try:
            self.__init_manager.change_password(user, old_password, new_password)
            return make_json_response()
        except Exception as e:
            return make_json_exception(ForbiddenError(), 403)
