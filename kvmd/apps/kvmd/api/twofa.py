






















from aiohttp.web import Request
from aiohttp.web import Response
import pyotp

from ....htserver import ForbiddenError
from ....htserver import NotFoundError
from ....htserver import exposed_http
from ....htserver import make_json_response
from ....htserver import make_json_exception

TOTP_SECRET_PATH = "/etc/kvmd/user/totp.secret"

class TwoFaApi:
    def __init__(self) -> None:
        pass



    @exposed_http("GET", "/2fa/create")
    async def __create_handler(self, req: Request) -> Response:
        try:
            with open(TOTP_SECRET_PATH, "r") as file:
                secret = file.read().strip()
                if secret != "":
                    return make_json_exception(ForbiddenError(),403)
        except FileNotFoundError:
            pass
        secret = pyotp.random_base32()
        uri = pyotp.TOTP(secret).provisioning_uri(name="GLKVM", issuer_name="GLKVM")
        return make_json_response({"secret": secret, "uri": uri})

    @exposed_http("GET", "/2fa/init")
    async def __init_handler(self, req: Request) -> Response:
        with open(TOTP_SECRET_PATH, "w") as file:
            try:
                if file.read().strip() != "":
                    return make_json_exception(ForbiddenError(),403)
            except:
                pass
            secret = req.query.get("secret", "")
            key = req.query.get("key", "")
            if secret == "":
                return make_json_exception(ForbiddenError(),403)

            if pyotp.TOTP(secret).verify(key):
                file.write(secret)
            else:
                return make_json_exception(ForbiddenError(),403)
        return make_json_response()

    @exposed_http("GET", "/2fa/show")
    async def __show_handler(self, req: Request) -> Response:
        with open(TOTP_SECRET_PATH, "r") as file:
            secret = file.read().strip()
            if secret == "":
                return make_json_exception(NotFoundError(),404)
            uri = pyotp.TOTP(secret).provisioning_uri(name="GLKVM", issuer_name="GLKVM")
        return make_json_response({"URI": uri})

    @exposed_http("GET", "/2fa/is_enabled", auth_required=False)
    async def __is_enabled_handler(self, req: Request) -> Response:
        try:
            with open(TOTP_SECRET_PATH, "r") as file:
                secret = file.read().strip()
                if secret == "":
                    return make_json_response({"enabled": False})
            return make_json_response({"enabled": True})
        except FileNotFoundError:
            return make_json_response({"enabled": False})

    @exposed_http("GET", "/2fa/delete")
    async def __delete_handler(self, req: Request) -> Response:
        with open(TOTP_SECRET_PATH, "w") as file:
            file.write("")
        return make_json_response()

    @exposed_http("GET", "/2fa/verify")
    async def __verify_handler(self, req: Request) -> Response:
        with open(TOTP_SECRET_PATH, "r") as file:
            secret = file.read().strip()
            if secret == "":
                return make_json_exception(NotFoundError(),404)
            code = req.query.get("code", "")
            if not pyotp.TOTP(secret).verify(code):
                return make_json_exception(ForbiddenError(),403)
        return make_json_response()
