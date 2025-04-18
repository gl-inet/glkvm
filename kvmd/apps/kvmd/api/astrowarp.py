






















import json
from aiohttp.web import Request
from aiohttp.web import Response

import os
from ....htserver import ForbiddenError
from ....htserver import NotFoundError
from ....htserver import exposed_http
from ....htserver import make_json_response
from ....htserver import make_json_exception

ASTROWARP_STATUS_PATH = "/var/run/cloud/bindinfo"
ASTROWARP_INIT_PATH = "/etc/init.d/S99gl-cloud"
ASTROWARP_CONFIG_PATH = "/etc/glinet/gl-cloud.conf"



class AstrowarpApi:
    MAC_PATH = "/proc/gl-hw-info/device_mac"
    SN_PATH = "/proc/gl-hw-info/device_sn"
    DDNS_PATH = "/proc/gl-hw-info/device_ddns"
    def __init__(self) -> None:
        pass




    @exposed_http("GET", "/astrowarp/status")
    async def __status_handler(self, req: Request) -> Response:
        with open(ASTROWARP_CONFIG_PATH, "r") as file:
            config = file.read()
            config_json = json.loads(config)
            enabled = config_json["enable"]
        try:
            with open(ASTROWARP_STATUS_PATH, "r") as file:

                status_str = file.read().strip()
                status = json.loads(status_str)

                if "bindtime" not in status or status["bindtime"] == "":
                    raise Exception("bindtime not found")
                if "email" not in status or status["email"] == "":
                    raise Exception("email not found")
                if "username" not in status or "username" == "":
                    raise Exception("username not found")
            return make_json_response({"result": "success","status": status,"enabled": enabled})
        except:
            return make_json_response({"result": "failed","enabled": enabled})

    @exposed_http("GET", "/astrowarp/show")
    async def __show_handler(self, req: Request) -> Response:
        try:
            with open(self.MAC_PATH, "r") as file:
                mac = file.read().strip()
            with open(self.SN_PATH, "r") as file:
                sn = file.read().strip()
            with open(self.DDNS_PATH, "r") as file:
                ddns = file.read().strip()
            return make_json_response({"url":f"{mac},{sn},{ddns}"})
        except:
            return make_json_exception(NotFoundError(),404)

    @exposed_http("GET", "/astrowarp/enable")
    async def __enable_handler(self, req: Request) -> Response:
        enable = req.query.get("enable", "")


        with open(ASTROWARP_CONFIG_PATH, "r+") as file:
            config = file.read()
            config_json = json.loads(config)
            config_json["enable"] = True if enable == "true" else False
            file.seek(0)
            file.write(json.dumps(config_json))
            file.truncate()

        if enable == "true":
            os.system(f"{ASTROWARP_INIT_PATH} restart")
        else:
            os.system(f"{ASTROWARP_INIT_PATH} stop")
        return make_json_response()
