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


import sys
import types



MODEL_PATH = "/proc/gl-hw-info/model"

def get_model_name() -> str:
    try:
        with open(MODEL_PATH, "r") as f:
            return f.read().strip()
    except Exception as e:
        get_logger(0).warning(f"Failed to read model info, using default value rm10: {str(e)}")
        return "rm10"


def parse_user_agent(ua_string: str) -> tuple[str, str]:
    """解析 User-Agent 字符串，返回 (device_type, browser)。

    device_type: "Mobile" | "Tablet" | "PC" | "Unknown"
    browser:     浏览器名称，如 "Chrome"、"Safari"，解析失败时为 "Unknown"
    """
    try:
        import user_agents  # pylint: disable=import-outside-toplevel
    except ImportError:
        return ("Unknown", "Unknown")

    ua = user_agents.parse(ua_string)
    if ua.is_mobile:
        device_type = "Mobile"
    elif ua.is_tablet:
        device_type = "Tablet"
    elif ua.is_pc:
        device_type = "PC"
    else:
        device_type = "Unknown"
    browser = ua.browser.family or "Unknown"
    return (device_type, browser)