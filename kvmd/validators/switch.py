





















import re

from typing import Any

from . import filter_printable
from . import check_re_match

from .basic import valid_stripped_string
from .basic import valid_number



def valid_switch_port_name(arg: Any) -> str:
    arg = valid_stripped_string(arg, name="switch port name")
    arg = filter_printable(arg, " ", 255)
    arg = re.sub(r"\s+", " ", arg)
    return arg.strip()


def valid_switch_edid_id(arg: Any, allow_default: bool) -> str:
    pattern = "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    if allow_default:
        pattern += "|^default$"
    return check_re_match(arg, "switch EDID ID", pattern).lower()


def valid_switch_edid_data(arg: Any) -> str:
    name = "switch EDID data"
    arg = valid_stripped_string(arg, name=name)
    arg = re.sub(r"\s", "", arg)
    return check_re_match(arg, name, "(?i)^([0-9a-f]{256}|[0-9a-f]{512})$").upper()


def valid_switch_color(arg: Any, allow_default: bool) -> str:
    pattern = "(?i)^[0-9a-f]{6}:[0-9a-f]{2}:[0-9a-f]{4}$"
    if allow_default:
        pattern += "|^default$"
    arg = check_re_match(arg, "switch color", pattern).upper()
    if arg == "DEFAULT":
        arg = "default"
    return arg


def valid_switch_atx_click_delay(arg: Any) -> float:
    return valid_number(arg, min=0, max=10, type=float, name="ATX delay")
