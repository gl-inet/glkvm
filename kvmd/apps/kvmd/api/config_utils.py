import os
from typing import Any

import yaml

from ....tools import run_shell
from ....logging import get_logger


# 默认配置文件路径（与 SystemApi 保持一致）
DEFAULT_CONFIG_PATH = "/etc/kvmd/user/boot.yaml"


def get_nested_value(data: dict, path: str, default: Any = None) -> Any:
    """获取嵌套字典中的值，path 使用 '/' 分隔，如 'kvmd/auth/two_step_login/enabled'"""
    keys = path.split("/")
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def set_nested_value(data: dict, path: str, value: Any) -> None:
    """设置嵌套字典中的值，不存在的中间节点自动创建"""
    keys = path.split("/")
    current = data
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


async def read_yaml(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    """读取 YAML 配置文件，返回字典；文件不存在时返回空字典"""
    try:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                return yaml.safe_load(f) or {}
        return {}
    except Exception as ex:
        get_logger(0).error("Cannot read config file %r: %s", config_path, ex)
        raise


async def write_yaml(data: dict, config_path: str = DEFAULT_CONFIG_PATH) -> None:
    """将字典写入 YAML 配置文件，并执行 sync 刷盘"""
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        await run_shell("sync")
    except Exception as ex:
        get_logger(0).error("Cannot write config file %r: %s", config_path, ex)
        raise


async def set_yaml_value(path: str, value: Any, config_path: str = DEFAULT_CONFIG_PATH) -> None:
    """便利函数：读取 YAML → 设置一个嵌套值 → 写回"""
    data = await read_yaml(config_path)
    set_nested_value(data, path, value)
    await write_yaml(data, config_path)
