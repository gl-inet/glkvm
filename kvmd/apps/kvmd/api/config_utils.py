import os
import subprocess
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


def delete_nested_key(data: dict, path: str) -> bool:
    """删除嵌套字典中指定 path 对应的 key，返回是否实际删除了某个 key。
    删除叶子 key 后会向上清理变为空的父节点。
    path 格式与 get/set_nested_value 一致，如 'kvmd/msd/type'。
    """
    keys = path.split("/")
    # 记录沿途的 (parent_dict, key) 以便回溯清理空节点
    trail: list[tuple[dict, str]] = []
    current = data
    for key in keys[:-1]:
        if not isinstance(current, dict) or key not in current:
            return False
        trail.append((current, key))
        current = current[key]
    if keys[-1] not in current:
        return False
    del current[keys[-1]]
    # 向上清理空的父节点
    for parent, key in reversed(trail):
        if isinstance(parent[key], dict) and not parent[key]:
            del parent[key]
        else:
            break
    return True


# 已从所有 API 中废弃、不再被任何端点管理的 boot.yaml key 路径列表。
# 这些 key 若残留在 boot.yaml 中会持续影响启动行为，服务器启动时自动删除。
# 废弃新参数时，在此追加对应的 YAML 路径。
DEPRECATED_BOOT_KEYS: list[str] = [
    "kvmd/msd/type",  # 原 set_param?msd_type 写入，现已废弃
]


def migrate_boot_config_sync(deprecated_keys: list[str] = DEPRECATED_BOOT_KEYS, config_path: str = DEFAULT_CONFIG_PATH) -> None:
    """同步版 boot.yaml 孤立 key 清理，用于 event loop 启动前调用。
    删除 deprecated_keys 中指定的孤立 key，若有改动则写回并执行 sync 刷盘。
    """
    try:
        if not os.path.exists(config_path):
            return
        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}
        removed = [key for key in deprecated_keys if delete_nested_key(data, key)]
        if removed:
            logger = get_logger(0)
            for key in removed:
                logger.info("migrate_boot_config: removed deprecated key %r", key)
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w") as f:
                yaml.dump(data, f, default_flow_style=False)
            subprocess.run(["sync"], check=False)
            logger.info("migrate_boot_config: boot.yaml cleaned, removed %d key(s)", len(removed))
    except Exception as ex:
        get_logger(0).error("migrate_boot_config: failed: %s", ex)


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
