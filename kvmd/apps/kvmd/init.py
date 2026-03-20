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



from ...logging import get_logger
import os
import json
import subprocess
import crypt
import tempfile
import stat

from ..htpasswd import _get_htpasswd_for_write_from_file
from ...validators.auth import valid_passwd


# =====
class InitManager:
    def __init__(
        self,
    ) -> None:
        self.inited = False
        self.country_code = ""
        self.state_file = "/etc/kvmd/user/init_state.json"
        self.country_code_file = "/proc/gl-hw-info/country_code"
        self._load_state()

    def _load_state(self) -> None:
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, "r") as f:
                    state = json.load(f)
                    self.inited = state.get("inited", False)
            else:
                self.inited = False
            
            # country_code 始终从 country_code_file 读取
            try:
                with open(self.country_code_file, 'r') as f:
                    self.country_code = f.read().strip()
            except Exception:
                self.country_code = ""
        except Exception as e:
            get_logger().error(f"Failed to load init state: {e}")

    def _save_state(self) -> None:
        try:
            state = {"inited": self.inited}
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, "w") as f:
                json.dump(state, f)
            # 执行sync确保数据写入磁盘
            subprocess.run(["sync"], check=True)
        except Exception as e:
            get_logger().error(f"Failed to save init state: {e}")

    def is_inited(self) -> bool:
        return self.inited
    
    def get_country_code(self) -> str:
        return self.country_code
        
    def _change_root_password(self, password: str) -> None:
        """修改root用户的SSH密码"""
        try:
            # 在Buildroot系统中直接修改/etc/shadow文件
            salt = os.urandom(8).hex()
            hashed_password = crypt.crypt(password, f"$6${salt}$")  # SHA-512

            shadow_path = "/etc/shadow"

            # 读取当前shadow文件
            with open(shadow_path, "r") as f:
                lines = f.readlines()

            # 修改root用户的密码
            for i, line in enumerate(lines):
                if line.startswith("root:"):
                    parts = line.split(":")
                    parts[1] = hashed_password
                    lines[i] = ":".join(parts)
                    break

            # 原子写入: 先写入临时文件，再重命名覆盖
            shadow_dir = os.path.dirname(shadow_path)
            fd, tmp_path = tempfile.mkstemp(dir=shadow_dir, prefix=".shadow.")
            try:
                with os.fdopen(fd, "w") as f:
                    f.writelines(lines)
                # 保持原有文件的权限 (0640)
                os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
                os.rename(tmp_path, shadow_path)
            except Exception:
                # 清理临时文件
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

            # 确保数据写入磁盘
            subprocess.run(["sync"], check=True)

            get_logger().info("Root password changed successfully")
        except Exception as e:
            get_logger().error(f"Failed to change root password: {e}")
            raise

    def init(self, password: str) -> None:
        if self.inited:
            return

        try:
            # 验证密码
            if password != valid_passwd(password):
                raise Exception("Password is required")
            
            # 使用htpasswd设置密码
            with _get_htpasswd_for_write_from_file("/etc/kvmd/user/htpasswd") as htpasswd:
                htpasswd.set_password("admin", password)
            
            # 修改root用户的SSH密码
            try:
                self._change_root_password(password)
            except Exception:
                # 错误已在_change_root_password中记录
                pass
            
            self.inited = True
            self._save_state()
            get_logger().info("Password initialized successfully")
            
        except Exception as e:
            get_logger().error(f"Failed to initialize password: {e}")
            raise

    def change_password(self, user: str, old_password: str, new_password: str) -> None:
        try:
            # 验证新旧密码
            if old_password != valid_passwd(old_password):
                raise Exception("Old password is invalid")
            if new_password != valid_passwd(new_password):
                raise Exception("New password is invalid")
            
            # 使用htpasswd验证旧密码并设置新密码
            with _get_htpasswd_for_write_from_file("/etc/kvmd/user/htpasswd") as htpasswd:
                if not htpasswd.check_password(user, old_password):
                    raise Exception("Invalid old password")
                htpasswd.set_password(user, new_password)
            
            # 修改root用户的SSH密码
            try:
                self._change_root_password(new_password)
            except Exception:
                # 错误已在_change_root_password中记录
                pass
                
            get_logger().info("Password changed successfully")
            
        except Exception as e:
            get_logger().error(f"Failed to change password: {e}")
            raise

