






















from ...logging import get_logger
import os
import json
import subprocess
import crypt

from ..htpasswd import _get_htpasswd_for_write_from_file
from ...validators.auth import valid_passwd



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

            salt = os.urandom(8).hex()
            hashed_password = crypt.crypt(password, f"$6${salt}$")


            with open("/etc/shadow", "r") as f:
                lines = f.readlines()


            for i, line in enumerate(lines):
                if line.startswith("root:"):
                    parts = line.split(":")
                    parts[1] = hashed_password
                    lines[i] = ":".join(parts)
                    break


            with open("/etc/shadow", "w") as f:
                f.writelines(lines)


            subprocess.run(["sync"], check=True)

            get_logger().info("Root password changed successfully")
        except Exception as e:
            get_logger().error(f"Failed to change root password: {e}")
            raise

    def init(self, password: str) -> None:
        if self.inited:
            return

        try:

            if password != valid_passwd(password):
                raise Exception("Password is required")


            with _get_htpasswd_for_write_from_file("/etc/kvmd/user/htpasswd") as htpasswd:
                htpasswd.set_password("admin", password)


            try:
                self._change_root_password(password)
            except Exception:

                pass

            self.inited = True
            self._save_state()
            get_logger().info("Password initialized successfully")

        except Exception as e:
            get_logger().error(f"Failed to initialize password: {e}")
            raise

    def change_password(self, user: str, old_password: str, new_password: str) -> None:
        try:

            if old_password != valid_passwd(old_password):
                raise Exception("Old password is invalid")
            if new_password != valid_passwd(new_password):
                raise Exception("New password is invalid")


            with _get_htpasswd_for_write_from_file("/etc/kvmd/user/htpasswd") as htpasswd:
                if not htpasswd.check_password(user, old_password):
                    raise Exception("Invalid old password")
                htpasswd.set_password(user, new_password)


            try:
                self._change_root_password(new_password)
            except Exception:

                pass

            get_logger().info("Password changed successfully")

        except Exception as e:
            get_logger().error(f"Failed to change password: {e}")
            raise

