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


import asyncio
import pwd
import grp
import dataclasses
import time
import datetime
import threading

import secrets
import pyotp


from ...logging import get_logger

from ... import aiotools

from ...plugins.auth import BaseAuthService
from ...plugins.auth import get_auth_service_class

from ...htserver import HttpExposed
from ...htserver import RequestUnixCredentials


# =====
@dataclasses.dataclass(frozen=True)
class _Session:
    user:      str
    expire_ts: int

    def __post_init__(self) -> None:
        assert self.user == self.user.strip()
        assert self.user
        assert self.expire_ts >= 0


@dataclasses.dataclass
class _TwoStepSession:
    user: str
    expire_ts: float       # 使用 time.time() 绝对时间戳
    original_expire: int   # 原始请求的 expire 参数
    client_ip: str         # 客户端 IP
    user_agent: str        # 浏览器 User-Agent
    device_type: str       # 设备类型 (Mobile/Tablet/PC/Unknown)
    browser: str           # 浏览器名称
    approved: bool = False # 是否已审批通过

    def __post_init__(self) -> None:
        assert self.user == self.user.strip()
        assert self.user


@dataclasses.dataclass
class _LoginAttempt:
    timestamp: float


@dataclasses.dataclass
class _ClientLockInfo:
    locked_until: float
    failed_attempts: list[_LoginAttempt]

    def __post_init__(self) -> None:
        if not hasattr(self, 'failed_attempts') or self.failed_attempts is None:
            self.failed_attempts = []


class RateLimitError(Exception):
    def __init__(self, msg: str, remaining_time: int = 0) -> None:
        super().__init__(msg)
        self.remaining_time = remaining_time


class AuthManager:  # pylint: disable=too-many-arguments,too-many-instance-attributes
    def __init__(
        self,
        enabled: bool,
        expire: int,
        usc_users: list[str],
        usc_groups: list[str],
        unauth_paths: list[str],

        int_type: str,
        int_kwargs: dict,
        force_int_users: list[str],

        ext_type: str,
        ext_kwargs: dict,

        totp_secret_path: str,

        rate_limit_enabled: bool = True,
        rate_limit_max_attempts: int = 10,
        rate_limit_time_window: int = 600,
        rate_limit_lockout_duration: int = 600,

        two_step_login_enabled: bool = False,
    ) -> None:

        logger = get_logger(0)

        self.__enabled = enabled
        if not enabled:
            logger.warning("AUTHORIZATION IS DISABLED")

        assert expire >= 0
        self.__expire = expire
        if expire > 0:
            logger.info("Maximum user session time is limited: %s",
                        self.__format_seconds(expire))

        self.__usc_uids = self.__load_usc_uids(usc_users, usc_groups)
        if self.__usc_uids:
            logger.info("Selfauth UNIX socket access is allowed for users: %s",
                        list(self.__usc_uids.values()))

        self.__unauth_paths = frozenset(unauth_paths)  # To speed up
        if self.__unauth_paths:
            logger.info("Authorization is disabled for APIs: %s",
                        list(self.__unauth_paths))

        self.__int_service: (BaseAuthService | None) = None
        if enabled:
            self.__int_service = get_auth_service_class(int_type)(**int_kwargs)
            logger.info("Using internal auth service %r",
                        self.__int_service.get_plugin_name())

        self.__force_int_users = force_int_users

        self.__ext_service: (BaseAuthService | None) = None
        if enabled and ext_type:
            self.__ext_service = get_auth_service_class(ext_type)(**ext_kwargs)
            logger.info("Using external auth service %r",
                        self.__ext_service.get_plugin_name())

        self.__totp_secret_path = totp_secret_path

        self.__sessions: dict[str, _Session] = {}  # {token: session}

        # Rate limiting configuration
        self.__rate_limit_enabled = rate_limit_enabled
        self.__rate_limit_max_attempts = rate_limit_max_attempts
        self.__rate_limit_time_window = rate_limit_time_window
        self.__rate_limit_lockout_duration = rate_limit_lockout_duration

        # Rate limiting state
        self.__client_locks: dict[str, _ClientLockInfo] = {}  # {client_ip: lock_info}
        self.__rate_limit_lock = threading.Lock()

        if self.__rate_limit_enabled:
            logger.info("Login rate limiting enabled: max_attempts=%d, time_window=%ds, lockout_duration=%ds",
                        self.__rate_limit_max_attempts,
                        self.__rate_limit_time_window,
                        self.__rate_limit_lockout_duration)

        # Two-step login
        self.__two_step_login_enabled = two_step_login_enabled
        self.__two_step_sessions: dict[str, _TwoStepSession] = {}  # {two_step_token: session}
        self.__two_step_expire = 60  # 1 minute

        if self.__two_step_login_enabled:
            logger.info("Two-step login is enabled")

    def is_auth_enabled(self) -> bool:
        return self.__enabled

    def is_auth_required(self, exposed: HttpExposed) -> bool:
        return (
            self.is_auth_enabled()
            and exposed.auth_required
            and exposed.path not in self.__unauth_paths
        )

    async def authorize(self, user: str, passwd: str) -> bool:
        assert user == user.strip()
        assert user
        assert self.__enabled
        assert self.__int_service
        logger = get_logger(0)

        # 2fa, 页面会把2fa密码拼接在passwd后面
        if self.__totp_secret_path:
            with open(self.__totp_secret_path) as file:
                secret = file.read().strip()
            if secret:
                code = passwd[-6:]
                if not pyotp.TOTP(secret).verify(code, valid_window=1):
                    logger.error("Got access denied for user %r by TOTP", user)
                    return False
                passwd = passwd[:-6]

        if user not in self.__force_int_users and self.__ext_service:
            service = self.__ext_service
        else:
            service = self.__int_service

        pname = service.get_plugin_name()
        ok = (await service.authorize(user, passwd))
        if ok:
            logger.info("Authorized user %r via auth service %r", user, pname)
        else:
            logger.error("Got access denied for user %r from auth service %r", user, pname)
        return ok

    async def login(self, user: str, passwd: str, expire: int, client_ip: str = 'unknown') -> (str | None):
        assert user == user.strip()
        assert user
        assert expire >= 0
        assert self.__enabled

        # Check if client is rate limited
        if self.__rate_limit_enabled:
            is_locked, remaining_time = self._is_client_locked(client_ip)
            if is_locked:
                get_logger(0).warning("Rate limit: Login attempt blocked for client %s, %d seconds remaining",
                                      client_ip, remaining_time)
                raise RateLimitError(
                    f"Too many failed login attempts. Please try again in {remaining_time} seconds.",
                    remaining_time
                )

        # Perform cleanup periodically (every 100th login attempt)
        if self.__rate_limit_enabled and hash(client_ip) % 100 == 0:
            self._cleanup_expired_data()

        if (await self.authorize(user, passwd)):
            token = self.__make_new_token()
            session = _Session(
                user=user,
                expire_ts=self.__make_expire_ts(expire),
            )
            self.__sessions[token] = session
            get_logger(0).info("Logged in user %r; expire=%s, sessions_now=%d",
                               session.user,
                               self.__format_expire_ts(session.expire_ts),
                               self.__get_sessions_number(session.user))
            return token
        else:
            # Record failed attempt for rate limiting
            if self.__rate_limit_enabled:
                self._record_failed_attempt(client_ip)
                # Check if client is now locked after this attempt
                is_locked, remaining_time = self._is_client_locked(client_ip)
                if is_locked:
                    raise RateLimitError(
                        f"Account temporarily locked due to too many failed attempts. Please try again in {remaining_time} seconds.",
                        remaining_time
                    )

        return None

    def __make_new_token(self) -> str:
        for _ in range(10):
            token = secrets.token_hex(32)
            if token not in self.__sessions:
                return token
        raise RuntimeError("Can't generate new unique token")

    def __make_expire_ts(self, expire: int) -> int:
        assert expire >= 0
        assert self.__expire >= 0

        if expire == 0:
            # The user requested infinite session: apply global expire.
            # It will allow this (0) or set a limit.
            expire = self.__expire
        else:
            # The user wants a limited session
            if self.__expire > 0:
                # If we have a global limit, override the user limit
                assert expire > 0
                expire = min(expire, self.__expire)

        if expire > 0:
            return (self.__get_now_ts() + expire)

        assert expire == 0
        return 0

    def __get_now_ts(self) -> int:
        return int(time.monotonic())

    def __format_expire_ts(self, expire_ts: int) -> str:
        if expire_ts > 0:
            seconds = expire_ts - self.__get_now_ts()
            return f"[{self.__format_seconds(seconds)}]"
        return "INF"

    def __format_seconds(self, seconds: int) -> str:
        return str(datetime.timedelta(seconds=seconds))

    def __get_sessions_number(self, user: str) -> int:
        return sum(
            1
            for session in self.__sessions.values()
            if session.user == user
        )

    def logout(self, token: str) -> None:
        assert self.__enabled
        if token in self.__sessions:
            user = self.__sessions[token].user
            # count = 0
            # for (key_t, session) in list(self.__sessions.items()):
            #     if session.user == user:
            #         count += 1
            #         del self.__sessions[key_t]
            # get_logger(0).info("Logged out user %r; sessions_closed=%d", user, count)
            # 去掉删除所有此用户token的代码, 实在太蠢
            del self.__sessions[token]
            get_logger(0).info("Logged out user %r; sessions_left=%d", user, self.__get_sessions_number(user))

    def check(self, token: str) -> (str | None):
        assert self.__enabled
        session = self.__sessions.get(token)
        if session is not None:
            if session.expire_ts <= 0:
                # Infinite session
                return session.user
            else:
                # Limited session
                if self.__get_now_ts() < session.expire_ts:
                    return session.user
                else:
                    del self.__sessions[token]
                    get_logger(0).info("The session of user %r is expired; sessions_left=%d",
                                       session.user,
                                       self.__get_sessions_number(session.user))
        return None

    def is_two_step_login_enabled(self) -> bool:
        return self.__two_step_login_enabled

    def get_two_step_expire(self) -> int:
        return self.__two_step_expire

    def set_two_step_login_enabled(self, enabled: bool) -> None:
        self.__two_step_login_enabled = enabled
        if not enabled:
            self.__two_step_sessions.clear()
        get_logger(0).info("Two-step login %s", "enabled" if enabled else "disabled")

    async def pre_login(self, user: str, passwd: str, expire: int, client_ip: str = 'unknown', user_agent: str = '') -> (str | None):
        """两步登录第一步：验证用户名密码，返回临时 token"""
        assert user == user.strip()
        assert user
        assert expire >= 0
        assert self.__enabled

        # Check if client is rate limited
        if self.__rate_limit_enabled:
            is_locked, remaining_time = self._is_client_locked(client_ip)
            if is_locked:
                get_logger(0).warning("Rate limit: Login attempt blocked for client %s, %d seconds remaining",
                                      client_ip, remaining_time)
                raise RateLimitError(
                    f"Too many failed login attempts. Please try again in {remaining_time} seconds.",
                    remaining_time
                )

        # Perform cleanup periodically
        if hash(client_ip) % 100 == 0:
            self._cleanup_two_step_sessions()

        if (await self.authorize(user, passwd)):
            two_step_token = self.__make_new_two_step_token()
            # 在创建时就解析 user_agent
            from ...utils import parse_user_agent  # pylint: disable=import-outside-toplevel
            device_type, browser = parse_user_agent(user_agent)
            session = _TwoStepSession(
                user=user,
                expire_ts=time.time() + self.__two_step_expire,
                original_expire=expire,
                client_ip=client_ip,
                user_agent=user_agent,
                device_type=device_type,
                browser=browser,
                approved=False,
            )
            self.__two_step_sessions[two_step_token] = session
            get_logger(0).info("Pre-login successful for user %r from %s; two_step_token issued, expires in %ds",
                               user, client_ip, self.__two_step_expire)

            aiotools.create_short_task(asyncio.create_subprocess_shell("killall -SIGUSR2 gl_kvm_gui"))

            return two_step_token
        else:
            # Record failed attempt for rate limiting
            if self.__rate_limit_enabled:
                self._record_failed_attempt(client_ip)
                is_locked, remaining_time = self._is_client_locked(client_ip)
                if is_locked:
                    raise RateLimitError(
                        f"Account temporarily locked due to too many failed attempts. Please try again in {remaining_time} seconds.",
                        remaining_time
                    )
        return None

    def complete_two_step_login(self, two_step_token: str) -> tuple[str | None, str]:
        """两步登录第二步：用临时 token 换取正式 token
        返回 (token, status):
            - (token, "ok")      — 审批通过，返回正式 token
            - (None, "pending")  — 尚未审批，前端应继续轮询
            - (None, "expired")  — 临时 token 已过期
            - (None, "invalid")  — 临时 token 无效（不存在或已被拒绝）
        """
        assert self.__enabled

        session = self.__two_step_sessions.get(two_step_token)
        if session is None:
            get_logger(0).warning("Two-step login failed: invalid token")
            return (None, "invalid")

        current_time = time.time()
        if current_time > session.expire_ts:
            del self.__two_step_sessions[two_step_token]
            get_logger(0).warning("Two-step login failed: token expired for user %r", session.user)
            return (None, "expired")

        # 检查是否已审批
        if not session.approved:
            return (None, "pending")

        # Token valid and approved, remove it and issue real token
        del self.__two_step_sessions[two_step_token]

        token = self.__make_new_token()
        real_session = _Session(
            user=session.user,
            expire_ts=self.__make_expire_ts(session.original_expire),
        )
        self.__sessions[token] = real_session
        get_logger(0).info("Two-step login completed for user %r; expire=%s, sessions_now=%d",
                           real_session.user,
                           self.__format_expire_ts(real_session.expire_ts),
                           self.__get_sessions_number(real_session.user))
        return (token, "ok")

    def __make_new_two_step_token(self) -> str:
        for _ in range(10):
            token = "2s_" + secrets.token_hex(32)  # Prefix to distinguish from regular tokens
            if token not in self.__two_step_sessions:
                return token
        raise RuntimeError("Can't generate new unique two-step token")

    def _cleanup_two_step_sessions(self) -> None:
        """Clean up expired two-step sessions"""
        current_time = time.time()
        expired_tokens = [
            token for token, session in self.__two_step_sessions.items()
            if current_time > session.expire_ts
        ]
        for token in expired_tokens:
            del self.__two_step_sessions[token]

    def get_pending_two_step_session(self) -> (dict | None):
        """获取最后一个待审批的两步登录 session 信息"""
        current_time = time.time()
        # 清理过期的 session
        self._cleanup_two_step_sessions()

        # 找到最后一个未审批的 session
        for token, session in reversed(list(self.__two_step_sessions.items())):
            if not session.approved and current_time <= session.expire_ts:
                return {
                    "token": token,
                    "user": session.user,
                    "client_ip": session.client_ip,
                    "user_agent": session.user_agent,
                    "device_type": session.device_type,
                    "browser": session.browser,
                    "expires_in": int(session.expire_ts - current_time),
                }
        return None

    def approve_two_step_session(self, two_step_token: str) -> bool:
        """批准两步登录请求"""
        session = self.__two_step_sessions.get(two_step_token)
        if session is None:
            get_logger(0).warning("Two-step approve failed: invalid token")
            return False

        if time.time() > session.expire_ts:
            del self.__two_step_sessions[two_step_token]
            get_logger(0).warning("Two-step approve failed: token expired")
            return False

        session.approved = True
        get_logger(0).info("Two-step login approved for user %r from %s", session.user, session.client_ip)
        return True

    def reject_two_step_session(self, two_step_token: str) -> bool:
        """拒绝两步登录请求"""
        session = self.__two_step_sessions.get(two_step_token)
        if session is None:
            get_logger(0).warning("Two-step reject failed: invalid token")
            return False

        del self.__two_step_sessions[two_step_token]
        get_logger(0).info("Two-step login rejected for user %r from %s", session.user, session.client_ip)
        return True

    @aiotools.atomic_fg
    async def cleanup(self) -> None:
        if self.__enabled:
            assert self.__int_service
            await self.__int_service.cleanup()
            if self.__ext_service:
                await self.__ext_service.cleanup()

    # =====

    def __load_usc_uids(self, users: list[str], groups: list[str]) -> dict[int, str]:
        uids: dict[int, str] = {}

        pwds: dict[str, int] = {}
        for pw in pwd.getpwall():
            assert pw.pw_name == pw.pw_name.strip()
            assert pw.pw_name
            pwds[pw.pw_name] = pw.pw_uid
            if pw.pw_name in users:
                uids[pw.pw_uid] = pw.pw_name

        for gr in grp.getgrall():
            if gr.gr_name in groups:
                for member in gr.gr_mem:
                    if member in pwds:
                        uid = pwds[member]
                        uids[uid] = member

        return uids

    def check_unix_credentials(self, creds: RequestUnixCredentials) -> (str | None):
        assert self.__enabled
        return self.__usc_uids.get(creds.uid)

    # =====
    # Rate limiting methods

    def _get_client_ip(self, req_headers: dict) -> str:
        """Extract client IP from request headers."""
        # Try to get real IP from headers set by reverse proxy
        real_ip = req_headers.get('X-Real-IP')
        if real_ip:
            return real_ip

        forwarded_for = req_headers.get('X-Forwarded-For')
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            return forwarded_for.split(',')[0].strip()

        # Fallback to a default identifier if no IP is available
        return 'unknown'

    def _is_client_locked(self, client_ip: str) -> tuple[bool, int]:
        """Check if client is currently locked. Returns (is_locked, remaining_seconds)."""
        if not self.__rate_limit_enabled:
            return False, 0

        with self.__rate_limit_lock:
            lock_info = self.__client_locks.get(client_ip)
            if not lock_info:
                return False, 0

            current_time = time.time()
            if lock_info.locked_until > current_time:
                remaining = int(lock_info.locked_until - current_time)
                return True, remaining
            else:
                # Lock has expired, remove it
                if lock_info.locked_until > 0:  # Was actually locked
                    get_logger(0).info("Rate limit lock expired for client %s", client_ip)
                    del self.__client_locks[client_ip]
                return False, 0

    def _record_failed_attempt(self, client_ip: str) -> None:
        """Record a failed login attempt for the client."""
        if not self.__rate_limit_enabled:
            return

        current_time = time.time()
        with self.__rate_limit_lock:
            if client_ip not in self.__client_locks:
                self.__client_locks[client_ip] = _ClientLockInfo(
                    locked_until=0,
                    failed_attempts=[]
                )

            lock_info = self.__client_locks[client_ip]
            lock_info.failed_attempts.append(_LoginAttempt(timestamp=current_time))

            # Clean up old attempts outside the time window
            cutoff_time = current_time - self.__rate_limit_time_window
            lock_info.failed_attempts = [
                attempt for attempt in lock_info.failed_attempts
                if attempt.timestamp > cutoff_time
            ]

            # Check if we should lock the client
            if self._should_lock_client(lock_info):
                self._lock_client(client_ip, lock_info, current_time)

    def _should_lock_client(self, lock_info: _ClientLockInfo) -> bool:
        """Check if client should be locked based on failed attempts."""
        return len(lock_info.failed_attempts) >= self.__rate_limit_max_attempts

    def _lock_client(self, client_ip: str, lock_info: _ClientLockInfo, current_time: float) -> None:
        """Lock the client for the configured duration."""
        lock_info.locked_until = current_time + self.__rate_limit_lockout_duration
        get_logger(0).warning("Rate limit: Locking client %s for %d seconds due to %d failed attempts",
                              client_ip,
                              self.__rate_limit_lockout_duration,
                              len(lock_info.failed_attempts))

    def _cleanup_expired_data(self) -> None:
        """Clean up expired rate limiting data to prevent memory leaks."""
        if not self.__rate_limit_enabled:
            return

        current_time = time.time()
        cutoff_time = current_time - self.__rate_limit_time_window

        with self.__rate_limit_lock:
            clients_to_remove = []
            for client_ip, lock_info in self.__client_locks.items():
                # Remove expired locks and old failed attempts
                if lock_info.locked_until > 0 and lock_info.locked_until <= current_time:
                    lock_info.locked_until = 0

                # Clean up old attempts
                lock_info.failed_attempts = [
                    attempt for attempt in lock_info.failed_attempts
                    if attempt.timestamp > cutoff_time
                ]

                # If no recent attempts and not locked, remove the entry
                if not lock_info.failed_attempts and lock_info.locked_until <= current_time:
                    clients_to_remove.append(client_ip)

            for client_ip in clients_to_remove:
                del self.__client_locks[client_ip]

    def get_rate_limit_status(self, client_ip: str) -> dict:
        """Get rate limiting status for a client (for monitoring/debugging)."""
        if not self.__rate_limit_enabled:
            return {"enabled": False}

        with self.__rate_limit_lock:
            lock_info = self.__client_locks.get(client_ip)
            if not lock_info:
                return {
                    "enabled": True,
                    "locked": False,
                    "failed_attempts": 0,
                    "remaining_attempts": self.__rate_limit_max_attempts
                }

            current_time = time.time()
            is_locked = lock_info.locked_until > current_time
            remaining_lock_time = max(0, int(lock_info.locked_until - current_time)) if is_locked else 0

            # Count recent attempts
            cutoff_time = current_time - self.__rate_limit_time_window
            recent_attempts = len([
                attempt for attempt in lock_info.failed_attempts
                if attempt.timestamp > cutoff_time
            ])

            return {
                "enabled": True,
                "locked": is_locked,
                "locked_until": lock_info.locked_until if is_locked else 0,
                "remaining_lock_time": remaining_lock_time,
                "failed_attempts": recent_attempts,
                "remaining_attempts": max(0, self.__rate_limit_max_attempts - recent_attempts)
            }

    def unlock_client(self, client_ip: str) -> bool:
        """Manually unlock a client (for admin use). Returns True if client was unlocked."""
        if not self.__rate_limit_enabled:
            return False

        with self.__rate_limit_lock:
            lock_info = self.__client_locks.get(client_ip)
            if lock_info and lock_info.locked_until > time.time():
                lock_info.locked_until = 0
                lock_info.failed_attempts.clear()
                get_logger(0).info("Rate limit: Manually unlocked client %s", client_ip)
                return True
            return False

    def get_all_locked_clients(self) -> dict[str, dict]:
        """Get status of all currently locked clients (for monitoring)."""
        if not self.__rate_limit_enabled:
            return {}

        current_time = time.time()
        locked_clients = {}

        with self.__rate_limit_lock:
            for client_ip, lock_info in self.__client_locks.items():
                if lock_info.locked_until > current_time:
                    remaining_time = int(lock_info.locked_until - current_time)
                    locked_clients[client_ip] = {
                        "locked_until": lock_info.locked_until,
                        "remaining_time": remaining_time,
                        "failed_attempts": len(lock_info.failed_attempts)
                    }

        return locked_clients
