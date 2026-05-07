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


import os
import stat
import io
import json
import socket
import struct
import ctypes
import ctypes.util
import contextlib
import warnings

from ctypes import POINTER
from ctypes import Structure
from ctypes import c_int
from ctypes import c_bool
from ctypes import c_char_p
from ctypes import c_void_p
from ctypes import c_char

from typing import Generator
from typing import AsyncGenerator

from PIL import ImageOps
from PIL import Image as PilImage

from ...errors import OperationError

from ... import libc
from ... import aiotools

# Fallback paths for libtesseract when ctypes.util.find_library fails
# Try version 5 (tesseract 5.x) first, then version 3 (tesseract 3.x)
_STATIC_LIBTESSERACT_PATHS = [
    "/usr/lib/libtesseract.so.5",
    "/usr/lib/libtesseract.so.5.0.0",
    "/usr/lib/arm-linux-gnueabihf/libtesseract.so.5",
    "/usr/lib/aarch64-linux-gnu/libtesseract.so.5",
    "/usr/lib/libtesseract.so.3",
    "/usr/lib/libtesseract.so.3.0.5",
]

# =====
class OcrError(OperationError):
    pass


# =====
class _TessBaseAPI(Structure):
    pass


def _load_libtesseract() -> (ctypes.CDLL | None):
    try:
        path = ctypes.util.find_library("tesseract")
        if not path:
            for candidate in _STATIC_LIBTESSERACT_PATHS:
                if os.path.exists(candidate):
                    path = candidate
                    break
            if not path:
                raise RuntimeError("Can't find libtesseract")
        lib = ctypes.CDLL(path)
        for (name, restype, argtypes) in [
            ("TessBaseAPICreate", POINTER(_TessBaseAPI), []),
            ("TessBaseAPIDelete", None, [POINTER(_TessBaseAPI)]),
            ("TessBaseAPIInit3", c_int, [POINTER(_TessBaseAPI), c_char_p, c_char_p]),
            ("TessBaseAPISetImage", None, [POINTER(_TessBaseAPI), c_void_p, c_int, c_int, c_int, c_int]),
            ("TessBaseAPIGetUTF8Text", POINTER(c_char), [POINTER(_TessBaseAPI)]),
            ("TessBaseAPISetVariable", c_bool, [POINTER(_TessBaseAPI), c_char_p, c_char_p]),
        ]:
            func = getattr(lib, name)
            if not func:
                raise RuntimeError(f"Can't find libtesseract.{name}")
            setattr(func, "restype", restype)
            setattr(func, "argtypes", argtypes)
        return lib
    except Exception as ex:
        warnings.warn(f"Can't load libtesseract: {ex}", RuntimeWarning)
        return None


_libtess = _load_libtesseract()


# =====
# RKNN OCR —— 通过 Unix domain socket 与 ocr_service 通信
# 协议：
#   请求：[4字节 JSON大小 LE][JSON语义参数]
#         JSON: {"left": -1, "top": -1, "right": -1, "bottom": -1}
#         - left/top/right/bottom: 裁剪坐标，-1 表示不裁剪
#         截图来源固定为 /run/kvmd/ustreamer.sock（ocr_service 通过 libwebsockets HTTP GET 获取）
#   响应：[4字节 文本大小 LE][UTF-8 文本]
#         大小 = 0xFFFFFFFF 表示错误，后跟 [4字节错误信息大小][错误信息]

_RKNN_SOCK_TIMEOUT = 15.0  # 秒


def _sock_recv_all(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OcrError("ocr_service: connection closed unexpectedly")
        buf += chunk
    return buf


def _rknn_recognize_params(sock_path: str, params: dict) -> str:
    """将 JSON 参数发给 ocr_service，service 自行取图并识别，返回识别文本"""
    payload = json.dumps(params, ensure_ascii=False).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(_RKNN_SOCK_TIMEOUT)
        try:
            sock.connect(sock_path)
        except (FileNotFoundError, ConnectionRefusedError) as ex:
            raise OcrError(f"ocr_service socket unavailable ({sock_path}): {ex}") from ex
        # 发送 [4字节 JSON大小 LE][JSON 字节]
        sock.sendall(struct.pack("<I", len(payload)))
        sock.sendall(payload)
        # 读取响应头（4字节）
        header = _sock_recv_all(sock, 4)
        (text_len,) = struct.unpack("<I", header)
        if text_len == 0xFFFFFFFF:
            err_len_data = _sock_recv_all(sock, 4)
            (err_len,) = struct.unpack("<I", err_len_data)
            err_msg = _sock_recv_all(sock, err_len).decode("utf-8", errors="replace")
            raise OcrError(f"ocr_service error: {err_msg}")
        if text_len == 0:
            return ""
        return _sock_recv_all(sock, text_len).decode("utf-8", errors="replace")


def _rknn_sock_available(sock_path: str) -> bool:
    """检查 ocr_service Unix socket 是否存在且可连接"""
    if not sock_path:
        return False
    try:
        return stat.S_ISSOCK(os.stat(sock_path).st_mode)
    except OSError:
        return False


def _tess_api(data_dir_path: str, langs: list[str]) -> Generator[_TessBaseAPI, None, None]:
    if not _libtess:
        raise OcrError("Tesseract is not available")
    api = _libtess.TessBaseAPICreate()
    try:
        if _libtess.TessBaseAPIInit3(api, data_dir_path.encode(), "+".join(langs).encode()) != 0:
            raise OcrError("Can't initialize Tesseract")
        if not _libtess.TessBaseAPISetVariable(api, b"debug_file", b"/dev/null"):
            raise OcrError("Can't set debug_file=/dev/null")
        yield api
    finally:
        _libtess.TessBaseAPIDelete(api)


_LANG_SUFFIX = ".traineddata"


# =====
class Ocr:
    def __init__(
        self,
        data_dir_path: str,
        default_langs: list[str],
        rknn_socket: str = "",
    ) -> None:
        self.__data_dir_path = data_dir_path
        self.__default_langs = default_langs
        self.__rknn_socket = rknn_socket
        self.__notifier = aiotools.AioNotifier()

    def _use_rknn(self) -> bool:
        """若 rknn_socket 已配置且 socket 文件存在则使用 RKNN 模式"""
        return _rknn_sock_available(self.__rknn_socket)

    async def get_state(self) -> dict:
        rknn = self._use_rknn()
        tess = bool(_libtess)
        enabled = rknn or tess
        default: list[str] = []
        available: list[str] = []
        if enabled:
            default = self.get_default_langs()
            if not rknn:
                available = self.get_available_langs()
        return {
            "enabled": enabled,
            "engine": ("rknn" if rknn else "tesseract"),
            "langs": {
                "default": default,
                "available": available,
            },
        }

    async def trigger_state(self) -> None:
        self.__notifier.notify()

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        while True:
            await self.__notifier.wait()
            yield (await self.get_state())

    # =====

    def get_default_langs(self) -> list[str]:
        return list(self.__default_langs)

    def get_available_langs(self) -> list[str]:
        # RKNN 模式无需（也无法使用）Tesseract 语言文件，直接返回空列表
        if self._use_rknn():
            return []
        # 若 tessdata 目录不存在则也返回空列表，避免 FileNotFoundError
        if not os.path.isdir(self.__data_dir_path):
            return []
        langs: set[str] = set()
        for lang_name in os.listdir(self.__data_dir_path):
            if lang_name.endswith(_LANG_SUFFIX):
                path = os.path.join(self.__data_dir_path, lang_name)
                if os.access(path, os.R_OK) and stat.S_ISREG(os.stat(path).st_mode):
                    lang = lang_name[:-len(_LANG_SUFFIX)]
                    if lang:
                        langs.add(lang)
        return sorted(langs)

    async def recognize(self, data: bytes, langs: list[str], left: int, top: int, right: int, bottom: int) -> str:
        if not langs:
            langs = self.__default_langs
        if self._use_rknn():
            # RKNN 模式：只传参数，ocr_service 自行获取截图，data 不使用
            return (await aiotools.run_async(self.__rknn_recognize, left, top, right, bottom))
        return (await aiotools.run_async(self.__tess_recognize, data, langs, left, top, right, bottom))

    # ── RKNN path ──────────────────────────────────────────────────────────

    def __rknn_recognize(self, left: int, top: int, right: int, bottom: int) -> str:
        """ocr_service 自行从固定路径 /run/kvmd/ustreamer.sock 获取截图并 OCR。
        ocr.py 只传递裁剪坐标。
        """
        params = {
            "left":   left,
            "top":    top,
            "right":  right,
            "bottom": bottom,
        }
        return _rknn_recognize_params(self.__rknn_socket, params)

    # ── Tesseract path ─────────────────────────────────────────────────────

    def __tess_recognize(self, data: bytes, langs: list[str], left: int, top: int, right: int, bottom: int) -> str:
        with _tess_api(self.__data_dir_path, langs) as api:
            assert _libtess
            with io.BytesIO(data) as bio:
                image = PilImage.open(bio)
                try:
                    if left >= 0 or top >= 0 or right >= 0 or bottom >= 0:
                        left   = (0 if left   < 0 else min(image.width,  left))
                        top    = (0 if top    < 0 else min(image.height, top))
                        right  = (image.width  if right  < 0 else min(image.width,  right))
                        bottom = (image.height if bottom < 0 else min(image.height, bottom))
                        if left < right and top < bottom:
                            image_cropped = image.crop((left, top, right, bottom))
                            image.close()
                            image = image_cropped  # type: ignore

                    ImageOps.grayscale(image)
                    image_resized = image.resize((int(image.size[0] * 2), int(image.size[1] * 2)), PilImage.Resampling.BICUBIC)
                    image.close()
                    image = image_resized  # type: ignore

                    _libtess.TessBaseAPISetImage(api, image.tobytes("raw", "RGB"), image.width, image.height, 3, image.width * 3)
                    text_ptr = None
                    try:
                        text_ptr = _libtess.TessBaseAPIGetUTF8Text(api)
                        text = ctypes.cast(text_ptr, c_char_p).value
                        if text is None:
                            raise OcrError("Can't recognize image")
                        return text.decode("utf-8")
                    finally:
                        if text_ptr is not None:
                            libc.free(text_ptr)
                finally:
                    image.close()

