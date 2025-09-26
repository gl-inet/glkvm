





















import time

from typing import Callable
from typing import Awaitable

from evdev import ecodes



class MagicHandler:
    __MAGIC_KEY = ecodes.KEY_LEFTALT
    __MAGIC_TIMEOUT = 2
    __MAGIC_TRIGGER = 2

    def __init__(
        self,
        proxy_handler: Callable[[int, bool], Awaitable[None]],
        key_handlers: (dict[int, Callable[[], Awaitable[None]]] | None)=None,
        numeric_handler: (Callable[[list[int]], Awaitable[bool]] | None)=None,
    ) -> None:

        self.__proxy_handler = proxy_handler
        self.__key_handlers = (key_handlers or {})
        self.__numeric_handler = numeric_handler

        self.__taps = 0
        self.__ts = 0.0
        self.__codes: list[int] = []

    async def handle_key(self, key: int, state: bool) -> None:
        if self.__ts + self.__MAGIC_TIMEOUT < time.monotonic():
            self.__taps = 0
            self.__ts = 0
            self.__codes = []

        if key == self.__MAGIC_KEY:
            if not state:
                self.__taps += 1
                self.__ts = time.monotonic()
        elif state:
            taps = self.__taps
            codes = self.__codes
            self.__taps = 0
            self.__ts = 0
            self.__codes = []
            if taps >= self.__MAGIC_TRIGGER:
                if key in self.__key_handlers:
                    await self.__key_handlers[key]()
                    return
                elif self.__numeric_handler is not None and (ecodes.KEY_1 <= key <= ecodes.KEY_8):
                    codes.append(key - ecodes.KEY_1)
                    if not (await self.__numeric_handler(list(codes))):


                        self.__taps = taps
                        self.__ts = time.monotonic()
                        self.__codes = codes
                    return

        await self.__proxy_handler(key, state)
