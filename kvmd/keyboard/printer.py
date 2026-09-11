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


import ctypes
import ctypes.util
import unicodedata

from typing import Generator

from evdev import ecodes

from .keysym import SymmapModifiers

import os

static_libxkbcommon_path = "/usr/lib/libxkbcommon.so.0.0.0"


# =====
# Mapping from Unicode combining characters to X11 dead key keysyms.
# Used to decompose accented characters (e.g. á = dead_acute + a) for
# keyboard layouts that use dead keys (Spanish, French, German, etc.)
_COMBINING_TO_DEAD_KEYSYM: dict[int, int] = {
    0x0300: 0xFE50,  # combining grave accent       → dead_grave
    0x0301: 0xFE51,  # combining acute accent       → dead_acute
    0x0302: 0xFE52,  # combining circumflex accent  → dead_circumflex
    0x0303: 0xFE53,  # combining tilde              → dead_tilde
    0x0304: 0xFE54,  # combining macron             → dead_macron
    0x0306: 0xFE55,  # combining breve              → dead_breve
    0x0307: 0xFE56,  # combining dot above          → dead_abovedot
    0x0308: 0xFE57,  # combining diaeresis          → dead_diaeresis
    0x030A: 0xFE58,  # combining ring above         → dead_abovering
    0x030B: 0xFE59,  # combining double acute       → dead_doubleacute
    0x030C: 0xFE5A,  # combining caron              → dead_caron
    0x0327: 0xFE5B,  # combining cedilla            → dead_cedilla
    0x0328: 0xFE5C,  # combining ogonek             → dead_ogonek
}


def _load_libxkbcommon() -> (ctypes.CDLL | None):
    path = ctypes.util.find_library("xkbcommon")
    if not path:
        if os.path.exists(static_libxkbcommon_path):
            path = static_libxkbcommon_path
        else:
            return None
    try:
        lib = ctypes.CDLL(path)
        func = getattr(lib, "xkb_utf32_to_keysym", None)
        if not func:
            return None
        setattr(func, "restype", ctypes.c_uint32)
        setattr(func, "argtypes", [ctypes.c_uint32])
        return lib
    except (OSError, AttributeError):
        return None


_libxkbcommon = _load_libxkbcommon()


def _ch_to_keysym_fallback(cp: int) -> int:
    """Pure Python fallback for xkb_utf32_to_keysym.
    For Latin-1 printable range the keysym equals the Unicode code point.
    Above U+00FF, EuroSign retains its legacy keysym; other code points
    use 0x01000000 + code point."""
    if (0x0020 <= cp <= 0x007E) or (0x00A0 <= cp <= 0x00FF):
        return cp
    if cp == 0x20AC:
        return cp  # EuroSign has a legacy keysym, used by the supplied keymaps.
    if cp > 0x00FF:
        return cp | 0x01000000
    return 0  # non-mappable control characters


def _ch_to_keysym(ch: str) -> int:
    assert len(ch) == 1
    # Some native xkbcommon builds return the obsolete 0x13A4 alias for Euro.
    # Our X11 keymaps consistently use EuroSign (0x20AC).
    if ch == "€":
        return 0x20AC
    if _libxkbcommon is not None:
        return _libxkbcommon.xkb_utf32_to_keysym(ord(ch))
    return _ch_to_keysym_fallback(ord(ch))


def _try_dead_key_decompose(
    ch: str,
    symmap: dict[int, dict[int, int]],
) -> (list[dict[int, int]] | None):
    """Try to decompose an accented character into [dead_key_keys, base_char_keys].

    For example, 'á' decomposes to dead_acute + 'a'.  If both the dead key
    and the base character exist in the symmap the function returns the two
    key-mapping dicts that should be pressed in sequence.  Otherwise returns None.
    """
    decomp = unicodedata.decomposition(ch)
    if not decomp or decomp.startswith("<"):
        return None

    parts = decomp.split()
    if len(parts) != 2:
        return None

    try:
        base_cp = int(parts[0], 16)
        combining_cp = int(parts[1], 16)
    except ValueError:
        return None

    dead_keysym = _COMBINING_TO_DEAD_KEYSYM.get(combining_cp)
    if dead_keysym is None:
        return None

    base_keysym = _ch_to_keysym(chr(base_cp))

    dead_keys = symmap.get(dead_keysym)
    base_keys = symmap.get(base_keysym)
    if dead_keys is None or base_keys is None:
        return None

    return [dead_keys, base_keys]


# =====
def text_to_evdev_keys(  # pylint: disable=too-many-branches
    text: str,
    symmap: dict[int, dict[int, int]],
) -> Generator[tuple[int, bool], None, None]:

    shift = False
    altgr = False

    for ch in text:
        # https://stackoverflow.com/questions/12343987/convert-ascii-character-to-x11-keycode
        # https://www.ascii-code.com
        #
        # key_sequence is a list of key-mapping dicts to press in order.
        # Normally it contains a single entry; for dead-key compositions
        # (e.g. á = dead_acute then a) it contains two entries.
        key_sequence: list[dict[int, int]] = []

        if ch == "\n":
            key_sequence = [{0: ecodes.KEY_ENTER}]
        elif ch == "\t":
            key_sequence = [{0: ecodes.KEY_TAB}]
        elif ch == " ":
            key_sequence = [{0: ecodes.KEY_SPACE}]
        else:
            if ch in ["\u201a", "\u2018", "\u2019"]:
                ch = "'"
            elif ch in ["\u201e", "\u201c", "\u201d"]:
                ch = "\""
            elif ch == "\u2013":  # Short (en dash)
                ch = "-"
            elif ch == "\u2014":  # Long (em dash)
                ch = "-"
            if not ch.isprintable():
                continue
            try:
                key_sequence = [symmap[_ch_to_keysym(ch)]]
            except Exception:
                # Character not directly in symmap — try dead-key
                # decomposition for accented characters like á é ñ etc.
                decomposed = _try_dead_key_decompose(ch, symmap)
                if decomposed is not None:
                    key_sequence = decomposed
                else:
                    continue

        for keys in key_sequence:
            for (modifiers, key) in keys.items():
                if modifiers & SymmapModifiers.CTRL:
                    # Not supported yet
                    continue

                if modifiers & SymmapModifiers.SHIFT and not shift:
                    yield (ecodes.KEY_LEFTSHIFT, True)
                    shift = True
                elif not (modifiers & SymmapModifiers.SHIFT) and shift:
                    yield (ecodes.KEY_LEFTSHIFT, False)
                    shift = False

                if modifiers & SymmapModifiers.ALTGR and not altgr:
                    # Send Left Ctrl + Right Alt for AltGr.
                    # On Windows, the keyboard driver synthesizes Left Ctrl when
                    # AltGr (Right Alt) is pressed on international layouts.
                    # Some USB HID hosts only recognise AltGr as Ctrl+Alt (0x41),
                    # not Right Alt alone (0x40).  Sending both ensures universal
                    # compatibility across Windows, Linux and BIOS/UEFI screens.
                    yield (ecodes.KEY_LEFTCTRL, True)
                    yield (ecodes.KEY_RIGHTALT, True)
                    altgr = True
                elif not (modifiers & SymmapModifiers.ALTGR) and altgr:
                    yield (ecodes.KEY_RIGHTALT, False)
                    yield (ecodes.KEY_LEFTCTRL, False)
                    altgr = False

                yield (key, True)
                yield (key, False)
                break

    if shift:
        yield (ecodes.KEY_LEFTSHIFT, False)
    if altgr:
        yield (ecodes.KEY_RIGHTALT, False)
        yield (ecodes.KEY_LEFTCTRL, False)
