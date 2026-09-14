# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
# ========================================================================== #


import struct

import pytest

from kvmd.apps.otg.hid import Hid
from kvmd.apps.otg.hid.mouse import make_mouse_hid
from kvmd.apps.otg.hid.ffs import make_descriptors
from kvmd.apps.otg.hid.ffs import make_strings
from kvmd.apps.otg.hid.ffs import make_hid_descriptor
from kvmd.apps.otg.hid.ffs import handle_setup


# =====
_HIDS = [make_mouse_hid(absolute=True, horizontal_wheel=True), make_mouse_hid(absolute=False, horizontal_wheel=True)]
_FD = 99


def _split(descs: bytes) -> list[bytes]:
    items: list[bytes] = []
    while descs:
        items.append(descs[:descs[0]])
        descs = descs[descs[0]:]
    return items


def _make_setup(request_type: int, request: int, value: int, index: int, length: int) -> bytes:
    return struct.pack("<BBHHH", request_type, request, value, index, length)


# =====
def test_ok__make_descriptors() -> None:
    blob = make_descriptors(_HIDS)
    (magic, length, flags, fs_count, hs_count) = struct.unpack("<5I", blob[:20])
    assert magic == 3
    assert length == len(blob)
    assert flags == 3
    assert fs_count == hs_count == 6

    half = (len(blob) - 20) // 2
    for (offset, interval) in [(20, 1), (20 + half, 4)]:
        descs = _split(blob[offset:offset + half])
        assert [desc[1] for desc in descs] == [4, 0x21, 5, 4, 0x21, 5]
        assert [desc[2] for desc in descs if desc[1] == 4] == [0, 1]  # Interface numbers
        assert [desc[4] for desc in descs if desc[1] == 4] == [1, 1]  # One endpoint each
        assert [desc[5:8] for desc in descs if desc[1] == 4] == [b"\x03\x00\x00"] * 2  # HID, no boot protocol
        assert [desc[8] for desc in descs if desc[1] == 4] == [1, 2]  # iInterface
        assert [desc[2] for desc in descs if desc[1] == 5] == [0x81, 0x82]  # IN endpoints only
        assert [desc[3] for desc in descs if desc[1] == 5] == [3, 3]  # Interrupt
        assert [desc[6] for desc in descs if desc[1] == 5] == [interval, interval]
        assert [
            struct.unpack("<H", desc[7:9])[0]
            for desc in descs if desc[1] == 0x21
        ] == [len(hid.report_descriptor) for hid in _HIDS]


def test_ok__make_descriptors__single() -> None:
    blob = make_descriptors(_HIDS[:1])
    assert struct.unpack("<5I", blob[:20])[3:] == (3, 3)
    assert len(blob) == 20 + 2 * (9 + 9 + 7)


def test_ok__make_strings() -> None:
    blob = make_strings(["Absolute Mouse", "Relative Mouse"])
    assert struct.unpack("<4I", blob[:16]) == (2, len(blob), 2, 1)
    assert struct.unpack("<H", blob[16:18])[0] == 0x0409
    assert blob[18:] == b"Absolute Mouse\0Relative Mouse\0"


def test_ok__make_hid_descriptor() -> None:
    hid = Hid(protocol=0, subclass=0, report_length=7, report_descriptor=(b"\x05" * 60))
    assert make_hid_descriptor(hid) == bytes([9, 0x21, 0x11, 0x01, 0, 1, 0x22, 60, 0])


# =====
def test_ok__get_report_descriptor(mocker) -> None:  # type: ignore
    write = mocker.patch("os.write")
    handle_setup(_FD, _make_setup(0x81, 6, 0x2200, 1, 3), _HIDS, [0, 0])
    write.assert_called_once_with(_FD, _HIDS[1].report_descriptor[:3])


def test_ok__get_hid_descriptor(mocker) -> None:  # type: ignore
    write = mocker.patch("os.write")
    handle_setup(_FD, _make_setup(0x81, 6, 0x2100, 0, 9), _HIDS, [0, 0])
    write.assert_called_once_with(_FD, make_hid_descriptor(_HIDS[0]))


def test_ok__get_input_report(mocker) -> None:  # type: ignore
    write = mocker.patch("os.write")
    handle_setup(_FD, _make_setup(0xA1, 1, 0x0100, 0, 64), _HIDS, [0, 0])
    write.assert_called_once_with(_FD, bytes(_HIDS[0].report_length))


def test_ok__set_and_get_idle(mocker) -> None:  # type: ignore
    read = mocker.patch("os.read")
    write = mocker.patch("os.write")
    idle = [0, 0]
    handle_setup(_FD, _make_setup(0x21, 10, 0x0500, 1, 0), _HIDS, idle)
    read.assert_called_once_with(_FD, 0)
    write.assert_not_called()
    assert idle == [0, 5]
    handle_setup(_FD, _make_setup(0xA1, 2, 0, 1, 1), _HIDS, idle)
    write.assert_called_once_with(_FD, b"\x05")


@pytest.mark.parametrize("setup", [
    _make_setup(0xA1, 55, 0, 1, 1),  # Unknown class request
    _make_setup(0x81, 6, 0x2200, 2, 64),  # Interface out of range
    _make_setup(0x81, 6, 0x0100, 0, 64),  # Device descriptor is not ours
])
def test_ok__unknown_in_request_stalls(mocker, setup: bytes) -> None:  # type: ignore
    read = mocker.patch("os.read")
    write = mocker.patch("os.write")
    handle_setup(_FD, setup, _HIDS, [0, 0])
    read.assert_called_once_with(_FD, 0)
    write.assert_not_called()


@pytest.mark.parametrize("setup", [
    _make_setup(0x21, 55, 0, 1, 0),  # Unknown class request
    _make_setup(0x21, 9, 0x0200, 0, 1),  # SET_REPORT (output) is not supported
    _make_setup(0x21, 10, 0x0500, 0, 1),  # SET_IDLE with an unexpected data stage
])
def test_ok__unknown_out_request_stalls(mocker, setup: bytes) -> None:  # type: ignore
    read = mocker.patch("os.read")
    write = mocker.patch("os.write")
    handle_setup(_FD, setup, _HIDS, [0, 0])
    write.assert_called_once_with(_FD, b"")
    read.assert_not_called()
