import asyncio
from pathlib import Path
from typing import Callable
from typing import NamedTuple
from unittest.mock import AsyncMock
from unittest.mock import Mock

import pytest
from evdev import ecodes

from kvmd.apps.kvmd.api.hid import HidApi
from kvmd.htserver import _get_exposed_ws
from kvmd.keyboard.keysym import build_symmap
from kvmd.keyboard.printer import text_to_evdev_keys


KEYMAPS = Path(__file__).resolve().parents[4] / "contrib" / "keymaps"


class HidFixture(NamedTuple):
    api: HidApi
    hid: Mock


@pytest.fixture(name="api")
def fixture_api(monkeypatch: pytest.MonkeyPatch) -> HidFixture:
    monkeypatch.setattr(HidApi, "_HidApi__load_jiggler_schedule", lambda _: None)
    hid = Mock(send_key_events=AsyncMock())
    return HidFixture(HidApi(hid, str(KEYMAPS / "de")), hid)


def handler(api: HidFixture, name: str) -> Callable:
    return next(item.handler for item in _get_exposed_ws(api.api) if item.event_type == name)


@pytest.mark.asyncio
@pytest.mark.parametrize("text", list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZäöüÄÖÜß@€[]{}\\|<>~ "))
async def test_german_characters(api: HidFixture, text: str) -> None:
    ws = Mock(send_event=AsyncMock())
    await handler(api, "mapped_text")(ws, {"text": text, "keymap": "de"})
    expected = list(text_to_evdev_keys(text, build_symmap(str(KEYMAPS / "de"))))
    assert expected
    api.hid.send_key_events.assert_awaited_once_with(expected, no_ignore_keys=True, slow=False)
    ws.send_event.assert_awaited_once_with("mapped_text_result", {"mapped": True, "text": text})
    held = set()
    for key, state in expected:
        if state:
            assert key not in held
            held.add(key)
        else:
            assert key in held
            held.remove(key)
    assert not held


@pytest.mark.asyncio
async def test_at_uses_german_altgr_q(api: HidFixture) -> None:
    ws = Mock(send_event=AsyncMock())
    await handler(api, "mapped_text")(ws, {"text": "@", "keymap": "de"})
    api.hid.send_key_events.assert_awaited_once_with([
        (ecodes.KEY_LEFTCTRL, True), (ecodes.KEY_RIGHTALT, True),
        (ecodes.KEY_Q, True), (ecodes.KEY_Q, False),
        (ecodes.KEY_RIGHTALT, False), (ecodes.KEY_LEFTCTRL, False),
    ], no_ignore_keys=True, slow=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("event", [{}, {"text": ""}, {"text": "ab"}, {"text": 42}, {"text": "\n"},
                                       {"text": "\x00"}, {"text": "\ud800"}, {"text": "a", "keymap": "../de"},
                                       {"text": "a", "keymap": "missing"}, {"text": "a", "keymap": []}])
async def test_invalid_input_does_not_emit_hid(api: HidFixture, event: dict) -> None:
    ws = Mock(send_event=AsyncMock())
    await handler(api, "mapped_text")(ws, event)
    api.hid.send_key_events.assert_not_called()
    ws.send_event.assert_awaited_once_with("mapped_text_result", {"mapped": False, "reason": "invalid"})


@pytest.mark.asyncio
async def test_unmappable_character_reports_failure(api: HidFixture) -> None:
    ws = Mock(send_event=AsyncMock())
    await handler(api, "mapped_text")(ws, {"text": "😀", "keymap": "de"})
    api.hid.send_key_events.assert_not_called()
    ws.send_event.assert_awaited_once_with("mapped_text_result", {"mapped": False, "text": "😀"})


@pytest.mark.asyncio
async def test_ack_waits_for_hid_sequence(api: HidFixture) -> None:
    entered = asyncio.Event()
    finish = asyncio.Event()

    async def send(*_args: object, **_kwargs: object) -> None:
        entered.set()
        await finish.wait()

    api.hid.send_key_events.side_effect = send
    ws = Mock(send_event=AsyncMock())
    task = asyncio.create_task(handler(api, "mapped_text")(ws, {"text": "a"}))
    await entered.wait()
    ws.send_event.assert_not_called()
    assert not task.done()
    finish.set()
    await task
    ws.send_event.assert_awaited_once()


@pytest.mark.asyncio
async def test_capability_is_advertised(api: HidFixture) -> None:
    state = await api.api.get_keymaps()
    assert state["mapped_text"] is True
    assert "de" in state["keymaps"]["available"]


@pytest.mark.asyncio
@pytest.mark.parametrize(("text", "key"), [("y", ecodes.KEY_Z), ("z", ecodes.KEY_Y)])
async def test_german_y_and_z_follow_characters(api: HidFixture, text: str, key: int) -> None:
    await handler(api, "mapped_text")(Mock(send_event=AsyncMock()), {"text": text, "keymap": "de"})
    api.hid.send_key_events.assert_awaited_once_with(
        [(key, True), (key, False)], no_ignore_keys=True, slow=False,
    )


@pytest.mark.asyncio
async def test_euro_without_native_xkbcommon(api: HidFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    from kvmd.keyboard import printer  # pylint: disable=import-outside-toplevel
    monkeypatch.setattr(printer, "_libxkbcommon", None)
    await handler(api, "mapped_text")(Mock(send_event=AsyncMock()), {"text": "€", "keymap": "de"})
    api.hid.send_key_events.assert_awaited_once_with([
        (ecodes.KEY_LEFTCTRL, True), (ecodes.KEY_RIGHTALT, True),
        (ecodes.KEY_E, True), (ecodes.KEY_E, False),
        (ecodes.KEY_RIGHTALT, False), (ecodes.KEY_LEFTCTRL, False),
    ], no_ignore_keys=True, slow=False)


@pytest.mark.asyncio
async def test_euro_with_obsolete_native_alias(api: HidFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    from kvmd.keyboard import printer  # pylint: disable=import-outside-toplevel
    native = Mock(xkb_utf32_to_keysym=Mock(return_value=0x13A4))
    monkeypatch.setattr(printer, "_libxkbcommon", native)
    await handler(api, "mapped_text")(Mock(send_event=AsyncMock()), {"text": "€", "keymap": "de"})
    assert api.hid.send_key_events.await_args.args[0] == [
        (ecodes.KEY_LEFTCTRL, True), (ecodes.KEY_RIGHTALT, True),
        (ecodes.KEY_E, True), (ecodes.KEY_E, False),
        (ecodes.KEY_RIGHTALT, False), (ecodes.KEY_LEFTCTRL, False),
    ]
    native.xkb_utf32_to_keysym.assert_not_called()
