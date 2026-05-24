from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from main import _asyncio_exception_handler, _is_benign_windows_connection_reset


class _FakeLoop:
    def __init__(self) -> None:
        self.default_calls: list[dict[str, object]] = []

    def default_exception_handler(self, context: dict[str, object]) -> None:
        self.default_calls.append(context)


def _make_10054_error() -> ConnectionResetError:
    exc = ConnectionResetError("[WinError 10054] 远程主机强迫关闭了一个现有的连接。")
    exc.winerror = 10054  # type: ignore[attr-defined]
    return exc


def test_benign_windows_connection_reset_is_suppressed() -> None:
    exc = _make_10054_error()
    context = {
        "exception": exc,
        "handle": SimpleNamespace(_callback=None, _args=()),
        "message": "Exception in callback _ProactorBasePipeTransport._call_connection_lost()",
    }

    assert _is_benign_windows_connection_reset(context) is True

    loop = _FakeLoop()
    _asyncio_exception_handler(cast(object, loop), context)

    assert loop.default_calls == []


def test_non_matching_exception_is_not_suppressed() -> None:
    exc = ConnectionResetError("connection reset")
    context = {
        "exception": exc,
        "message": "some other asyncio callback failure",
    }

    assert _is_benign_windows_connection_reset(context) is False

    loop = _FakeLoop()
    _asyncio_exception_handler(cast(object, loop), context)

    assert loop.default_calls == [context]

