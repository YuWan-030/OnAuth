from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from fastapi import Request
from utils import auth_security


class _FakeHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class _FakeRequest:
    def __init__(self, ip: str, user_agent: str):
        self.headers = _FakeHeaders({"User-Agent": user_agent, "X-Real-IP": ip})
        self.client = SimpleNamespace(host=ip)
        self.state = SimpleNamespace()


def test_extract_client_meta_detects_android_mobile() -> None:
    request = _FakeRequest(
        ip="8.8.8.8",
        user_agent=(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
        ),
    )

    ip, ua, is_mobile, browser, os_name, location = auth_security.extract_client_meta(
        cast(Request, request),
        include_location=False,
    )

    assert ip == "8.8.8.8"
    assert ua
    assert is_mobile is True
    assert browser == "Chrome"
    assert os_name == "Android"
    assert location == "-"


def test_extract_client_meta_detects_ios_safari_from_ipados_desktop_ua() -> None:
    request = _FakeRequest(
        ip="8.8.8.8",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
        ),
    )

    _, _, is_mobile, browser, os_name, _ = auth_security.extract_client_meta(
        cast(Request, request),
        include_location=False,
    )

    assert is_mobile is True
    assert browser == "Safari"
    assert os_name == "iOS"


def test_extract_client_meta_reuses_location_within_request(monkeypatch) -> None:
    request = _FakeRequest(
        ip="8.8.8.8",
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    )
    calls: list[str] = []

    def _fake_resolve(ip_value: str) -> str:
        calls.append(ip_value)
        return "中国 浙江 宁波 电信"

    monkeypatch.setattr(auth_security, "resolve_ip_location", _fake_resolve)

    first = auth_security.extract_client_meta(cast(Request, request), include_location=True)
    second = auth_security.extract_client_meta(cast(Request, request), include_location=True)

    assert first[5] == "中国 浙江 宁波 电信"
    assert second[5] == "中国 浙江 宁波 电信"
    assert calls == ["8.8.8.8"]

