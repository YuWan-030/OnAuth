from __future__ import annotations

import pytest
from fastapi import HTTPException

from routers.tenant import _parse_redirect_uri_whitelist_input


def test_parse_redirect_uri_whitelist_deduplicates_and_supports_multiline() -> None:
    raw = "https://a.example.com/callback\nhttps://a.example.com/callback,https://b.example.com/cb"
    parsed = _parse_redirect_uri_whitelist_input(raw)
    assert parsed == ["https://a.example.com/callback", "https://b.example.com/cb"]


def test_parse_redirect_uri_whitelist_rejects_non_local_http() -> None:
    with pytest.raises(HTTPException) as exc:
        _parse_redirect_uri_whitelist_input("http://evil.example.com/callback")
    assert exc.value.status_code == 400
    assert "仅允许本地地址" in str(exc.value.detail)

