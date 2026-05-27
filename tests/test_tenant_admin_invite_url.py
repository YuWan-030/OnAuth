from __future__ import annotations

from typing import Any, cast

import pytest
from fastapi import HTTPException

from routers import invite_admin


class _FakeRole:
    def __init__(self, name: str):
        self.name = name


class _FakeUser:
    def __init__(self, username: str, roles: list[_FakeRole]):
        self.username = username
        self.roles = roles


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    def setex(self, key: str, ttl: int, value):
        self.values[key] = value

    def hset(self, *args, **kwargs):
        return None

    def expire(self, *args, **kwargs):
        return None

    def zadd(self, *args, **kwargs):
        return None


def test_issue_tenant_admin_invite_code_returns_tenant_register_url(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(invite_admin, "redis_client", fake_redis, raising=False)
    monkeypatch.setattr(invite_admin, "_issue_tenant_admin_invite_payload", lambda issuer_username: ("CODE123", {"issuer_username": issuer_username, "created_at": "now", "expires_at": "later"}))

    result = invite_admin.issue_tenant_admin_invite_code(
        current_user=cast(Any, _FakeUser("root", [_FakeRole("super_admin")]))
    )

    assert result["status"] == "success"
    assert result["data"]["invite_url"] == "/tenant/register?invite_code=CODE123"


def test_issue_tenant_admin_invite_code_rejects_non_super_admin() -> None:
    with pytest.raises(HTTPException):
        invite_admin.issue_tenant_admin_invite_code(
            current_user=cast(Any, _FakeUser("admin", [_FakeRole("admin")]))
        )

