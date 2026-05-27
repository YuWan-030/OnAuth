from __future__ import annotations

import re
from types import SimpleNamespace
from typing import cast

import pytest
from database import User

from routers import auth_user


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}
        self.hashes: dict[str, dict[str, object]] = {}
        self.zsets: dict[str, dict[str, float]] = {}

    def get(self, key: str):
        return self.values.get(key)

    def setex(self, key: str, ttl: int, value):
        self.values[key] = value

    def delete(self, key: str):
        self.values.pop(key, None)
        self.hashes.pop(key, None)

    def hset(self, key: str, mapping=None, **kwargs):
        payload = dict(mapping or {})
        payload.update(kwargs)
        self.hashes.setdefault(key, {})
        self.hashes[key].update(payload)

    def hgetall(self, key: str):
        return self.hashes.get(key, {})

    def expire(self, *args, **kwargs):
        return None

    def zadd(self, key: str, mapping):
        self.zsets.setdefault(key, {})
        self.zsets[key].update(mapping)

    def zrevrange(self, key: str, start: int, end: int):
        items = sorted(self.zsets.get(key, {}).items(), key=lambda item: item[1], reverse=True)
        sliced = items[start:end + 1]
        return [code for code, _score in sliced]


@pytest.fixture()
def fake_redis(monkeypatch):
    backend = _FakeRedis()
    monkeypatch.setattr(auth_user, "redis_client", backend)
    return backend


def test_tenant_admin_invite_status_distinguishes_used_and_expired(fake_redis) -> None:
    code_used, _ = auth_user._issue_tenant_admin_invite_payload("root", invite_code="INV-USED")
    code_expired, _ = auth_user._issue_tenant_admin_invite_payload("root", invite_code="INV-EXPIRED")

    auth_user._mark_tenant_admin_invite_used(code_used, used_by="tenant_admin")
    fake_redis.delete(auth_user._tenant_admin_invite_key(code_expired))

    assert auth_user._tenant_admin_invite_status(code_used) == "used"
    assert auth_user._tenant_admin_invite_status(code_expired) == "expired"

    items = auth_user._tenant_admin_invite_list(limit=10)
    status_map = {item["invite_code"]: item for item in items}
    assert status_map[code_used]["status"] == "used"
    assert status_map[code_expired]["status"] == "expired"
    created_at = str(status_map[code_used]["created_at"])
    expires_at = str(status_map[code_used]["expires_at"])
    used_at = str(status_map[code_used]["used_at"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", created_at)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", expires_at)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", used_at)


def test_tenant_admin_invite_status_marks_revoke_as_revoked(fake_redis, monkeypatch) -> None:
    code, _ = auth_user._issue_tenant_admin_invite_payload("root", invite_code="INV-REVOKE")
    current_user = SimpleNamespace(username="super_root", roles=[SimpleNamespace(name="super_admin")])

    result = auth_user.revoke_tenant_admin_invite_code(
        invite_code=code,
        current_user=cast(User, cast(object, current_user)),
    )

    assert result["data"]["status"] == "revoked"
    assert auth_user._tenant_admin_invite_status(code) == "revoked"

