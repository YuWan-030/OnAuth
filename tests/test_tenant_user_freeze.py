from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from database import DeveloperGroup, User
from routers import auth_user, oauth


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def options(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def first(self):
        if isinstance(self._result, list):
            return self._result[0] if self._result else None
        return self._result

    def all(self):
        if isinstance(self._result, list):
            return list(self._result)
        if self._result is None:
            return []
        return [self._result]


class _FakeDB:
    def __init__(self, result_map: dict[type, object]):
        self._result_map = result_map
        self.committed = False
        self.added = []

    def query(self, model):
        return _FakeQuery(self._result_map.get(model))

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        return None

    def commit(self):
        self.committed = True

    def refresh(self, obj):
        return None


class _FakeRedis:
    def __init__(self):
        self.values: dict[str, object] = {}
        self.sets: dict[str, set[bytes]] = {}
        self.deleted: list[tuple[object, ...]] = []

    def get(self, key: str):
        return self.values.get(key)

    def delete(self, *keys):
        self.deleted.append(keys)
        for key in keys:
            norm_key = key.decode("utf-8") if isinstance(key, bytes) else key
            self.values.pop(norm_key, None)
            self.sets.pop(norm_key, None)

    def smembers(self, key: str):
        return set(self.sets.get(key, set()))

    def srem(self, key: str, member: str):
        members = self.sets.get(key, set())
        encoded = member.encode("utf-8") if isinstance(member, str) else member
        members.discard(encoded)
        self.sets[key] = members

    def setex(self, *args, **kwargs):
        return None

    def expire(self, *args, **kwargs):
        return None

    def hset(self, *args, **kwargs):
        return None

    def scan_iter(self, pattern: str):
        prefix = pattern[:-1] if pattern.endswith("*") else pattern
        for key in list(self.values.keys()):
            if key.startswith(prefix):
                yield key.encode("utf-8")


@pytest.fixture()
def fake_redis(monkeypatch):
    redis_backend = _FakeRedis()
    monkeypatch.setattr(auth_user, "redis_client", redis_backend)
    monkeypatch.setattr(oauth, "redis_client", redis_backend)
    monkeypatch.setattr(auth_user, "dispatch_webhook_event", lambda *args, **kwargs: None)
    return redis_backend


def test_tenant_freeze_user_revokes_sessions_and_oauth(fake_redis) -> None:
    fake_redis.sets["user:active_sessions:100"] = {b"sess_a", b"sess_b"}
    fake_redis.values["sess_a"] = b"100"
    fake_redis.values["sess_b"] = b"100"
    fake_redis.values["oauth_code:code_a"] = '{"client_id": "client_1", "user_id": 100, "username": "alice"}'
    fake_redis.values["oauth_userinfo:token_a"] = '{"user_id": 100, "username": "alice"}'

    group = SimpleNamespace(id=9, group_name="Space A", status="approved", is_active=True, expire_at=None)
    target_user = SimpleNamespace(id=100, username="alice", nickname="Alice", email="alice@example.com", is_active=True, roles=[])
    current_user = SimpleNamespace(id=22, username="tenant_admin", group_id=9, group=group, roles=[SimpleNamespace(name="tenant_admin")])
    db = _FakeDB({DeveloperGroup: group, User: target_user})

    result = auth_user.freeze_tenant_user(
        payload=auth_user.TenantUserFreezeSchema(user_id=100),
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert target_user.is_active is False
    deleted_flat = {
        item.decode("utf-8") if isinstance(item, bytes) else item
        for call in fake_redis.deleted
        for item in call
    }
    assert "sess_a" in deleted_flat
    assert "sess_b" in deleted_flat
    assert "user:active_sessions:100" in deleted_flat
    assert "oauth_code:code_a" in deleted_flat
    assert "oauth_userinfo:token_a" in deleted_flat


def test_tenant_freeze_user_rejects_self_freeze(fake_redis) -> None:
    group = SimpleNamespace(id=9, group_name="Space A", status="approved", is_active=True, expire_at=None)
    current_user = SimpleNamespace(id=22, username="tenant_admin", group_id=9, group=group, roles=[SimpleNamespace(name="tenant_admin")])
    db = _FakeDB({DeveloperGroup: group, User: current_user})

    with pytest.raises(HTTPException) as exc_info:
        auth_user.freeze_tenant_user(
            payload=auth_user.TenantUserFreezeSchema(user_id=22),
            current_user=cast(User, cast(object, current_user)),
            db=cast(Session, cast(object, db)),
        )

    assert exc_info.value.status_code == 400
    assert "不能冻结当前登录账号" in str(exc_info.value.detail)


def test_list_tenant_users_requires_approved_group(fake_redis) -> None:
    group = SimpleNamespace(id=9, group_name="Space A", status="pending", is_active=True, expire_at=None)
    current_user = SimpleNamespace(id=22, username="tenant_admin", group_id=9, group=group, roles=[SimpleNamespace(name="tenant_admin")])
    db = _FakeDB({DeveloperGroup: group, User: []})

    with pytest.raises(HTTPException) as exc_info:
        auth_user.list_tenant_users(
            current_user=cast(User, cast(object, current_user)),
            db=cast(Session, cast(object, db)),
        )

    assert exc_info.value.status_code == 403
    assert "尚未通过审核" in str(exc_info.value.detail)


def test_get_current_user_profile_returns_group_context(fake_redis) -> None:
    group = SimpleNamespace(id=9, group_name="Space A", group_code="grp-9", status="approved", is_active=True, expire_at=None)
    current_user = SimpleNamespace(id=22, username="tenant_admin", nickname="Tenant Admin", group_id=9, group=group, roles=[SimpleNamespace(name="read"), SimpleNamespace(name="tenant_admin")])
    db = _FakeDB({DeveloperGroup: group})

    result = auth_user.get_current_user_profile(
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert result["data"]["group_id"] == 9
    assert result["data"]["group_code"] == "grp-9"
    assert result["data"]["is_tenant_admin"] is True


def test_generate_tenant_invite_link_returns_shareable_url(fake_redis) -> None:
    group = SimpleNamespace(id=9, group_name="Space A", group_code="grp-9", status="approved", is_active=True, expire_at=None)
    current_user = SimpleNamespace(id=22, username="tenant_admin", group_id=9, group=group, roles=[SimpleNamespace(name="tenant_admin")])
    db = _FakeDB({DeveloperGroup: group})

    result = auth_user.generate_tenant_user_invite_link(
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert result["data"]["invite_url"].startswith("/register?invite_token=")


def test_register_user_with_invite_token_auto_binds_group(fake_redis) -> None:
    group = SimpleNamespace(id=9, group_name="Space A", group_code="grp-9", status="approved", is_active=True, expire_at=None)
    invite_payload = {"group_id": 9, "group_name": "Space A", "group_code": "grp-9", "issuer_username": "tenant_admin", "created_at": "2026-05-27T00:00:00+00:00"}
    fake_redis.values["tenant_invite:token_abc"] = str(invite_payload).replace("'", '"')
    db = _FakeDB({DeveloperGroup: group, User: None})

    result = auth_user.register_user(
        payload=auth_user.UserRegisterSchema(username="alice", password="Aa!23456", nickname="Alice", invite_token="token_abc"),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert result["group_id"] == 9
    assert db.added
    assert any(getattr(item, "group_id", None) == 9 and getattr(item, "username", None) == "alice" for item in db.added)


def test_register_user_requires_invite_token(fake_redis) -> None:
    db = _FakeDB({DeveloperGroup: None, User: None})

    with pytest.raises(HTTPException) as exc_info:
        auth_user.register_user(
            payload=auth_user.UserRegisterSchema(username="alice", password="Aa!23456", nickname="Alice"),
            db=cast(Session, cast(object, db)),
        )

    assert exc_info.value.status_code == 403
    assert "必须使用租户空间邀请码" in str(exc_info.value.detail)


def test_tenant_enable_blocks_system_frozen_user(fake_redis) -> None:
    group = SimpleNamespace(id=9, group_name="Space A", group_code="grp-9", status="approved", is_active=True, expire_at=None)
    frozen_user = SimpleNamespace(id=100, username="alice", nickname="Alice", email="alice@example.com", is_active=False, frozen_by_role="system_admin", roles=[])
    current_user = SimpleNamespace(id=22, username="tenant_admin", group_id=9, group=group, roles=[SimpleNamespace(name="tenant_admin")])
    db = _FakeDB({DeveloperGroup: group, User: frozen_user})

    with pytest.raises(HTTPException) as exc_info:
        auth_user.toggle_tenant_user_status(
            payload=auth_user.TenantUserToggleStatusSchema(user_id=100, is_active=True),
            current_user=cast(User, cast(object, current_user)),
            db=cast(Session, cast(object, db)),
        )

    assert exc_info.value.status_code == 403
    assert "无权启用" in str(exc_info.value.detail)


