from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from routers import auth_user


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._result


class _FakeDB:
    def __init__(self, result_map: dict[type, object]):
        self._result_map = result_map
        self.added: list[object] = []
        self.committed = False
        self._next_id = 1

    def query(self, model):
        return _FakeQuery(self._result_map.get(model))

    def add(self, obj):
        if getattr(obj, "id", None) is None:
            try:
                obj.id = self._next_id
                self._next_id += 1
            except Exception:
                pass
        self.added.append(obj)

    def flush(self):
        return None

    def commit(self):
        self.committed = True

    def refresh(self, obj):
        return None


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}
        self.deleted: list[str] = []

    def get(self, key: str):
        return self.values.get(key)

    def setex(self, key: str, ttl: int, value):
        self.values[key] = value

    def delete(self, key: str):
        self.deleted.append(key)
        self.values.pop(key, None)


@pytest.fixture()
def fake_redis(monkeypatch):
    backend = _FakeRedis()
    monkeypatch.setattr(auth_user, "redis_client", backend)
    monkeypatch.setattr(auth_user, "dispatch_webhook_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_user, "_extract_client_meta", lambda request, include_location=True: ("127.0.0.1", "ua", False, "Chrome", "Windows", ""))
    monkeypatch.setattr(auth_user, "_acquire_tenant_apply_limit", lambda client_ip: None)
    monkeypatch.setattr(auth_user, "_generate_group_code", lambda db: "GROUP1234")
    monkeypatch.setattr(auth_user, "_ensure_role", lambda *args, **kwargs: SimpleNamespace(name="tenant_admin", permissions=[]))
    return backend


def test_issue_tenant_admin_invite_code_requires_super_admin(fake_redis) -> None:
    with pytest.raises(HTTPException) as exc_info:
        auth_user.issue_tenant_admin_invite_code(
            current_user=cast(Any, SimpleNamespace(username="admin", roles=[SimpleNamespace(name="admin")]))
        )

    assert exc_info.value.status_code == 403


def test_issue_tenant_admin_invite_code_returns_and_persists_code(fake_redis) -> None:
    result = auth_user.issue_tenant_admin_invite_code(
        current_user=cast(Any, SimpleNamespace(username="root", roles=[SimpleNamespace(name="super_admin")]))
    )

    assert result["status"] == "success"
    invite_code = result["data"]["invite_code"]
    assert invite_code
    stored = fake_redis.values.get(auth_user._tenant_admin_invite_key(invite_code))
    assert stored is not None


def test_tenant_admin_registration_rejects_invalid_invite_code(fake_redis) -> None:
    db = _FakeDB({auth_user.User: None, auth_user.DeveloperGroup: None})

    with pytest.raises(HTTPException) as exc_info:
        auth_user.register_tenant_admin(
            payload=auth_user.TenantAdminRegisterSchema(
                username="tenant_admin_1",
                password="Aa!23456",
                nickname="Tenant Admin",
                group_name="Tenant Space",
                group_description="demo",
                invite_code="badcode1",
            ),
            request=cast(Any, SimpleNamespace()),
            db=cast(Session, cast(object, db)),
        )

    assert exc_info.value.status_code == 403
    assert "邀请码" in str(exc_info.value.detail)


def test_tenant_admin_registration_consumes_valid_invite_code(fake_redis) -> None:
    invite_code, _ = auth_user._issue_tenant_admin_invite_payload("root")
    db = _FakeDB({auth_user.User: None, auth_user.DeveloperGroup: None})

    result = auth_user.register_tenant_admin(
        payload=auth_user.TenantAdminRegisterSchema(
            username="tenant_admin_1",
            password="Aa!23456",
            nickname="Tenant Admin",
            group_name="Tenant Space",
            group_description="demo",
            invite_code=invite_code,
        ),
        request=cast(Any, SimpleNamespace()),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert result["group_code"] == "GROUP1234"
    assert auth_user._tenant_admin_invite_key(invite_code) in fake_redis.deleted
    assert db.committed is True
    assert len(db.added) >= 2
    created_group = db.added[0]
    created_user = db.added[1]
    assert getattr(created_group, "group_name", None) == "Tenant Space"
    assert getattr(created_user, "username", None) == "tenant_admin_1"
    assert getattr(created_group, "owner_user_id", None) == getattr(created_user, "id", None)



