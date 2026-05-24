from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from sqlalchemy.orm import Session

from database import User
from routers import tenant
from schemas.admin_schema import CredentialStatusInput


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def join(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._result


class _FakeDB:
    def __init__(self, group, credential):
        self.group = group
        self.credential = credential
        self.committed = False

    def query(self, model):
        if model.__name__ == "DeveloperGroup":
            return _FakeQuery(self.group)
        if model.__name__ == "AppCredential":
            return _FakeQuery(self.credential)
        if model.__name__ == "App":
            return _FakeQuery(SimpleNamespace(id=1, group_id=self.group.id))
        raise AssertionError(f"unexpected model: {model}")

    def commit(self):
        self.committed = True


def test_update_tenant_credential_status_can_enable_revoked_credential(monkeypatch) -> None:
    group = SimpleNamespace(id=8, status="approved", is_active=True, expire_at=None)
    credential = SimpleNamespace(client_id="cli_123", is_active=False)
    current_user = SimpleNamespace(id=100, group_id=8, roles=[SimpleNamespace(name="tenant_admin")])
    db = _FakeDB(group, credential)

    monkeypatch.setattr(tenant, "_get_tenant_group", lambda db, current_user: group)

    result = tenant.update_tenant_credential_status(
        client_id="cli_123",
        payload=cast(CredentialStatusInput, cast(object, SimpleNamespace(is_active=True))),
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert result["is_active"] is True
    assert credential.is_active is True
    assert db.committed is True


def test_revoke_tenant_credential_sets_inactive(monkeypatch) -> None:
    group = SimpleNamespace(id=8, status="approved", is_active=True, expire_at=None)
    credential = SimpleNamespace(client_id="cli_123", is_active=True)
    current_user = SimpleNamespace(id=100, group_id=8, roles=[SimpleNamespace(name="tenant_admin")])
    db = _FakeDB(group, credential)

    monkeypatch.setattr(tenant, "_get_tenant_group", lambda db, current_user: group)

    result = tenant.revoke_tenant_credential(
        client_id="cli_123",
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert credential.is_active is False
    assert db.committed is True

