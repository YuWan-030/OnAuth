from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from sqlalchemy.orm import Session

from routers import admin
from database import User
from schemas.admin_schema import TenantSpaceAssignInput


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._result


class _FakeDB:
    def __init__(self, group, user_results):
        self.group = group
        self.user_results = list(user_results)

    def query(self, model):
        if model.__name__ == "DeveloperGroup":
            return _FakeQuery(self.group)
        if model.__name__ == "User":
            result = self.user_results.pop(0)
            return _FakeQuery(result)
        raise AssertionError(f"unexpected model: {model}")

    def commit(self):
        return None

    def refresh(self, obj):
        return None


def test_assign_group_to_new_owner_clears_previous_non_super_admin_group_id(monkeypatch) -> None:
    group = SimpleNamespace(id=9, group_name="Space A", owner_user_id=11, owner="old_owner")
    old_owner = SimpleNamespace(id=11, username="old_owner", group_id=9, roles=[SimpleNamespace(name="tenant_admin")])
    new_owner = SimpleNamespace(id=22, username="new_owner", group_id=None, roles=[SimpleNamespace(name="tenant_admin")])
    current_user = SimpleNamespace(roles=[SimpleNamespace(name="super_admin")])
    db = _FakeDB(group, [new_owner, old_owner])

    monkeypatch.setattr(admin, "dispatch_webhook_event", lambda *args, **kwargs: None)

    result = admin.assign_group_to_tenant_admin(
        group_id=9,
        payload=cast(TenantSpaceAssignInput, cast(object, SimpleNamespace(user_id=22, bind_user_group=True))),
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert group.owner_user_id == 22
    assert group.owner == "new_owner"
    assert new_owner.group_id == 9
    assert old_owner.group_id is None


def test_assign_group_keeps_previous_super_admin_group_id(monkeypatch) -> None:
    group = SimpleNamespace(id=9, group_name="Space A", owner_user_id=11, owner="old_owner")
    old_owner = SimpleNamespace(id=11, username="old_owner", group_id=9, roles=[SimpleNamespace(name="super_admin")])
    new_owner = SimpleNamespace(id=22, username="new_owner", group_id=None, roles=[SimpleNamespace(name="tenant_admin")])
    current_user = SimpleNamespace(roles=[SimpleNamespace(name="super_admin")])
    db = _FakeDB(group, [new_owner, old_owner])

    monkeypatch.setattr(admin, "dispatch_webhook_event", lambda *args, **kwargs: None)

    result = admin.assign_group_to_tenant_admin(
        group_id=9,
        payload=cast(TenantSpaceAssignInput, cast(object, SimpleNamespace(user_id=22, bind_user_group=True))),
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert group.owner_user_id == 22
    assert new_owner.group_id == 9
    assert old_owner.group_id == 9

