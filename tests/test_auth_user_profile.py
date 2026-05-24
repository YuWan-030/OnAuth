from __future__ import annotations

from typing import cast
from types import SimpleNamespace

from sqlalchemy.orm import Session

from database import User
from routers.auth_user import get_current_user_profile


class _FakeQuery:
    def __init__(self, group):
        self._group = group

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._group


class _FakeDB:
    def __init__(self, group):
        self._group = group

    def query(self, model):
        return _FakeQuery(self._group)


def test_get_current_user_profile_resolves_group_from_group_id() -> None:
    group = SimpleNamespace(
        id=7,
        group_name="Tenant A",
        group_code="TENANT-A",
        status="approved",
        is_active=True,
        review_note=None,
        reviewed_at=None,
        expire_at=None,
    )
    current_user = SimpleNamespace(
        id=101,
        username="alice",
        nickname="Alice",
        group_id=7,
        roles=[SimpleNamespace(name="read"), SimpleNamespace(name="tenant_admin")],
    )

    result = get_current_user_profile(
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, _FakeDB(group))),
    )

    assert result["status"] == "success"
    assert result["data"]["user_id"] == 101
    assert result["data"]["group_id"] == 7
    assert result["data"]["group_name"] == "Tenant A"
    assert result["data"]["group_code"] == "TENANT-A"
    assert result["data"]["roles"] == ["read", "tenant_admin"]
    assert result["data"]["is_tenant_admin"] is True


def test_resolve_user_group_falls_back_to_owner_user_id() -> None:
    group = SimpleNamespace(
        id=9,
        group_name="Owner Space",
        group_code="OWNER-SPACE",
        status="approved",
        is_active=True,
        review_note=None,
        reviewed_at=None,
        expire_at=None,
        owner_user_id=101,
    )
    current_user = SimpleNamespace(
        id=101,
        username="owner_user",
        nickname="Owner",
        group_id=None,
        roles=[SimpleNamespace(name="read")],
    )

    result = get_current_user_profile(
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, _FakeDB(group))),
    )

    assert result["data"]["group_id"] == 9
    assert result["data"]["group_name"] == "Owner Space"


