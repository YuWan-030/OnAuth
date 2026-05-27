from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from fastapi import Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from database import User
from routers import admin, views
from schemas.admin_schema import TenantReviewInput


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._result


class _AdminFakeDB:
    def __init__(self, group, user):
        self._group = group
        self._user = user
        self.flushed = False
        self.committed = False

    def query(self, model):
        if model.__name__ == "DeveloperGroup":
            return _FakeQuery(self._group)
        if model.__name__ == "User":
            return _FakeQuery(self._user)
        raise AssertionError(f"unexpected model: {model}")

    def flush(self):
        self.flushed = True

    def commit(self):
        self.committed = True

    def refresh(self, obj):
        return None


class _ViewsFakeDB:
    def query(self, model):
        raise AssertionError("views tests should not hit db query")


def test_review_tenant_approve_binds_owner_group(monkeypatch) -> None:
    group = SimpleNamespace(
        id=33,
        group_name="Tenant Space",
        owner_user_id=10,
        owner="tenant_admin",
        status="pending",
        is_active=False,
        expire_at=None,
    )
    owner_user = SimpleNamespace(
        id=10,
        username="tenant_admin",
        group_id=None,
        roles=[SimpleNamespace(name="tenant_admin", is_active=False)],
    )
    db = _AdminFakeDB(group, owner_user)

    monkeypatch.setattr(admin, "dispatch_webhook_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(admin, "_clear_user_rbac_cache", lambda *args, **kwargs: None)

    result = admin.review_tenant(
        group_id=33,
        payload=cast(TenantReviewInput, cast(object, SimpleNamespace(action="approve", expire_at="2026-12-31T23:59:59", review_note="ok"))),
        current_user=cast(User, cast(object, SimpleNamespace(roles=[SimpleNamespace(name="super_admin")]))),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert group.status == "approved"
    assert group.is_active is True
    assert group.owner_user_id == owner_user.id
    assert group.owner == owner_user.username
    assert owner_user.group_id == group.id
    assert db.committed is True


def test_tenant_root_redirects_to_apply_when_not_bound(monkeypatch) -> None:
    user_obj = SimpleNamespace(id=10, username="tenant_admin", roles=[SimpleNamespace(name="tenant_admin")])
    monkeypatch.setattr(views, "_decode_session_username", lambda value: "tenant_admin")
    monkeypatch.setattr(views, "_load_user_from_session", lambda username, db: user_obj)
    monkeypatch.setattr(views, "_is_tenant_admin", lambda user: True)
    monkeypatch.setattr(views, "_tenant_access_snapshot", lambda user: (None, "当前账号尚未绑定租户空间"))

    response = views.tenant_root_view(
        request=cast(Request, cast(object, SimpleNamespace())),
        sso_session_id="sess_x",
        db=cast(Session, cast(object, _ViewsFakeDB())),
    )

    assert isinstance(response, RedirectResponse)
    assert response.headers["location"] == "/tenant/apply"


def test_index_redirects_tenant_admin_pending_to_error(monkeypatch) -> None:
    user_obj = SimpleNamespace(id=10, username="tenant_admin", roles=[SimpleNamespace(name="tenant_admin")])
    monkeypatch.setattr(views, "_decode_session_username", lambda value: "tenant_admin")
    monkeypatch.setattr(views, "check_user_admin_privilege", lambda username, db: False)
    monkeypatch.setattr(views, "_load_user_from_session", lambda username, db: user_obj)
    monkeypatch.setattr(views, "_is_tenant_admin", lambda user: True)
    monkeypatch.setattr(views, "_tenant_access_snapshot", lambda user: (SimpleNamespace(id=33), "租户空间尚未通过审核"))

    response = views.index_page_view(
        request=cast(Request, cast(object, SimpleNamespace())),
        sso_session_id="sess_x",
        db=cast(Session, cast(object, _ViewsFakeDB())),
    )

    assert isinstance(response, RedirectResponse)
    assert response.headers["location"] == "/tenant/error"


