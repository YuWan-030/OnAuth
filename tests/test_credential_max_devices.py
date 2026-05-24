from __future__ import annotations

import datetime
from types import SimpleNamespace
from typing import cast

from sqlalchemy.orm import Session

from database import User
from routers import admin, tenant


class _SingleResultQuery:
    def __init__(self, result, count_result: int | None = None):
        self._result = result
        self._count_result = count_result

    def filter(self, *args, **kwargs):
        return self

    def join(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def offset(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def first(self):
        return self._result

    def all(self):
        if isinstance(self._result, list):
            return list(self._result)
        return [self._result] if self._result is not None else []

    def count(self):
        if self._count_result is not None:
            return self._count_result
        if isinstance(self._result, list):
            return len(self._result)
        return 1 if self._result is not None else 0


class _FakeDB:
    def __init__(self, app=None, credential=None, credentials=None, count_result: int | None = None):
        self.app = app
        self.credential = credential
        self.credentials = list(credentials or [])
        self.count_result = count_result
        self.added = None
        self.committed = False

    def query(self, model):
        model_name = model.__name__
        if model_name == "App":
            return _SingleResultQuery(self.app)
        if model_name == "AppCredential":
            if self.credential is not None:
                return _SingleResultQuery(self.credential, self.count_result)
            return _SingleResultQuery(self.credentials, self.count_result)
        raise AssertionError(f"unexpected model: {model}")

    def add(self, obj):
        self.added = obj

    def commit(self):
        self.committed = True


def test_admin_create_credential_applies_max_devices(monkeypatch) -> None:
    app = SimpleNamespace(id=7, app_name="App A", group=SimpleNamespace(group_name="Group A"))
    db = _FakeDB(app=app)
    current_user = SimpleNamespace(roles=[SimpleNamespace(name="admin:create")])

    monkeypatch.setattr(admin, "generate_random_keys", lambda: ("cli_001", "sec_001"))
    monkeypatch.setattr(admin, "hash_secret", lambda value: f"hashed:{value}")
    monkeypatch.setattr(admin, "create_jwt_token", lambda **kwargs: "license-token")
    monkeypatch.setattr(admin, "_parse_redirect_uri_whitelist_input", lambda value: ["https://app.example.com/callback"])
    monkeypatch.setattr(admin, "_save_redirect_uri_whitelist", lambda *args, **kwargs: None)

    result = admin.create_app_credential(
        app_id=7,
        credential_name="Prod Credential",
        scope="read write",
        max_devices=6,
        redirect_uris="https://app.example.com/callback",
        valid_days=30,
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert db.committed is True
    assert db.added is not None
    assert db.added.max_devices == 6
    assert db.added.scope == "read write"
    assert result["max_devices"] == 6
    assert result["client_id"] == "cli_001"


def test_admin_update_credential_config_updates_max_devices(monkeypatch) -> None:
    credential = SimpleNamespace(
        client_id="cli_001",
        credential_name="Prod Credential",
        scope="read",
        max_devices=2,
        expire_at=datetime.datetime(2026, 6, 1, 12, 0, 0),
    )
    db = _FakeDB(credential=credential)
    current_user = SimpleNamespace(roles=[SimpleNamespace(name="admin:update")])

    monkeypatch.setattr(admin, "_parse_redirect_uri_whitelist_input", lambda value: ["https://app.example.com/callback"])
    monkeypatch.setattr(admin, "_save_redirect_uri_whitelist", lambda *args, **kwargs: None)

    result = admin.update_credential_config(
        client_id="cli_001",
        scope="write",
        add_days=15,
        max_devices=9,
        redirect_uris="https://app.example.com/callback",
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert db.committed is True
    assert credential.scope == "write"
    assert credential.max_devices == 9
    assert result["max_devices"] == 9


def test_admin_credential_list_exposes_max_devices() -> None:
    app = SimpleNamespace(app_name="App A", group=SimpleNamespace(group_name="Group A"))
    credentials = [
        SimpleNamespace(
            id=1,
            client_id="cli_001",
            credential_name="Prod Credential",
            scope="read",
            max_devices=4,
            app=app,
            expire_at=datetime.datetime(2026, 6, 1, 12, 0, 0),
            is_active=True,
        )
    ]
    db = _FakeDB(credentials=credentials)
    current_user = SimpleNamespace(roles=[SimpleNamespace(name="admin:read")])

    result = admin.list_credentials_flat(
        page=1,
        limit=20,
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["count"] == 1
    assert result["data"][0]["max_devices"] == 4


def test_tenant_create_credential_applies_max_devices(monkeypatch) -> None:
    group = SimpleNamespace(id=8, group_name="Tenant A")
    app = SimpleNamespace(id=15, app_name="Tenant App", group_id=8, is_active=True)
    db = _FakeDB(app=app, count_result=0)
    current_user = SimpleNamespace(id=100, group_id=8, roles=[SimpleNamespace(name="tenant:credential:create")])

    monkeypatch.setattr(tenant, "_get_tenant_group", lambda db, current_user: group)
    monkeypatch.setattr(tenant, "generate_random_keys", lambda: ("cli_tenant", "sec_tenant"))
    monkeypatch.setattr(tenant, "hash_secret", lambda value: f"hashed:{value}")
    monkeypatch.setattr(tenant, "create_jwt_token", lambda **kwargs: "tenant-license")
    monkeypatch.setattr(tenant, "dispatch_webhook_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(tenant, "_parse_redirect_uri_whitelist_input", lambda value: ["https://tenant.example.com/callback"])
    monkeypatch.setattr(tenant, "_save_redirect_uri_whitelist", lambda *args, **kwargs: None)

    result = tenant.create_tenant_credential(
        app_id=15,
        credential_name="Tenant Credential",
        scope="read",
        max_devices=5,
        redirect_uris="https://tenant.example.com/callback",
        valid_days=90,
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert db.committed is True
    assert db.added is not None
    assert db.added.max_devices == 5
    assert result["max_devices"] == 5
    assert result["client_id"] == "cli_tenant"


def test_tenant_update_credential_config_updates_max_devices(monkeypatch) -> None:
    group = SimpleNamespace(id=8, group_name="Tenant A")
    credential = SimpleNamespace(
        client_id="cli_tenant",
        credential_name="Tenant Credential",
        scope="read",
        max_devices=2,
        expire_at=datetime.datetime(2026, 6, 1, 12, 0, 0),
        app=SimpleNamespace(id=15, group_id=8),
    )
    db = _FakeDB(credential=credential)
    current_user = SimpleNamespace(id=100, group_id=8, roles=[SimpleNamespace(name="tenant:credential:create")])

    monkeypatch.setattr(tenant, "_get_tenant_group", lambda db, current_user: group)
    monkeypatch.setattr(tenant, "_parse_redirect_uri_whitelist_input", lambda value: ["https://tenant.example.com/callback"])
    monkeypatch.setattr(tenant, "_save_redirect_uri_whitelist", lambda *args, **kwargs: None)

    result = tenant.update_tenant_credential_config(
        client_id="cli_tenant",
        scope="write",
        add_days=7,
        max_devices=8,
        redirect_uris="https://tenant.example.com/callback",
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert db.committed is True
    assert credential.scope == "write"
    assert credential.max_devices == 8
    assert result["max_devices"] == 8


def test_tenant_credential_list_exposes_max_devices(monkeypatch) -> None:
    group = SimpleNamespace(id=8, group_name="Tenant A")
    app = SimpleNamespace(id=15, app_name="Tenant App", group_id=8)
    credentials = [
        SimpleNamespace(
            id=1,
            client_id="cli_tenant",
            credential_name="Tenant Credential",
            scope="read",
            max_devices=3,
            redirect_uris=[],
            is_active=True,
            expire_at=datetime.datetime(2026, 6, 1, 12, 0, 0),
            app=app,
            app_id=15,
        )
    ]
    db = _FakeDB(credentials=credentials)
    current_user = SimpleNamespace(id=100, group_id=8, roles=[SimpleNamespace(name="tenant:credential:read")])

    monkeypatch.setattr(tenant, "_get_tenant_group", lambda db, current_user: group)

    result = tenant.list_tenant_credentials(
        page=1,
        limit=20,
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["count"] == 1
    assert result["data"][0]["max_devices"] == 3

