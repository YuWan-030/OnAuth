from __future__ import annotations

import datetime
import json
import uuid
from types import SimpleNamespace
from typing import cast

from sqlalchemy.orm import Session

from database import App, AppCredential, DeveloperGroup, SessionLocal, init_db, User
from routers import admin, tenant
from routers import credential_redirect_uris as redirect_store
from utils.crypto import hash_secret


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def set(self, key, value):
        self.store[str(key)] = value if isinstance(value, str) else value.decode("utf-8") if isinstance(value, bytes) else str(value)
        return True

    def get(self, key):
        return self.store.get(str(key))

    def delete(self, key):
        self.store.pop(str(key), None)
        return True


def _create_credential(db: Session, client_id: str) -> AppCredential:
    suffix = uuid.uuid4().hex[:8]
    group = DeveloperGroup(
        group_name=f"edit-test-group-{suffix}",
        group_code=f"eg{suffix}",
        owner="tester",
        is_active=True,
        status="approved",
    )
    db.add(group)
    db.flush()

    app = App(
        group_id=group.id,
        app_name=f"edit-test-app-{suffix}",
        owner="tester",
        is_active=True,
    )
    db.add(app)
    db.flush()

    credential = AppCredential(
        app_id=app.id,
        credential_name=f"edit-test-credential-{suffix}",
        client_id=client_id,
        client_secret_hash=hash_secret("secret123"),
        scope="read",
        max_devices=1,
        expire_at=datetime.datetime.now() + datetime.timedelta(days=30),
    )
    db.add(credential)
    db.commit()
    db.refresh(credential)
    return credential


def test_admin_update_credential_config_persists_redirect_uris_to_database(monkeypatch) -> None:
    init_db()
    fake_redis = _FakeRedis()
    monkeypatch.setattr(redirect_store, "redis_client", fake_redis, raising=False)

    db = SessionLocal()
    client_id = f"admin-edit-{uuid.uuid4().hex[:12]}"
    app_id: int | None = None
    group_id: int | None = None
    try:
        credential = _create_credential(db, client_id)
        app_id = credential.app_id
        group_id = credential.app.group_id if credential.app else None

        result = admin.update_credential_config(
            client_id=client_id,
            scope="write",
            add_days=10,
            max_devices=3,
            redirect_uris="https://admin.example.com/callback\nhttps://admin.example.com/alt",
            current_user=cast(User, cast(object, SimpleNamespace(roles=[SimpleNamespace(name="admin:update")]))),
            db=cast(Session, cast(object, db)),
        )

        db.refresh(credential)
        assert json.loads(credential.redirect_uris_json or "[]") == [
            "https://admin.example.com/callback",
            "https://admin.example.com/alt",
        ]
        assert result["redirect_uris"] == [
            "https://admin.example.com/callback",
            "https://admin.example.com/alt",
        ]
        assert fake_redis.get(f"oauth:redirect_uris:{client_id}") == json.dumps(
            ["https://admin.example.com/callback", "https://admin.example.com/alt"],
            ensure_ascii=False,
        )
    finally:
        db.query(AppCredential).filter(AppCredential.client_id == client_id).delete()
        db.commit()
        if app_id is not None:
            db.query(App).filter(App.id == app_id).delete(synchronize_session=False)
        if group_id is not None:
            db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_tenant_update_credential_config_persists_redirect_uris_to_database(monkeypatch) -> None:
    init_db()
    fake_redis = _FakeRedis()
    monkeypatch.setattr(redirect_store, "redis_client", fake_redis, raising=False)

    db = SessionLocal()
    client_id = f"tenant-edit-{uuid.uuid4().hex[:12]}"
    app_id: int | None = None
    group_id: int | None = None
    try:
        credential = _create_credential(db, client_id)
        app_id = credential.app_id
        group_id = credential.app.group_id if credential.app else None
        group = SimpleNamespace(id=credential.app.group_id, status="approved", is_active=True, expire_at=None)

        monkeypatch.setattr(tenant, "_get_tenant_group", lambda db, current_user: group)

        result = tenant.update_tenant_credential_config(
            client_id=client_id,
            scope="write",
            add_days=5,
            max_devices=4,
            redirect_uris="https://tenant.example.com/callback",
            current_user=cast(User, cast(object, SimpleNamespace(group_id=group.id, roles=[SimpleNamespace(name="tenant:credential:create")]))),
            db=cast(Session, cast(object, db)),
        )

        db.refresh(credential)
        assert json.loads(credential.redirect_uris_json or "[]") == ["https://tenant.example.com/callback"]
        assert result["redirect_uris"] == ["https://tenant.example.com/callback"]
        assert fake_redis.get(f"oauth:redirect_uris:{client_id}") == json.dumps(
            ["https://tenant.example.com/callback"],
            ensure_ascii=False,
        )
    finally:
        db.query(AppCredential).filter(AppCredential.client_id == client_id).delete()
        db.commit()
        if app_id is not None:
            db.query(App).filter(App.id == app_id).delete(synchronize_session=False)
        if group_id is not None:
            db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).delete(synchronize_session=False)
        db.commit()
        db.close()


