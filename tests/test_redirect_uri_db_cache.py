from __future__ import annotations

import datetime
import json
import uuid
from typing import cast

from sqlalchemy.orm import Session

from database import App, AppCredential, DeveloperGroup, SessionLocal, init_db
from routers import oauth
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


def _make_credential(db, client_id: str) -> AppCredential:
    suffix = uuid.uuid4().hex[:8]
    group = DeveloperGroup(
        group_name=f"redirect-test-group-{suffix}",
        group_code=f"tg{suffix}",
        owner="tester",
        is_active=True,
        status="approved",
    )
    db.add(group)
    db.flush()

    app = App(
        group_id=group.id,
        app_name=f"redirect-test-app-{suffix}",
        owner="tester",
        is_active=True,
    )
    db.add(app)
    db.flush()

    credential = AppCredential(
        app_id=app.id,
        credential_name=f"redirect-test-credential-{suffix}",
        client_id=client_id,
        client_secret_hash=hash_secret("secret123"),
        scope="read",
        max_devices=1,
        expire_at=datetime.datetime.now() + datetime.timedelta(days=30),
    )
    db.add(credential)
    db.flush()
    return credential


def test_redirect_uri_whitelist_persists_to_database_and_refreshes_cache(monkeypatch) -> None:
    init_db()
    fake_redis = _FakeRedis()
    monkeypatch.setattr(redirect_store, "redis_client", fake_redis, raising=False)

    db = SessionLocal()
    client_id = f"client-{uuid.uuid4().hex[:12]}"
    app_id: int | None = None
    group_id: int | None = None
    try:
        credential = _make_credential(db, client_id)
        app_id = credential.app_id
        group_id = credential.app.group_id if credential.app else None
        redirect_uris = ["https://app.example.com/callback", "http://localhost/callback"]

        saved_values = redirect_store.set_redirect_uri_whitelist(credential, redirect_uris)
        db.commit()

        fresh = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
        assert fresh is not None
        assert json.loads(fresh.redirect_uris_json or "[]") == redirect_uris
        assert saved_values == redirect_uris
        assert fake_redis.get(f"oauth:redirect_uris:{client_id}") == json.dumps(redirect_uris, ensure_ascii=False)

        fake_redis.delete(f"oauth:redirect_uris:{client_id}")
        loaded_values = redirect_store.load_redirect_uri_whitelist(db, client_id)
        assert loaded_values == redirect_uris
        assert fake_redis.get(f"oauth:redirect_uris:{client_id}") == json.dumps(redirect_uris, ensure_ascii=False)
    finally:
        db.query(AppCredential).filter(AppCredential.client_id == client_id).delete()
        db.commit()
        if app_id is not None:
            db.query(App).filter(App.id == app_id).delete(synchronize_session=False)
        if group_id is not None:
            db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_redirect_uri_whitelist_falls_back_to_legacy_redis_cache(monkeypatch) -> None:
    init_db()
    fake_redis = _FakeRedis()
    monkeypatch.setattr(redirect_store, "redis_client", fake_redis, raising=False)

    db = SessionLocal()
    client_id = f"legacy-{uuid.uuid4().hex[:12]}"
    app_id: int | None = None
    group_id: int | None = None
    try:
        credential = _make_credential(db, client_id)
        app_id = credential.app_id
        group_id = credential.app.group_id if credential.app else None
        db.commit()

        legacy_values = ["https://legacy.example.com/callback"]
        fake_redis.set(f"oauth:redirect_uris:{client_id}", json.dumps(legacy_values, ensure_ascii=False))

        loaded_values = redirect_store.load_redirect_uri_whitelist(db, client_id)
        assert loaded_values == legacy_values
    finally:
        db.query(AppCredential).filter(AppCredential.client_id == client_id).delete()
        db.commit()
        if app_id is not None:
            db.query(App).filter(App.id == app_id).delete(synchronize_session=False)
        if group_id is not None:
            db.query(DeveloperGroup).filter(DeveloperGroup.id == group_id).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_oauth_redirect_uri_whitelist_prefers_redis_cache(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(oauth, "redis_client", fake_redis, raising=False)

    cached_values = ["https://redis.example.com/callback"]
    fake_redis.set("oauth:redirect_uris:client-cache", json.dumps(cached_values, ensure_ascii=False))

    class _ExplodingDB:
        def query(self, *_args, **_kwargs):
            raise AssertionError("database should not be queried when redis cache exists")

    whitelist = oauth._load_redirect_uri_whitelist("client-cache", cast(Session, cast(object, _ExplodingDB())))
    assert whitelist == set(cached_values)


