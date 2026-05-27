from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from database import AppCredential, User
from schemas.admin_schema import UserToggleStatusInput
from routers import admin, oauth


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
        self.committed = False

    def query(self, model):
        return _FakeQuery(self._result_map.get(model))

    def commit(self):
        self.committed = True


class _FakeRedis:
    def __init__(self):
        self.values: dict[str, object] = {}
        self.sets: dict[str, set[bytes]] = {}
        self.deleted: list[tuple[object, ...]] = []
        self.srem_calls: list[tuple[str, str]] = []
        self.scan_patterns: list[str] = []

    def get(self, key: str):
        return self.values.get(key)

    def setex(self, key: str, ttl: int, value):
        self.values[key] = value

    def delete(self, *keys):
        self.deleted.append(keys)
        for key in keys:
            norm_key = key.decode("utf-8") if isinstance(key, bytes) else key
            self.values.pop(norm_key, None)
            self.sets.pop(norm_key, None)

    def scan_iter(self, pattern: str):
        self.scan_patterns.append(pattern)
        prefix = pattern[:-1] if pattern.endswith("*") else pattern
        for key in list(self.values.keys()):
            if key.startswith(prefix):
                yield key.encode("utf-8")

    def smembers(self, key: str):
        return set(self.sets.get(key, set()))

    def srem(self, key: str, member: str):
        self.srem_calls.append((key, member))
        members = self.sets.get(key, set())
        members.discard(member.encode("utf-8"))
        members.discard(member if isinstance(member, bytes) else str(member).encode("utf-8"))
        self.sets[key] = members

    def expire(self, *args, **kwargs):
        return None


def test_toggle_user_status_revokes_sessions_by_user_id(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    fake_redis.sets["user:active_sessions:100"] = {b"sess_aaa", b"sess_bbb"}
    fake_redis.values["sess_aaa"] = b"100"
    fake_redis.values["sess_bbb"] = b"100"
    fake_redis.values["oauth_code:code_aaa"] = '{"client_id": "client_1", "user_id": 100, "username": "alice"}'
    fake_redis.values["oauth_userinfo:access_aaa"] = '{"user_id": 100, "username": "alice"}'
    fake_redis.values["oauth_userinfo:refresh_aaa"] = '{"user_id": 100, "username": "alice"}'
    monkeypatch.setattr(admin, "redis_client", fake_redis)
    monkeypatch.setattr(oauth, "redis_client", fake_redis)

    target_user = SimpleNamespace(id=100, username="alice", is_active=True)
    db = _FakeDB({User: target_user})

    result = admin.toggle_user_status(
        payload=UserToggleStatusInput(user_id=100, is_active=False),
        current_user=cast(User, cast(object, SimpleNamespace())),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert target_user.is_active is False
    deleted_flat = {
        item.decode("utf-8") if isinstance(item, bytes) else item
        for call in fake_redis.deleted
        for item in call
    }
    assert "sess_aaa" in deleted_flat
    assert "sess_bbb" in deleted_flat
    assert "user:active_sessions:100" in deleted_flat
    assert "oauth_code:code_aaa" in deleted_flat
    assert "oauth_userinfo:access_aaa" in deleted_flat
    assert "oauth_userinfo:refresh_aaa" in deleted_flat


def test_revoke_user_oauth_artifacts_cleans_only_matching_user(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    fake_redis.values["oauth_code:code_1"] = '{"client_id": "client_1", "user_id": 100, "username": "alice"}'
    fake_redis.values["oauth_code:code_2"] = '{"client_id": "client_1", "user_id": 200, "username": "bob"}'
    fake_redis.values["oauth_userinfo:token_1"] = '{"user_id": 100, "username": "alice"}'
    fake_redis.values["oauth_userinfo:token_2"] = '{"user_id": 200, "username": "bob"}'
    monkeypatch.setattr(oauth, "redis_client", fake_redis)

    result = oauth.revoke_user_oauth_artifacts(100, "alice")

    assert result == {"oauth_code": 1, "oauth_userinfo": 1}
    deleted_flat = {
        item.decode("utf-8") if isinstance(item, bytes) else item
        for call in fake_redis.deleted
        for item in call
    }
    assert "oauth_code:code_1" in deleted_flat
    assert "oauth_userinfo:token_1" in deleted_flat
    assert "oauth_code:code_2" not in deleted_flat
    assert "oauth_userinfo:token_2" not in deleted_flat


def test_oauth_authorize_blocks_inactive_session(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    fake_redis.values["sess_001"] = b"100"
    monkeypatch.setattr(oauth, "redis_client", fake_redis)
    monkeypatch.setattr(oauth, "_load_redirect_uri_whitelist", lambda client_id: ["http://localhost/callback"])

    app = SimpleNamespace(app_name="Demo App", app_logo=None, is_active=True, group=SimpleNamespace(group_name="Demo Group", is_active=True))
    cred = SimpleNamespace(is_active=True, app=app)
    inactive_user = SimpleNamespace(id=100, username="alice", is_active=False)
    db = _FakeDB({AppCredential: cred, User: inactive_user})

    captured: dict[str, object] = {}

    def _fake_template_response(*, request, name, context, status_code=None):
        captured["name"] = name
        captured["context"] = context
        captured["status_code"] = status_code
        return captured

    monkeypatch.setattr(oauth.templates, "TemplateResponse", _fake_template_response)

    response = oauth.oauth_authorize(
        request=cast(Request, cast(object, SimpleNamespace())),
        client_id="client_1",
        response_type="code",
        redirect_uri="http://localhost/callback",
        scope="read",
        state="",
        code_challenge="",
        code_challenge_method="",
        sso_session_id="sess_001",
        session_id="",
        db=cast(Session, cast(object, db)),
    )

    assert response["name"] == "oauth_error.html"
    assert "已被冻结" in str(response["context"]["detail"])
    deleted_flat = {
        item.decode("utf-8") if isinstance(item, bytes) else item
        for call in fake_redis.deleted
        for item in call
    }
    assert "sess_001" in deleted_flat


def test_oauth_token_exchange_rejects_disabled_user_for_authorization_code(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    fake_redis.values["oauth_code:auth_1"] = '{"client_id": "client_1", "redirect_uri": "http://localhost/callback", "scope": "read", "username": "alice", "user_id": 100, "response_type": "code", "code_challenge": null, "code_challenge_method": null}'
    monkeypatch.setattr(oauth, "redis_client", fake_redis)
    monkeypatch.setattr(oauth, "_ensure_redis_security_ready", lambda: None)
    monkeypatch.setattr(oauth, "verify_secret", lambda secret, stored_hash: True)

    app = SimpleNamespace(app_name="Demo App", app_logo=None, is_active=True, group=SimpleNamespace(group_name="Demo Group", is_active=True))
    cred = SimpleNamespace(client_secret_hash="hash", scope="read", expire_at=None, is_active=True, app=app)
    inactive_user = SimpleNamespace(id=100, username="alice", is_active=False)
    db = _FakeDB({AppCredential: cred, User: inactive_user})

    with pytest.raises(HTTPException) as exc_info:
        oauth.oauth_token_exchange(
            grant_type="authorization_code",
            client_id="client_1",
            client_secret="secret_1",
            authorization="",
            code="auth_1",
            code_verifier="",
            refresh_token="",
            db=cast(Session, cast(object, db)),
        )

    assert exc_info.value.status_code == 403
    assert "已被冻结" in str(exc_info.value.detail)


def test_oauth_token_exchange_rejects_disabled_user_for_refresh_token(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    fake_redis.values["oauth_userinfo:refresh_1"] = '{"username": "alice", "user_id": 100}'
    monkeypatch.setattr(oauth, "redis_client", fake_redis)
    monkeypatch.setattr(oauth, "_ensure_redis_security_ready", lambda: None)
    monkeypatch.setattr(oauth, "verify_secret", lambda secret, stored_hash: True)
    monkeypatch.setattr(oauth.jwt, "decode", lambda token, secret, algorithms: {"token_type": "refresh_token", "sub": "client_1", "scope": "read"})

    app = SimpleNamespace(app_name="Demo App", app_logo=None, is_active=True, group=SimpleNamespace(group_name="Demo Group", is_active=True))
    cred = SimpleNamespace(client_secret_hash="hash", scope="read", expire_at=None, is_active=True, app=app)
    inactive_user = SimpleNamespace(id=100, username="alice", is_active=False)
    db = _FakeDB({AppCredential: cred, User: inactive_user})

    with pytest.raises(HTTPException) as exc_info:
        oauth.oauth_token_exchange(
            grant_type="refresh_token",
            client_id="client_1",
            client_secret="secret_1",
            authorization="",
            code="",
            code_verifier="",
            refresh_token="refresh_1",
            db=cast(Session, cast(object, db)),
        )

    assert exc_info.value.status_code == 403
    assert "已被冻结" in str(exc_info.value.detail)


