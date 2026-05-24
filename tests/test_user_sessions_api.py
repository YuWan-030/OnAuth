from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from sqlalchemy.orm import Session
from fastapi import Request

from database import User
from routers import auth_user


class _FakeRedis:
    def __init__(self) -> None:
        self.user_sessions = {7: {"sess_current", "sess_other", "sess_third"}}
        self.meta = {
            "sess_current": {b"ip": b"127.0.0.1", b"browser": b"Chrome", b"os": b"Windows", b"location": b"Local", b"login_time": b"2026-05-24 10:00:00"},
            "sess_other": {b"ip": b"10.0.0.8", b"browser": b"Firefox", b"os": b"Linux", b"location": b"Office", b"login_time": b"2026-05-23 09:00:00"},
            "sess_third": {b"ip": b"10.0.0.9", b"browser": b"Chrome", b"os": b"macOS", b"location": b"Lab", b"login_time": b"2026-05-22 09:00:00"},
        }
        self.deleted: list[str] = []
        self.srem_calls: list[tuple[str, str]] = []

    def smembers(self, key: str):
        if key == "user:active_sessions:7":
            return {item.encode("utf-8") for item in self.user_sessions[7]}
        return set()

    def hgetall(self, key: str):
        token = key.split(":", 1)[1]
        return self.meta.get(token, {})

    def sismember(self, key: str, token_id: str):
        return token_id in self.user_sessions.get(7, set())

    def delete(self, key: str):
        self.deleted.append(key)

    def srem(self, key: str, token_id: str):
        self.srem_calls.append((key, token_id))
        self.user_sessions.setdefault(7, set()).discard(token_id)


class _FakeRequest:
    def __init__(self, token: str):
        self.cookies = {"sso_session_id": token}
        self.headers = {}


def test_app_factory_imports_without_user_router_dependency() -> None:
    import app_factory

    paths = {route.path for route in app_factory.app.routes}
    assert "/api/v1/user/sessions" in paths
    assert "/api/v1/user/sessions/revoke" in paths


def test_list_my_sessions_returns_current_session_first(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(auth_user, "redis_client", fake_redis)

    result = auth_user.list_my_sessions(
        request=cast(Request, cast(object, _FakeRequest("sess_current"))),
        current_user=cast(User, cast(object, SimpleNamespace(id=7, username="alice", roles=[]))),
        db=cast(Session, cast(object, SimpleNamespace())),
    )

    assert result["status"] == "success"
    assert result["count"] == 3
    assert result["data"][0]["token_id"] == "sess_current"
    assert result["data"][0]["is_current"] is True
    assert result["data"][1]["token_id"] == "sess_other"


def test_list_my_sessions_supports_browser_and_device_filters(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(auth_user, "redis_client", fake_redis)

    result = auth_user.list_my_sessions(
        request=cast(Request, cast(object, _FakeRequest("sess_current"))),
        browser="Chrome",
        device="macOS",
        current_user=cast(User, cast(object, SimpleNamespace(id=7, username="alice", roles=[]))),
        db=cast(Session, cast(object, SimpleNamespace())),
    )

    assert result["status"] == "success"
    assert result["count"] == 1
    assert result["data"][0]["token_id"] == "sess_third"


def test_revoke_my_sessions_batch_revokes_only_selected_tokens(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(auth_user, "redis_client", fake_redis)

    result = auth_user.revoke_my_sessions_batch(
        payload=auth_user.SessionBatchRevokeInput(token_ids=["sess_other", "sess_third"]),
        request=cast(Request, cast(object, _FakeRequest("sess_current"))),
        current_user=cast(User, cast(object, SimpleNamespace(id=7, username="alice", roles=[]))),
        db=cast(Session, cast(object, SimpleNamespace())),
    )

    assert result["status"] == "success"
    assert result["count"] == 2
    assert ("user:active_sessions:7", "sess_other") in fake_redis.srem_calls
    assert ("user:active_sessions:7", "sess_third") in fake_redis.srem_calls
    assert "sess_other" in fake_redis.deleted
    assert "sess_third" in fake_redis.deleted


def test_revoke_my_sessions_all_keeps_current_when_requested(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(auth_user, "redis_client", fake_redis)

    result = auth_user.revoke_my_sessions_all(
        payload=auth_user.SessionRevokeAllInput(keep_current=True),
        request=cast(Request, cast(object, _FakeRequest("sess_current"))),
        current_user=cast(User, cast(object, SimpleNamespace(id=7, username="alice", roles=[]))),
        db=cast(Session, cast(object, SimpleNamespace())),
    )

    assert result["status"] == "success"
    assert result["count"] == 2
    assert result["kept_current"] is True
    assert ("user:active_sessions:7", "sess_current") not in fake_redis.srem_calls
    assert "sess_current" not in fake_redis.deleted
    assert "sess_other" in fake_redis.deleted
    assert "sess_third" in fake_redis.deleted


def test_revoke_my_session_blocks_other_users(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(auth_user, "redis_client", fake_redis)

    result = auth_user.revoke_my_session(
        payload=auth_user.SessionRevokeInput(token_id="sess_other"),
        request=cast(Request, cast(object, _FakeRequest("sess_current"))),
        current_user=cast(User, cast(object, SimpleNamespace(id=7, username="alice", roles=[]))),
        db=cast(Session, cast(object, SimpleNamespace())),
    )

    assert result["status"] == "success"
    assert result["is_current"] is False
    assert ("user:active_sessions:7", "sess_other") in fake_redis.srem_calls
    assert "sess_other" in fake_redis.deleted


