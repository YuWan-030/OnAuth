from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from fastapi import BackgroundTasks, Request, Response
from sqlalchemy.orm import Session

from routers import auth_user, oauth


class _FakeQuery:
    def __init__(self, obj: Any):
        self._obj = obj

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._obj


class _FakeDB:
    def __init__(self, user: Any):
        self._user = user

    def query(self, model):
        return _FakeQuery(self._user)


class _FakeRedis:
    def __init__(self) -> None:
        self.setex_calls: list[tuple[str, int, Any]] = []
        self.expire_calls: list[tuple[str, int]] = []
        self.hset_calls: list[tuple[str, dict[str, Any]]] = []
        self.sadd_calls: list[tuple[str, str]] = []

    def setex(self, key: str, ttl: int, value: Any):
        self.setex_calls.append((key, ttl, value))

    def expire(self, key: str, ttl: int):
        self.expire_calls.append((key, ttl))

    def hset(self, key: str, mapping: dict[str, Any]):
        self.hset_calls.append((key, dict(mapping)))

    def sadd(self, key: str, token_id: str):
        self.sadd_calls.append((key, token_id))

    def get(self, key: str):
        return None


class _FakeResponse:
    def __init__(self) -> None:
        self.cookies: list[dict[str, Any]] = []

    def set_cookie(self, **kwargs):
        self.cookies.append(kwargs)


class _FakeBackgroundTasks:
    def __init__(self) -> None:
        self.tasks: list[tuple[Any, tuple[Any, ...], dict[str, Any]]] = []

    def add_task(self, func, *args, **kwargs):
        self.tasks.append((func, args, kwargs))


class _FakeRequest:
    def __init__(self, path: str = "/auth/login"):
        self.url = SimpleNamespace(path=path)
        self.headers = {"User-Agent": "pytest"}
        self.cookies = {}


def test_auth_login_sets_one_day_cookie_and_redis_ttl(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    fake_response = _FakeResponse()
    fake_background = _FakeBackgroundTasks()
    fake_user = SimpleNamespace(
        id=7,
        username="alice",
        password_hash="hash",
        is_active=True,
        roles=[SimpleNamespace(permissions=[SimpleNamespace(name="read")])],
    )
    fake_db = _FakeDB(fake_user)

    monkeypatch.setattr(auth_user, "redis_client", fake_redis)
    monkeypatch.setattr(auth_user, "_is_global_melt_enabled", lambda db: False)
    monkeypatch.setattr(auth_user, "_is_account_locked", lambda username: False)
    monkeypatch.setattr(auth_user, "_get_login_fail_count", lambda username, client_ip: 0)
    monkeypatch.setattr(auth_user, "_get_login_fail_policy", lambda db, request, username, fail_count: (3, 600))
    monkeypatch.setattr(auth_user, "verify_captcha", lambda *args, **kwargs: True)
    monkeypatch.setattr(auth_user, "_record_risk_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(auth_user.pwd_context, "verify", lambda raw, hashed: True)
    monkeypatch.setattr(auth_user, "_clear_login_fail", lambda username, client_ip: None)
    monkeypatch.setattr(auth_user, "_clear_account_lock", lambda username: None)
    monkeypatch.setattr(auth_user, "_extract_client_meta", lambda request, include_location=False: ("127.0.0.1", "UA", False, "Chrome", "Windows", ""))
    monkeypatch.setattr(auth_user, "dispatch_webhook_event", lambda **kwargs: None)

    result = auth_user.login_user(
        payload=auth_user.UserLoginSchema(username="alice", password="secret", captcha_token="", captcha_code=""),
        request=cast(Request, cast(Any, _FakeRequest())),
        background_tasks=cast(BackgroundTasks, cast(Any, fake_background)),
        response=cast(Response, cast(Any, fake_response)),
        db=cast(Session, cast(object, fake_db)),
    )

    assert result["status"] == "success"
    assert fake_redis.setex_calls[0][1] == 86400
    assert ("user:active_sessions:7", 86400) in fake_redis.expire_calls
    assert fake_response.cookies[0]["max_age"] == 86400
    assert fake_response.cookies[0]["httponly"] is True
    assert fake_response.cookies[0]["path"] == "/"


def test_oauth_login_submit_sets_one_day_cookie_and_redis_ttl(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    fake_response = _FakeResponse()
    fake_background = _FakeBackgroundTasks()
    fake_user = SimpleNamespace(
        id=7,
        username="alice",
        password_hash="hash",
        is_active=True,
        roles=[SimpleNamespace(permissions=[SimpleNamespace(name="read")])],
    )
    fake_db = _FakeDB(fake_user)

    monkeypatch.setattr(oauth, "redis_client", fake_redis)
    monkeypatch.setattr(oauth, "_is_global_melt_enabled", lambda db: False)
    monkeypatch.setattr(oauth, "_get_login_fail_count", lambda username, client_ip: 0)
    monkeypatch.setattr(oauth, "_get_login_fail_policy", lambda db, request, username, fail_count: (3, 600))
    monkeypatch.setattr(oauth, "verify_captcha", lambda *args, **kwargs: True)
    monkeypatch.setattr(oauth, "_record_risk_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(oauth, "verify_password", lambda raw, hashed: True)
    monkeypatch.setattr(oauth, "_clear_login_fail", lambda username, client_ip: None)
    monkeypatch.setattr(oauth, "_extract_client_meta", lambda request, include_location=False: ("127.0.0.1", "UA", False, "Chrome", "Windows", ""))
    monkeypatch.setattr(oauth, "dispatch_webhook_event", lambda **kwargs: None)

    result = oauth.login_submit(
        response=cast(Response, cast(Any, fake_response)),
        request=cast(Request, cast(Any, _FakeRequest(path="/oauth/login_submit"))),
        background_tasks=cast(BackgroundTasks, cast(Any, fake_background)),
        username="alice",
        password="secret",
        client_id="client-001",
        redirect_uri="https://app.example.com/callback",
        scope="read",
        state="",
        code_challenge="",
        code_challenge_method="",
        captcha_token="",
        captcha_code="",
        db=cast(Session, cast(object, fake_db)),
    )

    assert result["status"] == "success"
    assert fake_redis.setex_calls[0][1] == 86400
    assert ("user:active_sessions:7", 86400) in fake_redis.expire_calls
    assert fake_response.cookies[0]["max_age"] == 86400
    assert fake_response.cookies[0]["httponly"] is True
    assert fake_response.cookies[0]["path"] == "/"



