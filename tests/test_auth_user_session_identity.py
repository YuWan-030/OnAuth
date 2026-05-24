from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from fastapi import Response
from sqlalchemy.orm import Session

from routers import auth_user


class _FakeQuery:
    def __init__(self, user):
        self._user = user

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._user


class _FakeDB:
    def __init__(self, user):
        self._user = user
        self.deleted = None
        self.committed = False

    def query(self, model):
        return _FakeQuery(self._user)

    def delete(self, obj):
        self.deleted = obj

    def commit(self):
        self.committed = True


class _FakeRedis:
    def __init__(self, token_value: bytes = b"1"):
        self.token_value = token_value
        self.deleted: list[str] = []
        self.srem_calls: list[tuple[str, str]] = []

    def get(self, key: str):
        return self.token_value

    def delete(self, key: str):
        self.deleted.append(key)

    def srem(self, key: str, token_id: str):
        self.srem_calls.append((key, token_id))

    def smembers(self, key: str):
        return {b"sess_other"}


class _FakeResponse:
    def __init__(self) -> None:
        self.deleted_cookies: list[dict[str, object]] = []

    def delete_cookie(self, **kwargs):
        self.deleted_cookies.append(kwargs)


def test_change_password_resolves_numeric_user_id_from_session(monkeypatch) -> None:
    user = SimpleNamespace(id=1, username="admin", password_hash="old-hash")
    fake_db = _FakeDB(user)
    fake_redis = _FakeRedis(token_value=b"1")

    monkeypatch.setattr(auth_user, "redis_client", fake_redis)
    monkeypatch.setattr(auth_user.pwd_context, "verify", lambda raw, hashed: raw == "admin@123")
    monkeypatch.setattr(auth_user.pwd_context, "hash", lambda value: f"hashed:{value}")

    result = auth_user.change_password(
        current_password="admin@123",
        new_password="Wzt52052..",
        authorization="",
        sso_session_id_cookie="sess_5ebaeab3767325b4f19fddb6",
        db=cast(Session, cast(object, fake_db)),
    )

    assert result["status"] == "success"
    assert user.password_hash == "hashed:TestAa123.."
    assert fake_db.committed is True


def test_delete_account_resolves_numeric_user_id_from_session(monkeypatch) -> None:
    user = SimpleNamespace(id=1, username="admin", password_hash="old-hash")
    fake_db = _FakeDB(user)
    fake_redis = _FakeRedis(token_value=b"1")
    fake_response = _FakeResponse()
    dispatched: list[dict[str, object]] = []

    monkeypatch.setattr(auth_user, "redis_client", fake_redis)
    monkeypatch.setattr(auth_user.pwd_context, "verify", lambda raw, hashed: raw == "admin@123")
    monkeypatch.setattr(auth_user, "dispatch_webhook_event", lambda **kwargs: dispatched.append(kwargs))

    result = auth_user.delete_account(
        response=cast(Response, cast(object, fake_response)),
        confirm_password="admin@123",
        authorization="",
        sso_session_id_cookie="sess_5ebaeab3767325b4f19fddb6",
        sso_session_id_form="",
        db=cast(Session, cast(object, fake_db)),
    )

    assert result["status"] == "success"
    assert fake_db.deleted is user
    assert fake_db.committed is True
    payload = cast(dict[str, object], dispatched[0]["payload"])
    assert dispatched and payload["user_id"] == 1
    assert fake_response.deleted_cookies and fake_response.deleted_cookies[0]["key"] == "sso_session_id"

