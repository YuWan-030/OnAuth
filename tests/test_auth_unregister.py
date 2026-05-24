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
    def __init__(self) -> None:
        self.values = {"sess_current": b"alice"}
        self.session_set = {b"sess_current", b"sess_other"}
        self.deleted: list[str] = []
        self.srem_calls: list[tuple[str, str]] = []

    def get(self, key: str):
        return self.values.get(key)

    def smembers(self, key: str):
        if key == "user:active_sessions:7":
            return set(self.session_set)
        return set()

    def delete(self, key: str):
        self.deleted.append(key)

    def srem(self, key: str, token_id: str):
        self.srem_calls.append((key, token_id))
        self.session_set.discard(token_id.encode("utf-8"))


class _FakeResponse:
    def __init__(self) -> None:
        self.deleted_cookies: list[dict[str, object]] = []

    def delete_cookie(self, **kwargs):
        self.deleted_cookies.append(kwargs)


def test_delete_account_purges_all_user_sessions_and_rbac_cache(monkeypatch) -> None:
    user = SimpleNamespace(id=7, username="alice", password_hash="hashed")
    fake_db = _FakeDB(user)
    fake_redis = _FakeRedis()
    fake_response = _FakeResponse()
    dispatched: list[dict[str, object]] = []

    monkeypatch.setattr(auth_user, "redis_client", fake_redis)
    monkeypatch.setattr(auth_user.pwd_context, "verify", lambda confirm_password, password_hash: confirm_password == "correct-password")
    monkeypatch.setattr(auth_user, "dispatch_webhook_event", lambda **kwargs: dispatched.append(kwargs))

    result = auth_user.delete_account(
        response=cast(Response, cast(object, fake_response)),
        confirm_password="correct-password",
        authorization=None,
        sso_session_id_cookie="sess_current",
        sso_session_id_form=None,
        db=cast(Session, cast(object, fake_db)),
    )

    assert result["status"] == "success"
    assert fake_db.deleted is user
    assert fake_db.committed is True
    assert "sess_current" in fake_redis.deleted
    assert "sess_other" in fake_redis.deleted
    assert "sess_meta:sess_current" in fake_redis.deleted
    assert "sess_meta:sess_other" in fake_redis.deleted
    assert "rbac:perms:sess_current" in fake_redis.deleted
    assert "rbac:perms:sess_other" in fake_redis.deleted
    assert ("user:active_sessions:7", "sess_current") in fake_redis.srem_calls
    assert ("user:active_sessions:7", "sess_other") in fake_redis.srem_calls
    assert fake_response.deleted_cookies and fake_response.deleted_cookies[0]["key"] == "sso_session_id"
    payload = cast(dict[str, object], dispatched[0]["payload"])
    assert dispatched and payload["user_id"] == 7



