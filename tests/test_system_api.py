from __future__ import annotations

from types import SimpleNamespace

from routers import system_api


class _FakeRedis:
    def __init__(self) -> None:
        self.keys = [b"sess_ok", b"sess_meta:sess_ok", b"sess_other"]
        self.types = {
            "sess_ok": b"string",
            "sess_meta:sess_ok": b"hash",
            "sess_other": b"string",
        }
        self.values = {
            "sess_ok": b"101",
            "sess_other": b"202",
        }
        self.deleted: list[str] = []
        self.srem_calls: list[tuple[str, str]] = []
        self.get_calls: list[str] = []

    def scan_iter(self, pattern: str):
        assert pattern == "sess_*"
        return iter(self.keys)

    def type(self, key: str):
        return self.types[key]

    def get(self, key: str):
        self.get_calls.append(key)
        return self.values[key]

    def srem(self, key: str, token_id: str):
        self.srem_calls.append((key, token_id))

    def delete(self, key: str):
        self.deleted.append(key)


def test_load_session_user_id_skips_hash_keys(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(system_api, "redis_client", fake)

    assert system_api._load_session_user_id("sess_ok") == 101
    assert system_api._load_session_user_id("sess_meta:sess_ok") is None
    assert fake.get_calls == ["sess_ok"]


def test_revoke_online_sessions_all_ignores_session_meta_hash(monkeypatch) -> None:
    fake = _FakeRedis()
    monkeypatch.setattr(system_api, "redis_client", fake)

    result = system_api.revoke_online_sessions_all(
        payload=SimpleNamespace(keep_current=False, reason=None),
        sso_session_id=None,
        current_user=SimpleNamespace(),
        db=SimpleNamespace(),
    )

    assert result["code"] == 200
    assert result["count"] == 2
    assert fake.get_calls == ["sess_ok", "sess_other"]
    assert ("user:active_sessions:101", "sess_ok") in fake.srem_calls
    assert ("user:active_sessions:202", "sess_other") in fake.srem_calls
    assert "sess_meta:sess_ok" in fake.deleted


def test_build_announcement_feed_payload_splits_broadcast_and_notices() -> None:
    items = [
        SimpleNamespace(
            id=10,
            title="系统维护",
            content="今晚 22:00 维护",
            type="bulletin",
            is_pinned=True,
            created_at=None,
        ),
        SimpleNamespace(
            id=11,
            title="常规通知A",
            content="内容A",
            type="notice",
            is_pinned=False,
            created_at=None,
        ),
        SimpleNamespace(
            id=12,
            title="常规通知B",
            content="内容B",
            type="notice",
            is_pinned=False,
            created_at=None,
        ),
    ]

    payload = system_api._build_announcement_feed_payload(items, notice_limit=2)

    assert payload["broadcast"]["id"] == 10
    assert len(payload["notices"]) == 2
    assert payload["notices"][0]["id"] == 11


def test_build_announcement_feed_payload_without_bulletin() -> None:
    items = [
        SimpleNamespace(
            id=21,
            title="通知1",
            content="正文1",
            type="notice",
            is_pinned=False,
            created_at=None,
        )
    ]

    payload = system_api._build_announcement_feed_payload(items, notice_limit=3)

    assert payload["broadcast"] is None
    assert len(payload["notices"]) == 1
    assert payload["notices"][0]["id"] == 21


