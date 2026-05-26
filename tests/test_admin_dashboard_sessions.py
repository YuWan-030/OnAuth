from __future__ import annotations

from routers import admin


class _FakeRedis:
    def __init__(self) -> None:
        self.index_keys = [b"user:active_sessions:1", b"user:active_sessions:2"]
        self.set_members = {
            "user:active_sessions:1": {b"sess_user_1", b"sess_non_user", b"sess_dup"},
            "user:active_sessions:2": {b"sess_user_2", b"sess_dup", b"sess_bad_type", b"sess_bad_value"},
        }
        self.types = {
            "sess_user_1": b"string",
            "sess_user_2": b"string",
            "sess_non_user": b"string",
            "sess_dup": b"string",
            "sess_bad_type": b"hash",
            "sess_bad_value": b"string",
        }
        self.values = {
            "sess_user_1": b"1",
            "sess_user_2": b"2",
            "sess_non_user": b"oauth:pending",
            "sess_dup": b"1",
            "sess_bad_value": b"not-an-int",
        }

    def scan_iter(self, pattern: str):
        assert pattern == "user:active_sessions:*"
        return iter(self.index_keys)

    def smembers(self, key: str):
        return self.set_members.get(key, set())

    def type(self, key: str):
        return self.types.get(key, b"none")

    def get(self, key: str):
        return self.values.get(key)


def test_count_active_user_sessions_filters_non_user_and_invalid(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(admin, "redis_client", fake_redis)

    # valid: sess_user_1, sess_user_2, sess_dup(only counted once)
    assert admin._count_active_user_sessions() == 3

