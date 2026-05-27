from __future__ import annotations
from typing import Any, cast
from sqlalchemy import text
from database import SessionLocal
from routers import invite_admin
class _FakeRole:
    def __init__(self, name: str):
        self.name = name
class _FakeUser:
    def __init__(self, username: str, roles: list[_FakeRole]):
        self.username = username
        self.roles = roles
class _FakeRedis:
    def setex(self, *args, **kwargs):
        return None
    def delete(self, *args, **kwargs):
        return None
def test_issue_tenant_admin_invite_code_persists_to_database(monkeypatch) -> None:
    fake_redis = _FakeRedis()
    monkeypatch.setattr(invite_admin, 'redis_client', fake_redis, raising=False)
    db = SessionLocal()
    try:
        before_count = db.execute(text('SELECT COUNT(*) FROM tenant_admin_invite_records')).scalar_one()
        result = invite_admin.issue_tenant_admin_invite_code(
            db=db,
            current_user=cast(Any, _FakeUser('root', [_FakeRole('super_admin')]))
        )
        after_count = db.execute(text('SELECT COUNT(*) FROM tenant_admin_invite_records')).scalar_one()
    finally:
        db.close()
    assert result['status'] == 'success'
    assert after_count == before_count + 1
    assert result['data']['invite_code']
