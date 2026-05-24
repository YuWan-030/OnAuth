from __future__ import annotations

import datetime
from types import SimpleNamespace
from typing import cast

from sqlalchemy.orm import Session

from database import User
from routers import admin


class _DeviceQuery:
    def __init__(self, rows):
        self._rows = rows

    def join(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def offset(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def all(self):
        return list(self._rows)

    def count(self):
        return len(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _AppQuery:
    def __init__(self, app):
        self._app = app

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._app


class _FakeDB:
    def __init__(self, app, devices):
        self.app = app
        self.devices = list(devices)
        self.committed = False

    def query(self, model):
        if model.__name__ == "App":
            return _AppQuery(self.app)
        if model.__name__ == "AppDevice":
            return _DeviceQuery(self.devices)
        raise AssertionError(f"unexpected model: {model}")

    def commit(self):
        self.committed = True


def test_list_admin_app_devices_returns_device_rows() -> None:
    app = SimpleNamespace(id=7, app_name="App A")
    credential = SimpleNamespace(id=11, credential_name="Prod Cred", client_id="cli_001")
    devices = [
        SimpleNamespace(
            id=1,
            device_id="dev-1",
            credential_id=11,
            credential=credential,
            is_revoked=False,
            revoked_at=None,
            revoke_reason=None,
            expires_at=datetime.datetime(2026, 6, 1, 12, 0, 0),
            last_seen_at=datetime.datetime(2026, 5, 24, 9, 0, 0),
            activated_at=datetime.datetime(2026, 5, 20, 9, 0, 0),
        )
    ]
    db = _FakeDB(app, devices)
    current_user = SimpleNamespace(roles=[SimpleNamespace(name="admin:read")])

    result = admin.list_admin_app_devices(
        app_id=7,
        page=1,
        limit=20,
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert result["count"] == 1
    row = result["data"][0]
    assert row["device_id"] == "dev-1"
    assert row["credential_name"] == "Prod Cred"
    assert row["client_id"] == "cli_001"


def test_unbind_admin_app_device_marks_device_revoked() -> None:
    app = SimpleNamespace(id=7, app_name="App A")
    credential = SimpleNamespace(id=11, credential_name="Prod Cred", client_id="cli_001")
    target = SimpleNamespace(
        id=1,
        device_id="dev-1",
        credential_id=11,
        credential=credential,
        is_revoked=False,
        revoked_at=None,
        revoke_reason=None,
        expires_at=None,
        last_seen_at=None,
        activated_at=None,
    )
    db = _FakeDB(app, [target])
    current_user = SimpleNamespace(roles=[SimpleNamespace(name="admin:update")])

    result = admin.unbind_admin_app_device(
        app_id=7,
        device_id="dev-1",
        current_user=cast(User, cast(object, current_user)),
        db=cast(Session, cast(object, db)),
    )

    assert result["status"] == "success"
    assert result["device_id"] == "dev-1"
    assert target.is_revoked is True
    assert target.revoke_reason == "admin_unbind"
    assert db.committed is True

