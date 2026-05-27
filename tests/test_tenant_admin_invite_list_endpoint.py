from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from database import User
from routers import auth_user


def test_list_tenant_admin_invite_codes_uses_independent_reader_session(monkeypatch) -> None:
    sample = [{"invite_code": "CODE1", "status": "active"}]
    monkeypatch.setattr(auth_user, "_tenant_admin_invite_list", lambda limit: sample)

    current_user = SimpleNamespace(username="super_root", roles=[SimpleNamespace(name="super_admin")])
    result = auth_user.list_tenant_admin_invite_codes(
        limit=50,
        db=cast(Any, object()),
        current_user=cast(User, cast(object, current_user)),
    )

    assert result["status"] == "success"
    assert result["data"] == sample

