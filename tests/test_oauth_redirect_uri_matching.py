from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from sqlalchemy.orm import Session
from starlette.requests import Request

from database import App, AppCredential, User
from routers import oauth
from routers.oauth import _redirect_uri_matches_whitelist_entry


def test_localhost_whitelist_without_port_matches_any_local_port() -> None:
    assert _redirect_uri_matches_whitelist_entry(
        "http://localhost:3000/callback",
        "http://localhost/callback",
    ) is True
    assert _redirect_uri_matches_whitelist_entry(
        "http://127.0.0.1:54321/callback",
        "http://127.0.0.1/callback",
    ) is True


def test_explicit_port_still_requires_exact_match() -> None:
    assert _redirect_uri_matches_whitelist_entry(
        "http://localhost:3000/callback",
        "http://localhost:3000/callback",
    ) is True
    assert _redirect_uri_matches_whitelist_entry(
        "http://localhost:3001/callback",
        "http://localhost:3000/callback",
    ) is False


def test_host_and_path_must_still_match() -> None:
    assert _redirect_uri_matches_whitelist_entry(
        "http://localhost:3000/other",
        "http://localhost/callback",
    ) is False
    assert _redirect_uri_matches_whitelist_entry(
        "http://evil.example.com/callback",
        "http://localhost/callback",
    ) is False


class _FakeQuery:
    def __init__(self, obj) -> None:
        self._obj = obj

    def join(self, *_args, **_kwargs):
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        return self._obj


class _FakeDB:
    def __init__(self, cred) -> None:
        self._cred = cred

    def query(self, model):
        if model is AppCredential:
            return _FakeQuery(self._cred)
        if model is App:
            return _FakeQuery(self._cred)
        raise AssertionError(f"unexpected model: {model!r}")


def test_consent_submit_passes_db_into_redirect_uri_validation(monkeypatch) -> None:
    cred = SimpleNamespace(app=SimpleNamespace(app_name="Demo App"))
    fake_db = _FakeDB(cred)

    captured: dict[str, object] = {}

    monkeypatch.setattr(oauth, "_validate_state", lambda state: state)

    def _fake_validate_redirect_uri(client_id, redirect_uri, db):
        captured["client_id"] = client_id
        captured["redirect_uri"] = redirect_uri
        captured["db"] = db
        return redirect_uri

    monkeypatch.setattr(oauth, "_validate_redirect_uri", _fake_validate_redirect_uri)
    monkeypatch.setattr(oauth, "_resolve_active_session_user", lambda session_id, db: (None, None, "会话已冻结"))

    def _fake_template_response(*, request, name, context, status_code=None):
        captured["template_name"] = name
        captured["template_context"] = context
        captured["status_code"] = status_code
        return captured

    monkeypatch.setattr(oauth.templates, "TemplateResponse", _fake_template_response)

    response = oauth.consent_submit(
        request=cast(Request, cast(object, SimpleNamespace())),
        action="allow",
        client_id="client_1",
        redirect_uri="https://example.com/callback",
        scope="read",
        state="state_1234",
        code_challenge="",
        code_challenge_method="",
        session_id="sess_001",
        db=cast(Session, cast(object, fake_db)),
    )

    assert captured["client_id"] == "client_1"
    assert captured["redirect_uri"] == "https://example.com/callback"
    assert captured["db"] is fake_db
    assert response["template_name"] == "oauth_error.html"
    assert response["status_code"] == 403


def test_validate_redirect_uri_requires_switch_for_non_local_http(monkeypatch) -> None:
    cred = SimpleNamespace(allow_http_redirect_uri=False)
    fake_db = _FakeDB(cred)

    monkeypatch.setattr(oauth, "_load_redirect_uri_whitelist", lambda client_id, db: {"http://tenant.example.com/callback"})

    try:
        oauth._validate_redirect_uri("client_1", "http://tenant.example.com/callback", cast(Session, cast(object, fake_db)))
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 400
        assert "HTTP" in str(getattr(exc, "detail", ""))
    else:
        raise AssertionError("non-local http redirect_uri should require the compatibility switch")


def test_validate_redirect_uri_allows_non_local_http_when_switch_enabled(monkeypatch) -> None:
    cred = SimpleNamespace(allow_http_redirect_uri=True)
    fake_db = _FakeDB(cred)

    monkeypatch.setattr(oauth, "_load_redirect_uri_whitelist", lambda client_id, db: {"http://tenant.example.com/callback"})

    result = oauth._validate_redirect_uri(
        "client_1",
        "http://tenant.example.com/callback",
        cast(Session, cast(object, fake_db)),
    )

    assert result == "http://tenant.example.com/callback"


def test_require_same_group_rejects_cross_tenant_user() -> None:
    cred = SimpleNamespace(app=SimpleNamespace(group_id=2))
    user = SimpleNamespace(group_id=1, roles=[])

    try:
        oauth._require_same_group(cast(User, cast(object, user)), cast(AppCredential, cast(object, cred)))
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 403
    else:
        raise AssertionError("cross-tenant OAuth authorization should be blocked")


def test_require_same_group_allows_same_tenant_user() -> None:
    cred = SimpleNamespace(app=SimpleNamespace(group_id=2))
    user = SimpleNamespace(group_id=2, roles=[])

    oauth._require_same_group(cast(User, cast(object, user)), cast(AppCredential, cast(object, cred)))


