from __future__ import annotations

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

