from __future__ import annotations

import hashlib
import datetime

from utils.crypto import (
    hash_secret,
    verify_secret,
    create_refresh_token,
    introspect_token,
)
from bootstrap import DEFAULT_RISK_RULE_SPECS
from utils.risk_expr import evaluate_match_expression, build_risk_context


def test_secret_hash_uses_bcrypt_prefix_and_verifies() -> None:
    raw = "sec_demo_secret_123!"
    stored = hash_secret(raw)
    assert stored.startswith("bcrypt$")
    assert verify_secret(raw, stored) is True
    assert verify_secret("wrong_secret", stored) is False


def test_secret_verify_supports_legacy_sha256_hash() -> None:
    raw = "legacy-secret"
    legacy = hashlib.sha256(raw.encode()).hexdigest()
    assert verify_secret(raw, legacy) is True
    assert verify_secret(raw, f"sha256${legacy}") is True
    assert verify_secret("bad", legacy) is False


def test_create_refresh_token_and_introspect_active() -> None:
    expire_at = datetime.datetime.now() + datetime.timedelta(minutes=5)
    token = create_refresh_token("cli_test", "read write", expire_at)
    info = introspect_token(token, token_type="refresh_token")
    assert info["active"] is True
    assert info["sub"] == "cli_test"
    assert info["token_type"] == "refresh_token"


def test_risk_expression_eval_basic() -> None:
    ctx = build_risk_context(username="alice", ip="127.0.0.1", fail_count=3)
    assert evaluate_match_expression("fail_count >= 3 and username == 'alice'", ctx) is True


def test_risk_expression_rejects_too_long() -> None:
    ctx = build_risk_context(username="alice")
    too_long = "a" * 513
    try:
        evaluate_match_expression(too_long, ctx)
        assert False, "expected long expression to be rejected"
    except Exception as exc:
        assert "too long" in str(exc)


def test_risk_expression_rejects_unknown_identifier() -> None:
    ctx = build_risk_context(username="alice")
    try:
        evaluate_match_expression("secret_value == 1", ctx)
        assert False, "expected unknown identifier rejection"
    except Exception as exc:
        assert "unknown identifier" in str(exc)


def test_default_risk_rules_include_common_security_policies() -> None:
    names = {item["name"] for item in DEFAULT_RISK_RULE_SPECS}
    rule_types = {item["rule_type"] for item in DEFAULT_RISK_RULE_SPECS}

    assert "登录失败验证码策略(默认)" in names
    assert "防扫描器策略(默认)" in names
    assert "防恶意UI/自动化策略(默认)" in names
    assert "防SQL注入策略(默认)" in names
    assert "防XSS注入策略(默认)" in names
    assert "高危路径探测策略(默认)" in names

    assert "LOGIN_FAIL_CAPTCHA" in rule_types
    assert "SECURITY_SCANNER_BLOCK" in rule_types
    assert "MALICIOUS_UI_BLOCK" in rule_types
    assert "SQL_INJECTION_BLOCK" in rule_types
    assert "XSS_INJECTION_BLOCK" in rule_types
    assert "SENSITIVE_PATH_BLOCK" in rule_types


