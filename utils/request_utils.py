from __future__ import annotations

# Centralized request/auth helper exports.
# Keep this as the single import target for routers to avoid scattered duplicates.

from utils.auth_security import (
    resolve_ip_location,
    extract_client_meta,
    record_risk_event,
    is_global_melt_enabled,
    get_login_fail_policy,
    login_fail_key,
    get_login_fail_count,
    increment_login_fail,
    clear_login_fail,
    captcha_required_response,
)

__all__ = [
    "resolve_ip_location",
    "extract_client_meta",
    "record_risk_event",
    "is_global_melt_enabled",
    "get_login_fail_policy",
    "login_fail_key",
    "get_login_fail_count",
    "increment_login_fail",
    "clear_login_fail",
    "captcha_required_response",
]

