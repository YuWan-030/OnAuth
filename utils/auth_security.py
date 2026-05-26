import os
import re
import requests
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi import Request
from sqlalchemy.orm import Session

from database import RiskEvent, RiskGlobalSetting
from middlewares.auth import redis_client
from utils.captcha import issue_captcha
from utils.risk_expr import build_risk_context, resolve_login_fail_policy


IP_LOCATION_CACHE_TTL_SECONDS = int(os.getenv("IP_LOCATION_CACHE_TTL_SECONDS", "86400"))


def _ip_location_cache_key(ip_value: str) -> str:
    return f"ip_location:{ip_value}"


def _read_cached_ip_location(ip_value: str) -> str | None:
    try:
        cached = redis_client.get(_ip_location_cache_key(ip_value))
        if isinstance(cached, str) and cached.strip():
            return cached.strip()
    except Exception:
        return None
    return None


def _write_cached_ip_location(ip_value: str, location: str) -> None:
    try:
        redis_client.setex(_ip_location_cache_key(ip_value), IP_LOCATION_CACHE_TTL_SECONDS, location)
    except Exception:
        return


def _parse_cip_cc_location(raw_text: str) -> str:
    text = str(raw_text or "")
    if not text.strip():
        return "未知"

    operator = ""
    match_operator = re.search(r"^\s*运营商\s*[:：]\s*(.+?)\s*$", text, flags=re.MULTILINE)
    if match_operator:
        operator = match_operator.group(1).strip()

    def _with_operator(location_text: str) -> str:
        clean_location = str(location_text or "").strip()
        if not clean_location:
            return "未知"
        if operator and operator not in clean_location:
            return f"{clean_location} {operator}"
        return clean_location

    match_address = re.search(r"^\s*地址\s*[:：]\s*(.+?)\s*$", text, flags=re.MULTILINE)
    if match_address:
        address = match_address.group(1).strip()
        if address:
            return _with_operator(address)

    for label in ("数据三", "数据二"):
        match_data = re.search(rf"^\s*{label}\s*[:：]\s*(.+?)\s*$", text, flags=re.MULTILINE)
        if not match_data:
            continue
        value = match_data.group(1).strip()
        # cip.cc 通常形如: 中国浙江省宁波市 | 电信
        location_only = value.split("|", 1)[0].strip()
        if location_only:
            return _with_operator(location_only)

    return "未知"


def resolve_ip_location(ip_value: str) -> str:
    if not ip_value or ip_value == "-":
        return "未知"
    private_prefixes = ("10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "192.168.")
    if ip_value.startswith(private_prefixes):
        return "内网"

    cached_location = _read_cached_ip_location(ip_value)
    if cached_location:
        return cached_location

    try:
        resp = requests.get(
            f"https://www.cip.cc/{ip_value}",
            headers={"User-Agent": "curl/8.0.0"},
            timeout=2,
        )
        if resp.status_code == 200:
            location = _parse_cip_cc_location(resp.text)
            _write_cached_ip_location(ip_value, location)
            return location
    except Exception:
        return "未知"
    return "未知"


def _parse_user_agent(user_agent: str) -> tuple[bool, str, str]:
    ua_lower = (user_agent or "").lower()

    # iPadOS desktop UA often carries "Macintosh" but still includes mobile Safari tokens.
    is_ios = any(token in ua_lower for token in ("iphone", "ipad", "ipod", "cpu iphone os", "cpu os")) or (
        "macintosh" in ua_lower and "mobile/" in ua_lower and "safari" in ua_lower
    )
    is_android = "android" in ua_lower
    is_mobile = is_android or is_ios or any(
        token in ua_lower for token in ("mobile", "phone", "iemobile", "windows phone")
    )

    if any(token in ua_lower for token in ("edg/", "edga/", "edgios/", " edge/")):
        browser = "Edge"
    elif "samsungbrowser" in ua_lower:
        browser = "Samsung Internet"
    elif "opr/" in ua_lower or "opera" in ua_lower:
        browser = "Opera"
    elif "firefox" in ua_lower or "fxios" in ua_lower:
        browser = "Firefox"
    elif "chrome" in ua_lower or "crios" in ua_lower or "chromium" in ua_lower:
        browser = "Chrome"
    elif "safari" in ua_lower:
        browser = "Safari"
    else:
        browser = "Unknown"

    if is_android:
        os_name = "Android"
    elif is_ios:
        os_name = "iOS"
    elif "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os" in ua_lower or "macintosh" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    else:
        os_name = "Unknown"

    return is_mobile, browser, os_name


def extract_client_meta(request: Request, include_location: bool = True) -> tuple[str, str, bool, str, str, str]:
    cached_base = getattr(request.state, "_client_meta_base", None)
    if cached_base is None:
        ip_raw = request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP") or request.client.host
        ip_value = str(ip_raw) if ip_raw else "-"
        client_ip = (ip_value.split(",")[0].strip() if ip_value else "-")
        user_agent = request.headers.get("User-Agent") or ""
        is_mobile, browser, os_name = _parse_user_agent(user_agent)

        cached_base = (client_ip, user_agent, is_mobile, browser, os_name)
        request.state._client_meta_base = cached_base

    client_ip, user_agent, is_mobile, browser, os_name = cached_base
    if not include_location:
        return client_ip, user_agent, is_mobile, browser, os_name, "-"

    cached_location = getattr(request.state, "_client_meta_location", None)
    if cached_location is None:
        cached_location = resolve_ip_location(client_ip)
        request.state._client_meta_location = cached_location

    return client_ip, user_agent, is_mobile, browser, os_name, cached_location


def record_risk_event(db: Session, request: Request, risk_level: str, action: str = "BLOCK") -> None:
    client_ip, _, _, _, _, _ = extract_client_meta(request, include_location=False)
    try:
        db.add(RiskEvent(
            action=action,
            latency_ms=0,
            ip=client_ip,
            path=request.url.path,
            risk_level=risk_level
        ))
        db.commit()
    except Exception:
        db.rollback()


def is_global_melt_enabled(db: Session) -> bool:
    setting = db.query(RiskGlobalSetting).first()
    return bool(setting and setting.is_melt)


def get_login_fail_policy(
    db: Session,
    request: Request,
    username: str,
    fail_count: int,
    default_threshold: int,
    default_window: int,
    rule_type: str,
) -> tuple[int, int]:
    client_ip, user_agent, is_mobile, browser, os_name, _ = extract_client_meta(request, include_location=False)
    context = build_risk_context(
        username=username,
        ip=client_ip,
        path=request.url.path,
        user_agent=user_agent,
        browser=browser,
        os=os_name,
        location="",
        is_mobile=is_mobile,
        fail_count=fail_count,
    )
    threshold, window, _ = resolve_login_fail_policy(
        db=db,
        context=context,
        default_threshold=default_threshold,
        default_window=default_window,
        rule_type=rule_type,
        action="CAPTCHA",
    )
    return threshold, window


def login_fail_key(username: str, client_ip: str) -> str:
    safe_user = (username or "").strip().lower() or "unknown"
    safe_ip = (client_ip or "-").strip()
    return f"login_fail:{safe_user}:{safe_ip}"


def get_login_fail_count(redis_client, username: str, client_ip: str) -> int:
    value = redis_client.get(login_fail_key(username, client_ip))
    try:
        return int(value or 0)
    except ValueError:
        return 0


def increment_login_fail(redis_client, username: str, client_ip: str, ttl_seconds: int) -> int:
    key = login_fail_key(username, client_ip)
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, ttl_seconds)
    return int(count)


def clear_login_fail(redis_client, username: str, client_ip: str) -> None:
    redis_client.delete(login_fail_key(username, client_ip))


def captcha_required_response(redis_client, message: str, status_code: int = status.HTTP_403_FORBIDDEN) -> JSONResponse:
    token, image = issue_captcha(redis_client)
    return JSONResponse(
        status_code=status_code,
        content={
            "message": message,
            "captcha_required": True,
            "captcha_token": token,
            "captcha_image": image,
        },
    )

