import requests
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi import Request
from sqlalchemy.orm import Session

from database import RiskEvent, RiskGlobalSetting
from utils.captcha import issue_captcha
from utils.risk_expr import build_risk_context, resolve_login_fail_policy


def resolve_ip_location(ip_value: str) -> str:
    if not ip_value or ip_value == "-":
        return "未知"
    private_prefixes = ("10.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "192.168.")
    if ip_value.startswith(private_prefixes):
        return "内网"
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip_value}", params={"fields": "country,regionName,city"}, timeout=1)
        if resp.status_code == 200:
            data = resp.json()
            parts = [data.get("country"), data.get("regionName"), data.get("city")]
            return " ".join([p for p in parts if p]) or "未知"
    except Exception:
        return "未知"
    return "未知"


def extract_client_meta(request: Request) -> tuple[str, str, bool, str, str, str]:
    ip_raw = request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP") or request.client.host
    ip_value = str(ip_raw) if ip_raw else "-"
    client_ip = (ip_value.split(",")[0].strip() if ip_value else "-")
    user_agent = request.headers.get("User-Agent") or ""
    ua_lower = user_agent.lower()
    is_mobile = any(key in ua_lower for key in ["mobile", "iphone", "android", "ipad"])

    if "edg" in ua_lower or "edge" in ua_lower:
        browser = "Edge"
    elif "chrome" in ua_lower and "safari" in ua_lower:
        browser = "Chrome"
    elif "safari" in ua_lower:
        browser = "Safari"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    else:
        browser = "Unknown"

    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os" in ua_lower or "macintosh" in ua_lower:
        os_name = "macOS"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower or "ios" in ua_lower:
        os_name = "iOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    else:
        os_name = "Unknown"

    location = resolve_ip_location(client_ip)
    return client_ip, user_agent, is_mobile, browser, os_name, location


def record_risk_event(db: Session, request: Request, risk_level: str, action: str = "BLOCK") -> None:
    client_ip, _, _, _, _, _ = extract_client_meta(request)
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
    client_ip, user_agent, is_mobile, browser, os_name, location = extract_client_meta(request)
    context = build_risk_context(
        username=username,
        ip=client_ip,
        path=request.url.path,
        user_agent=user_agent,
        browser=browser,
        os=os_name,
        location=location,
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

