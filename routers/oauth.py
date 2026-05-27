import base64
import json
import datetime
import os
import secrets
import hashlib
import re
import jwt
import redis
from fastapi import APIRouter, Depends, HTTPException, Query, Form, Cookie, Response, Request, Header, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import time
from urllib.parse import urlencode, urlparse
from database import get_db, AppCredential, User
from middlewares.auth import redis_client
from routers.credential_redirect_uris import load_redirect_uri_whitelist_from_credential
from routers.webhook import dispatch_webhook_event
from utils.crypto import verify_password, create_access_token, create_refresh_token, verify_secret
from utils.captcha import verify_captcha
from utils.request_utils import (
    extract_client_meta,
    resolve_ip_location,
    record_risk_event,
    is_global_melt_enabled,
    get_login_fail_policy,
    get_login_fail_count,
    increment_login_fail,
    clear_login_fail,
    captcha_required_response,
)
from config import SECRET_KEY, ALGORITHM


def _resolve_ip_location(ip_value: str) -> str:
    # 兼容旧符号，避免影响其他调用方
    from utils.auth_security import resolve_ip_location
    return resolve_ip_location(ip_value)


def _extract_client_meta(request: Request, include_location: bool = True) -> tuple[str, str, bool, str, str, str]:
    return extract_client_meta(request, include_location=include_location)


def _store_session_meta(session_id: str, client_meta: tuple[str, str, bool, str, str, str]) -> None:
    client_ip, user_agent, is_mobile, browser, os_name, location = client_meta
    device_type = "mobile" if is_mobile else "desktop"
    meta_key = f"sess_meta:{session_id}"
    redis_client.hset(meta_key, mapping={
        "ip": client_ip,
        "ua": user_agent,
        "is_mobile": "1" if is_mobile else "0",
        "device_type": device_type,
        "browser": browser,
        "os": os_name,
        "location": location,
        "login_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    redis_client.expire(meta_key, SESSION_TTL_SECONDS)


def _enrich_session_location_async(session_id: str, client_ip: str) -> None:
    if not session_id or not client_ip:
        return
    location = resolve_ip_location(client_ip)
    try:
        redis_client.hset(f"sess_meta:{session_id}", mapping={"location": location})
    except Exception:
        return


def _record_risk_event(db: Session, request: Request, risk_level: str, action: str = "BLOCK") -> None:
    record_risk_event(db, request, risk_level, action)


def _is_global_melt_enabled(db: Session) -> bool:
    return is_global_melt_enabled(db)


def _purge_session_links(session_id: str | None, user_id: int | None = None) -> None:
    if not session_id:
        return
    try:
        redis_client.delete(session_id)
        if user_id is not None:
            redis_client.srem(f"user:active_sessions:{user_id}", session_id)
    except Exception:
        return


def _resolve_active_session_user(session_id: str | None, db: Session) -> tuple[User | None, int | None, str | None]:
    if not session_id or not str(session_id).startswith("sess_"):
        return None, None, None

    raw_user = redis_client.get(session_id)
    if not raw_user:
        return None, None, None

    raw_user_text = raw_user.decode("utf-8") if isinstance(raw_user, bytes) else str(raw_user)
    try:
        user_id = int(str(raw_user_text).strip())
    except (TypeError, ValueError):
        return None, None, "会话数据损坏，请重新登录"

    linked_user = db.query(User).filter(User.id == user_id).first()
    if not linked_user:
        return None, user_id, "关联用户已不存在"
    if not linked_user.is_active:
        return linked_user, user_id, "该账户已被冻结，请联系管理员"
    return linked_user, user_id, None


def revoke_user_oauth_artifacts(user_id: int | None, username: str | None = None) -> dict[str, int]:
    """
    按用户维度清理 OAuth 相关 Redis 残留：
    - 授权码 oauth_code:*
    - access_token / refresh_token 的 oauth_userinfo:*
    """
    deleted_code_count = 0
    deleted_userinfo_count = 0

    try:
        target_user_id = int(user_id) if user_id is not None else None
    except (TypeError, ValueError):
        target_user_id = None

    target_username = (username or "").strip() or None

    if target_user_id is None and not target_username:
        return {"oauth_code": 0, "oauth_userinfo": 0}

    def _matches_payload(payload: dict) -> bool:
        payload_user_id = payload.get("user_id")
        payload_username = str(payload.get("username") or "").strip() or None

        try:
            if target_user_id is not None and payload_user_id is not None and int(payload_user_id) == target_user_id:
                return True
        except (TypeError, ValueError):
            pass

        if target_username and payload_username and payload_username == target_username:
            return True
        return False

    try:
        for raw_key in redis_client.scan_iter("oauth_code:*"):
            key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
            raw_value = redis_client.get(key)
            if not raw_value:
                continue
            raw_text = raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)
            try:
                payload = json.loads(raw_text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and _matches_payload(payload):
                redis_client.delete(key)
                deleted_code_count += 1

        for raw_key in redis_client.scan_iter("oauth_userinfo:*"):
            key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
            raw_value = redis_client.get(key)
            if not raw_value:
                continue
            raw_text = raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)
            try:
                payload = json.loads(raw_text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and _matches_payload(payload):
                redis_client.delete(key)
                deleted_userinfo_count += 1
    except Exception:
        return {"oauth_code": deleted_code_count, "oauth_userinfo": deleted_userinfo_count}

    return {"oauth_code": deleted_code_count, "oauth_userinfo": deleted_userinfo_count}


LOGIN_FAIL_THRESHOLD = 3
LOGIN_FAIL_TTL_SECONDS = 600
LOGIN_FAIL_RULE_TYPE = "LOGIN_FAIL_CAPTCHA"
PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
STATE_RE = re.compile(r"^[A-Za-z0-9\-._~]{8,128}$")
SESSION_TTL_SECONDS = 86400


def _get_login_fail_policy(db: Session, request: Request, username: str, fail_count: int) -> tuple[int, int]:
    return get_login_fail_policy(
        db=db,
        request=request,
        username=username,
        fail_count=fail_count,
        default_threshold=LOGIN_FAIL_THRESHOLD,
        default_window=LOGIN_FAIL_TTL_SECONDS,
        rule_type=LOGIN_FAIL_RULE_TYPE,
    )


def _login_fail_key(username: str, client_ip: str) -> str:
    safe_user = (username or "").strip().lower() or "unknown"
    safe_ip = (client_ip or "-").strip()
    return f"login_fail:{safe_user}:{safe_ip}"


def _get_login_fail_count(username: str, client_ip: str) -> int:
    return get_login_fail_count(redis_client, username, client_ip)


def _increment_login_fail(username: str, client_ip: str, ttl_seconds: int) -> int:
    return increment_login_fail(redis_client, username, client_ip, ttl_seconds)


def _clear_login_fail(username: str, client_ip: str) -> None:
    clear_login_fail(redis_client, username, client_ip)


def _captcha_required_response(message: str) -> JSONResponse:
    return captcha_required_response(redis_client, message, status_code=403)


def _validate_pkce_challenge(code_challenge: str) -> str:
    challenge = (code_challenge or "").strip()
    if len(challenge) < 43 or len(challenge) > 128:
        raise HTTPException(status_code=400, detail="PKCE 参数错误：code_challenge 长度必须在 43~128 之间")
    if not re.fullmatch(r"[A-Za-z0-9\-._~]+", challenge):
        raise HTTPException(status_code=400, detail="PKCE 参数错误：code_challenge 含有非法字符")
    return challenge


def _normalize_pkce_method(code_challenge_method: str | None) -> str:
    method = (code_challenge_method or "S256").strip().upper()
    if method != "S256":
        raise HTTPException(status_code=400, detail="PKCE 参数错误：code_challenge_method 仅支持 S256")
    return method


def _validate_code_verifier(code_verifier: str) -> str:
    verifier = (code_verifier or "").strip()
    if not PKCE_VERIFIER_RE.fullmatch(verifier):
        raise HTTPException(status_code=400, detail="PKCE 参数错误：code_verifier 格式不合法")
    return verifier


def _derive_code_challenge(code_verifier: str, method: str) -> str:
    if method != "S256":
        raise HTTPException(status_code=400, detail="PKCE 参数错误：code_challenge_method 仅支持 S256")
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def _normalize_optional_pkce(code_challenge: str | None, code_challenge_method: str | None) -> tuple[str, str]:
    challenge = (code_challenge or "").strip()
    if not challenge:
        return "", ""
    method = _normalize_pkce_method(code_challenge_method)
    return _validate_pkce_challenge(challenge), method


def _validate_state(state: str | None) -> str | None:
    if state is None:
        return None
    clean_state = state.strip()
    if not clean_state:
        return None
    if not STATE_RE.fullmatch(clean_state):
        raise HTTPException(status_code=400, detail="state 参数不合法：需为 8~128 位 URL 安全字符")
    if len(set(clean_state)) < 4:
        raise HTTPException(status_code=400, detail="state 参数强度过低，请使用高熵随机值")
    return clean_state


def _load_redirect_uri_whitelist(client_id: str, db: Session) -> set[str]:
    whitelist: set[str] = set()

    # 支持环境变量下发白名单: {"client_id": ["https://a/cb", "http://127.0.0.1:8765/callback"]}
    env_json = (os.getenv("OAUTH_REDIRECT_URI_WHITELIST_JSON") or "").strip()
    if env_json:
        try:
            mapping = json.loads(env_json)
            values = mapping.get(client_id, []) if isinstance(mapping, dict) else []
            if isinstance(values, str):
                values = [values]
            for item in values:
                if isinstance(item, str) and item.strip():
                    whitelist.add(item.strip())
        except Exception:
            pass

    redis_raw = redis_client.get(f"oauth:redirect_uris:{client_id}")
    if redis_raw is not None:
        if isinstance(redis_raw, bytes):
            redis_raw = redis_raw.decode("utf-8", errors="ignore")
        redis_value = str(redis_raw).strip()
        if redis_value:
            try:
                parsed = json.loads(redis_value)
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, str) and item.strip():
                            whitelist.add(item.strip())
                    return whitelist
            except Exception:
                for item in redis_value.split(","):
                    uri = item.strip()
                    if uri:
                        whitelist.add(uri)
                return whitelist
        return whitelist

    credential = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if credential:
        for uri in load_redirect_uri_whitelist_from_credential(credential):
            whitelist.add(uri)

    return whitelist


def _redirect_uri_matches_whitelist_entry(redirect_uri: str, whitelist_entry: str) -> bool:
    clean_uri = (redirect_uri or "").strip()
    clean_entry = (whitelist_entry or "").strip()
    if not clean_uri or not clean_entry:
        return False

    request_parsed = urlparse(clean_uri)
    entry_parsed = urlparse(clean_entry)

    if request_parsed.scheme != entry_parsed.scheme:
        return False
    if request_parsed.hostname != entry_parsed.hostname:
        return False
    if request_parsed.path != entry_parsed.path:
        return False
    if request_parsed.params != entry_parsed.params or request_parsed.query != entry_parsed.query:
        return False
    if request_parsed.fragment or entry_parsed.fragment:
        return False

    request_port = request_parsed.port
    entry_port = entry_parsed.port
    local_hosts = {"localhost", "127.0.0.1", "::1"}

    if entry_parsed.hostname in local_hosts and entry_port is None:
        return True

    return request_port == entry_port


def _validate_redirect_uri(client_id: str, redirect_uri: str, db: Session) -> str:
    clean_uri = (redirect_uri or "").strip()
    if not clean_uri:
        raise HTTPException(status_code=400, detail="redirect_uri 不能为空")

    parsed = urlparse(clean_uri)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="redirect_uri 不合法：必须是完整的 http(s) URL")
    if parsed.fragment:
        raise HTTPException(status_code=400, detail="redirect_uri 不允许包含 URL fragment")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise HTTPException(status_code=400, detail="redirect_uri 使用 http 时仅允许本地回调地址")

    try:
        whitelist = _load_redirect_uri_whitelist(client_id, db)
    except TypeError:
        # 兼容旧测试里只接收一个参数的 monkeypatch
        whitelist = _load_redirect_uri_whitelist(client_id)
    if not whitelist:
        raise HTTPException(status_code=400, detail="客户端未配置 redirect_uri 白名单")
    if not any(_redirect_uri_matches_whitelist_entry(clean_uri, item) for item in whitelist):
        raise HTTPException(status_code=400, detail="redirect_uri 不在客户端白名单中")

    return clean_uri


def _ensure_redis_security_ready() -> None:
    try:
        redis_client.ping()
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        raise HTTPException(status_code=503, detail="鉴权基础设施暂时不可用，请稍后重试")


router = APIRouter(tags=["OAuth2标准流"])
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))



@router.get("/oauth/authorize", summary="【OAuth2标准流】授权入口（纯净 Session 终极优化版）")
def oauth_authorize(
        request: Request,
        client_id: str = Query(...),
        response_type: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query("read"),
        state: str = Query(None),
        code_challenge: str = Query(None),
        code_challenge_method: str = Query(None),

        # 🎯 纯净双轨：只拦截你中台登录时亲手种下的两个 Session Cookie 键名
        sso_session_id: str = Cookie(None),
        session_id: str = Query(None),
        db: Session = Depends(get_db)
):
    if response_type != "code":
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": "目前仅支持 response_type='code' 标准授权码模式。"}
        )

    normalized_state = _validate_state(state)
    pkce_challenge, pkce_method = _normalize_optional_pkce(code_challenge, code_challenge_method)

    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": "非法的客户端申请：client_id 未注册。"}
        )

    redirect_uri = _validate_redirect_uri(client_id, redirect_uri, db)

    # 三层架构熔断合规审计
    current_app = cred.app
    current_group = current_app.group
    if not cred.is_active:
        detail_msg = "安全合规性拒绝：该凭证授权通道已被手工关闭。"
    elif not current_app.is_active:
        detail_msg = f"安全合规性拒绝：独立应用 [{current_app.app_name}] 已被强制下线。"
    elif not current_group.is_active:
        detail_msg = f"安全合规性拒绝：组织空间 [{current_group.group_name}] 已被整体封禁！"
    else:
        detail_msg = None

    if detail_msg:
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": detail_msg}
        )

    # 🚀 【双轨纯 Session 清洗流】
    # 顺位：URL显式传参最高准则 > 旧版或第三方规范(sso_session_id)
    effective_session_id = session_id or sso_session_id

    session_user, session_user_id, session_blocked_detail = _resolve_active_session_user(effective_session_id, db)
    if session_blocked_detail:
        _purge_session_links(effective_session_id, session_user_id)
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": session_blocked_detail},
            status_code=403,
        )

    user_logged_in = session_user.username if session_user else None

    context = {
        "request": request,
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": normalized_state or "",
        "code_challenge": pkce_challenge,
        "code_challenge_method": pkce_method,
        "group_name": current_group.group_name,
        "app_name": current_app.app_name,
        "app_logo": current_app.app_logo
    }

    # 🚨 如果没有任何渠道命中有效的 Redis 会话，踢回登录墙
    if not user_logged_in:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context=context
        )

    # 🚀 完美平滑降落到授权确认舱（Consent Page）
    context.update({
        "username": user_logged_in,
        "session_id": effective_session_id
    })
    return templates.TemplateResponse(
        request=request,
        name="consent.html",
        context=context
    )


@router.post("/oauth/login_submit", summary="内部路由：处理中台登录提交并执行安全认证")
def login_submit(
        response: Response,
        request: Request,
        background_tasks: BackgroundTasks,
        username: str = Form(...),
        password: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        scope: str = Form(...),
        state: str = Form(None),
        code_challenge: str = Form(None),
        code_challenge_method: str = Form(None),
        captcha_token: str = Form(None),
        captcha_code: str = Form(None),
        db: Session = Depends(get_db)
):
    _validate_state(state)

    if _is_global_melt_enabled(db):
        _record_risk_event(db, request, risk_level="high", action="BLOCK")
        raise HTTPException(status_code=503, detail="全局熔断已开启，登录入口临时关闭，请稍后重试")

    client_meta = _extract_client_meta(request, include_location=False)
    client_ip, user_agent, is_mobile, browser, os_name, _ = client_meta
    fail_count = _get_login_fail_count(username, client_ip)
    threshold, window_seconds = _get_login_fail_policy(db, request, username, fail_count)
    if fail_count >= threshold:
        if not verify_captcha(redis_client, captcha_token, captcha_code):
            return _captcha_required_response("登录失败次数过多，请输入验证码")

    # 1. 🔍 捞取核心用户基础信息
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        _record_risk_event(db, request, risk_level="high")
        new_count = _increment_login_fail(username, client_ip, window_seconds)
        if new_count >= threshold:
            return _captcha_required_response("登录失败次数过多，请输入验证码")
        raise HTTPException(status_code=401, detail="安全身份审计拒绝：用户名或密码错误，请重新核对")

    if not user.is_active:
        _record_risk_event(db, request, risk_level="medium")
        raise HTTPException(status_code=403, detail="合规性安全阻断：当前用户账户已被系统永久冻结或查封")

    _clear_login_fail(username, client_ip)

    pkce_challenge, pkce_method = _normalize_optional_pkce(code_challenge, code_challenge_method)

    # 2. ⚡ 生成传统的 Redis 会话（供 OAuth 授权大厅撞库）
    new_session_id = "sess_" + secrets.token_hex(12)
    redis_client.setex(new_session_id, SESSION_TTL_SECONDS, str(user.id))
    # 🌟 顺手做个反向索引：把这个 session_id 扔进该用户的活跃会话集合里
    user_set_key = f"user:active_sessions:{user.id}"
    redis_client.sadd(user_set_key, new_session_id)
    redis_client.expire(user_set_key, SESSION_TTL_SECONDS)  # 保持过期时间一致

    _store_session_meta(new_session_id, client_meta)
    background_tasks.add_task(_enrich_session_location_async, new_session_id, client_ip)


    # 3. 🎯 组装目标重定向 URL
    target_query = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
    }
    if pkce_challenge:
        target_query["code_challenge"] = pkce_challenge
        target_query["code_challenge_method"] = pkce_method
    if state:
        target_query["state"] = state
    target_url = f"/oauth/authorize?{urlencode(target_query)}"

    dispatch_webhook_event(
        event_type="auth.login",
        payload={
            "user_id": user.id,
            "username": user.username,
            "ip_address": client_ip,
            "login_at": int(time.time()),
            "browser": browser,
            "os": os_name,
            "is_mobile": bool(is_mobile),
            "user_agent": user_agent,
        },
        db=db
    )

    # 4. 🚀 【下发 SSO 凭证】
    response.set_cookie(
        key="sso_session_id",
        value=new_session_id,
        httponly=True,
        path="/",
        secure=False,  # 本地调试设为 False
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
        expires=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=SESSION_TTL_SECONDS),
    )

    return {
        "status": "success",
        "message": "身份核验通过，SSO会话已建立！",
        "redirect_url": target_url
    }
@router.post("/oauth/consent_submit", summary="内部路由：处理用户授权结果")
def consent_submit(
        request: Request,  # 🌟 修复：显式注入标准的 Request 实例
        action: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        scope: str = Form(...),
        state: str = Form(None),
        code_challenge: str = Form(None),
        code_challenge_method: str = Form(None),
        session_id: str = Form(..., description="接收从上一步 HTML 隐藏表单里提交上来的会话ID"),
        db: Session = Depends(get_db)
):
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        raise HTTPException(status_code=400, detail="非法客户端：client_id 未注册")

    if action != "allow":
        app_name = cred.app.app_name if cred.app else "未知应用"
        return templates.TemplateResponse(
            request=request,
            name="deny.html",
            context={
                "request": request,  # 使用标准 Request
                "app_name": app_name,
                "session_id": session_id
            },
            status_code=403
        )

    _validate_state(state)
    redirect_uri = _validate_redirect_uri(client_id, redirect_uri, db)

    session_user, session_user_id, session_blocked_detail = _resolve_active_session_user(session_id, db)
    if session_blocked_detail:
        _purge_session_links(session_id, session_user_id)
        return templates.TemplateResponse(
            request=request,
            name="oauth_error.html",
            context={"request": request, "detail": session_blocked_detail},
            status_code=403,
        )

    if not session_user:
        raise HTTPException(status_code=401, detail="会话已过期，请重新登录")

    pkce_challenge, pkce_method = _normalize_optional_pkce(code_challenge, code_challenge_method)

    user = session_user

    user_allowed_scopes = set()
    for role in user.roles:
        for perm in role.permissions:
            user_allowed_scopes.add(perm.name)

    requested_scopes = set([s.strip() for s in scope.split(",") if s.strip()])
    final_scopes = requested_scopes.intersection(user_allowed_scopes)

    if not final_scopes:
        raise HTTPException(
            status_code=403,
            detail="安全受限：您当前所在的权限组级别，无法满足该客户端所要求的任何权限范围"
        )

    auth_code = "code_" + secrets.token_hex(16)
    auth_code_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": ",".join(final_scopes),
        "username": user.username,
        "user_id": user.id,
        "response_type": "code",
        "code_challenge": pkce_challenge,
        "code_challenge_method": pkce_method
    }
    redis_client.setex(f"oauth_code:{auth_code}", 600, json.dumps(auth_code_data))

    target_url = f"{redirect_uri}?code={auth_code}"
    if state:
        target_url += f"&state={state}"

    return RedirectResponse(url=target_url, status_code=303)

@router.post("/oauth/token", summary="【OAuth2标准流】统一令牌网关")
def oauth_token_exchange(
        grant_type: str = Form(...),
        client_id: str = Form(None),
        client_secret: str = Form(None),
        authorization: str = Header(None, description="标准 HTTP Basic 认证头"),
        code: str = Form(None),
        code_verifier: str = Form(None),
        refresh_token: str = Form(None),
        db: Session = Depends(get_db)
):
    _ensure_redis_security_ready()
    current_time = datetime.datetime.now()

    if authorization and authorization.startswith("Basic "):
        try:
            base64_str = authorization.split(" ")[1]
            decoded = base64.b64decode(base64_str).decode("utf-8")
            h_client_id, h_client_secret = decoded.split(":", 1)
            client_id = h_client_id
            client_secret = h_client_secret
        except Exception:
            raise HTTPException(status_code=401, detail="HTTP Basic 认证请求头格式解析破损")

    if not client_id:
        raise HTTPException(status_code=401, detail="缺少客户端标识(Client ID)")

    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred:
        raise HTTPException(status_code=401, detail="Client ID 或 Secret 安全不匹配")

    # 🚀【核心漏洞修复：防御层扩展到三层多租户】
    # 无论是客户端凭证、授权码兑换还是令牌刷新，先过硬熔断基线
    current_app = cred.app
    current_group = current_app.group

    if not cred.is_active:
        raise HTTPException(status_code=403, detail="该应用凭证通道已被中台管理员手工阻断")
    if not current_app.is_active:
        raise HTTPException(status_code=403, detail=f"独立应用 [{current_app.app_name}] 已被中台下线熔断")
    if not current_group.is_active:
        raise HTTPException(status_code=403, detail=f"该应用所属的工作室组织 [{current_group.group_name}] 已被整体查封")

    if cred.expire_at and cred.expire_at < current_time:
        raise HTTPException(status_code=403, detail="该中台服务订阅已到期，无法继续签发/刷新凭证")

    if grant_type == "client_credentials":
        if not client_secret or not verify_secret(client_secret, cred.client_secret_hash):
            raise HTTPException(status_code=401, detail="Client ID 或 Secret 安全不匹配")
        token_expire = current_time + datetime.timedelta(days=1)
        if cred.expire_at and token_expire > cred.expire_at:
            token_expire = cred.expire_at

        access_token = create_access_token(client_id, cred.scope, token_expire)
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": int((token_expire - current_time).total_seconds()),
            "scope": cred.scope
        }

    elif grant_type == "authorization_code":
        if not code:
            raise HTTPException(status_code=400, detail="授权码模式下必须提供 'code' 参数")
        redis_key = f"oauth_code:{code}"
        code_raw = redis_client.get(redis_key)
        if not code_raw:
            raise HTTPException(status_code=400, detail="无效或已被二次使用/已过期的非安全授权码")

        redis_client.delete(redis_key)
        code_info = json.loads(code_raw)

        if code_info["client_id"] != client_id:
            raise HTTPException(status_code=400, detail="安全隔离阻断：串号漏洞拒绝！")

        expected_challenge = str(code_info.get("code_challenge") or "").strip()
        if expected_challenge:
            if not code_verifier:
                raise HTTPException(status_code=400, detail="PKCE 校验失败：授权码模式下必须提供 code_verifier")
            verifier = _validate_code_verifier(code_verifier)
            method = _normalize_pkce_method(code_info.get("code_challenge_method", "S256"))
            derived_challenge = _derive_code_challenge(verifier, method)
            if not secrets.compare_digest(derived_challenge, expected_challenge):
                raise HTTPException(status_code=400, detail="PKCE 校验失败：code_verifier 不匹配")
        else:
            if not client_secret or not verify_secret(client_secret, cred.client_secret_hash):
                raise HTTPException(status_code=401, detail="传统授权码模式下缺少或错误的 Client Secret")

        user_id_raw = code_info.get("user_id")
        try:
            user_id = int(str(user_id_raw).strip())
        except (TypeError, ValueError):
            raise HTTPException(status_code=401, detail="授权码上下文中的用户信息损坏")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="关联用户已不存在")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="该账户已被冻结，请联系管理员")

        access_token_expire = current_time + datetime.timedelta(days=1)
        refresh_token_expire = current_time + datetime.timedelta(days=30)

        if cred.expire_at and access_token_expire > cred.expire_at:
            access_token_expire = cred.expire_at
        if cred.expire_at and refresh_token_expire > cred.expire_at:
            refresh_token_expire = cred.expire_at

        target_scope = code_info["scope"]
        access_token = create_access_token(client_id, target_scope, access_token_expire)
        new_refresh_token = create_refresh_token(client_id, target_scope, refresh_token_expire)

        user_context = {
            "username": code_info.get("username"),
            "user_id": code_info.get("user_id"),
        }
        access_ttl = max(1, int((access_token_expire - current_time).total_seconds()))
        refresh_ttl = max(1, int((refresh_token_expire - current_time).total_seconds()))
        redis_client.setex(f"oauth_userinfo:{access_token}", access_ttl, json.dumps(user_context))
        redis_client.setex(f"oauth_userinfo:{new_refresh_token}", refresh_ttl, json.dumps(user_context))

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": int((access_token_expire - current_time).total_seconds()),
            "scope": target_scope,
            "user_info": {"user": code_info["username"]}
        }

    elif grant_type == "refresh_token":
        if not client_secret or not verify_secret(client_secret, cred.client_secret_hash):
            raise HTTPException(status_code=401, detail="Client ID 或 Secret 安全不匹配")
        if not refresh_token:
            raise HTTPException(status_code=400, detail="刷新令牌模式下必须传 'refresh_token'")

        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("token_type") != "refresh_token":
                raise HTTPException(status_code=401, detail="非法欺骗：该令牌并非合法的刷新令牌体")

            if payload.get("sub") != client_id:
                raise HTTPException(status_code=401, detail="令牌错位拦截！")

            prior_user_context = redis_client.get(f"oauth_userinfo:{refresh_token}")
            if prior_user_context:
                prior_user_context_raw = prior_user_context.decode("utf-8") if isinstance(prior_user_context, bytes) else str(prior_user_context)
                try:
                    prior_user_context_data = json.loads(prior_user_context_raw)
                except json.JSONDecodeError:
                    raise HTTPException(status_code=401, detail="刷新令牌上下文受损")

                user_id_raw = prior_user_context_data.get("user_id")
                if user_id_raw is not None:
                    try:
                        user_id = int(str(user_id_raw).strip())
                    except (TypeError, ValueError):
                        raise HTTPException(status_code=401, detail="刷新令牌上下文中的用户信息损坏")

                    user = db.query(User).filter(User.id == user_id).first()
                    if not user:
                        raise HTTPException(status_code=401, detail="关联用户已不存在")
                    if not user.is_active:
                        raise HTTPException(status_code=403, detail="该账户已被冻结，请联系管理员")

            # 🌟【核心修复点】既然熔断校验已在上方前置拦截完成，这里可以直接安全地重新签发双币令牌
            target_scope = payload.get("scope", "read")
            access_token_expire = current_time + datetime.timedelta(days=1)
            refresh_token_expire = current_time + datetime.timedelta(days=30)

            if cred.expire_at and access_token_expire > cred.expire_at:
                access_token_expire = cred.expire_at
            if cred.expire_at and refresh_token_expire > cred.expire_at:
                refresh_token_expire = cred.expire_at

            new_access_token = create_access_token(client_id, target_scope, access_token_expire)
            new_refresh_token = create_refresh_token(client_id, target_scope, refresh_token_expire)

            if prior_user_context:
                access_ttl = max(1, int((access_token_expire - current_time).total_seconds()))
                refresh_ttl = max(1, int((refresh_token_expire - current_time).total_seconds()))
                redis_client.setex(f"oauth_userinfo:{new_access_token}", access_ttl, prior_user_context)
                redis_client.setex(f"oauth_userinfo:{new_refresh_token}", refresh_ttl, prior_user_context)

            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer",
                "expires_in": int((access_token_expire - current_time).total_seconds()),
                "scope": target_scope
            }
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="刷新令牌生存周期也已全部结束，请引导用户重新登录授权")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="刷新令牌受损")
    else:
        raise HTTPException(status_code=400, detail="未知的 grant_type 协议参数")

@router.post("/oauth/revoke", summary="【OAuth2标准流】客户端主动注销/撤销指定令牌")
def oauth_revoke_token(
        token: str = Form(..., description="要销毁的 access_token 或 refresh_token"),
        token_type_hint: str = Form("access_token", description="令牌类型暗示"),
        authorization: str = Header(None, description="标准 HTTP Basic 认证头"),
        client_id: str = Form(None),
        client_secret: str = Form(None),
        db: Session = Depends(get_db)
):
    _ensure_redis_security_ready()

    if authorization and authorization.startswith("Basic "):
        try:
            base64_str = authorization.split(" ")[1]
            decoded = base64.b64decode(base64_str).decode("utf-8")
            h_client_id, h_client_secret = decoded.split(":", 1)
            client_id = h_client_id
            client_secret = h_client_secret
        except Exception:
            raise HTTPException(status_code=401, detail="HTTP Basic 认证请求头格式解析破损")

    if not client_id or not client_secret:
        raise HTTPException(status_code=401, detail="缺少客户端凭证(Client ID / Secret)")

    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()
    if not cred or not verify_secret(client_secret, cred.client_secret_hash):
        raise HTTPException(status_code=401, detail="Client ID 或 Secret 安全不匹配")

    token_subject = None
    token_exp = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        token_subject = payload.get("sub")
        token_exp = payload.get("exp")
    except Exception:
        payload = None

    # 按 RFC 7009 返回 200，避免用错误细节辅助枚举；仅撤销当前 client 的令牌
    if token_subject and token_subject != client_id:
        return {}

    ttl_seconds = 86400
    if isinstance(token_exp, int):
        remain = int(token_exp - time.time())
        if remain > 0:
            ttl_seconds = remain

    redis_client.setex(f"revoked_token:{token}", ttl_seconds, "1")
    return {}
