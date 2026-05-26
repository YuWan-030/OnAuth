import datetime

from fastapi import APIRouter, Depends, HTTPException, Cookie
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import (
    get_db,
    User,
    SessionLocal,
    SystemSiteSetting,
    SystemAnnouncement,
    RiskRule,
    RiskEvent,
    RiskGlobalSetting,
)
from middlewares.auth import redis_client
from middlewares.rbac import RBACChecker
from utils.captcha import issue_captcha
from utils.risk_expr import validate_match_expression
from schemas.admin_schema import (
    AnnouncementCreateInput,
    AnnouncementUpdateInput,
    SiteSettingUpdateInput,
    RiskRuleCreateInput,
    RiskRuleUpdateInput,
    RiskRuleStatusInput,
    RiskGlobalMeltInput,
    RiskEventCreateInput,
)

router = APIRouter(tags=["系统管理接口"])


class SessionRevokeInput(BaseModel):
    token_id: str = Field(..., min_length=1, description="会话令牌")
    username: str | None = Field(None, description="可选：用户名")


class SessionBatchRevokeInput(BaseModel):
    token_ids: list[str] = Field(default_factory=list, description="会话令牌列表")


class SessionRevokeAllInput(BaseModel):
    keep_current: bool = Field(True, description="是否保留当前会话")
    reason: str | None = Field(None, description="下线原因")


def _load_session_user_id(token_id: str) -> int | None:
    if not token_id.startswith("sess_"):
        return None

    try:
        key_type = redis_client.type(token_id)
        key_type = key_type.decode("utf-8") if isinstance(key_type, bytes) else str(key_type)
    except Exception:
        return None

    if key_type != "string":
        return None

    try:
        raw_user_id = redis_client.get(token_id)
    except Exception:
        return None

    if not raw_user_id:
        return None

    try:
        return int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
    except ValueError:
        return None


def _is_string_session_key(token_id: str) -> bool:
    if not token_id.startswith("sess_"):
        return False

    try:
        key_type = redis_client.type(token_id)
        key_type = key_type.decode("utf-8") if isinstance(key_type, bytes) else str(key_type)
    except Exception:
        return False

    return key_type == "string"


def _resolve_device_type_from_meta(meta: dict[str, str]) -> str:
    raw_type = str(meta.get("device_type", "")).strip().lower()
    if raw_type in {"mobile", "desktop"}:
        return raw_type

    raw_mobile = str(meta.get("is_mobile", "")).strip().lower()
    return "mobile" if raw_mobile in {"1", "true", "yes"} else "desktop"


@router.get("/system/session", summary="【管理端】获取在线会话列表")
def list_online_sessions(
        page: int = 1,
        limit: int = 10,
        username: str | None = None,
        ip: str | None = None,
        device: str | None = None,
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    username_filter = (username or "").strip()
    ip_filter = (ip or "").strip()
    device_filter = (device or "").strip().lower()

    sessions = []
    for raw_key in redis_client.scan_iter("sess_*"):
        token_id = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
        try:
            key_type = redis_client.type(token_id)
            key_type = key_type.decode("utf-8") if isinstance(key_type, bytes) else str(key_type)
        except Exception:
            continue
        if key_type != "string":
            continue

        raw_user_id = redis_client.get(token_id)
        if not raw_user_id:
            continue
        try:
            user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
        except ValueError:
            continue
        user_obj = db.query(User).filter(User.id == user_id).first()
        if not user_obj:
            continue
        if username_filter and (username_filter not in user_obj.username and username_filter not in token_id):
            continue
        meta_key = f"sess_meta:{token_id}"
        meta_raw = redis_client.hgetall(meta_key) or {}

        def _decode(value, default=""):
            if value is None:
                return default
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="ignore")
            return str(value)

        meta = {str(_decode(k)): _decode(v) for k, v in meta_raw.items()}
        ip_value = meta.get("ip", "-")
        browser_value = meta.get("browser", "Unknown")
        os_value = meta.get("os", "Unknown")
        device_type_value = _resolve_device_type_from_meta(meta)
        location_value = meta.get("location", "未知")
        login_time = meta.get("login_time") or "-"

        if ip_filter and ip_filter not in ip_value:
            continue
        device_label = f"{browser_value} {os_value} {device_type_value}".strip().lower()
        if device_filter and device_filter not in device_label:
            continue

        ttl = redis_client.ttl(token_id)
        ttl = int(ttl) if isinstance(ttl, (int, float)) and ttl > 0 else 0

        sessions.append({
            "token_id": token_id,
            "username": user_obj.username,
            "user_id": user_obj.id,
            "ip": ip_value,
            "browser": browser_value,
            "os": os_value,
            "device_type": device_type_value,
            "location": location_value,
            "login_time": login_time,
            "ttl": ttl,
            "group_id": user_obj.group_id,
        })

    sessions.sort(key=lambda item: item.get("login_time", ""), reverse=True)
    page = max(page, 1)
    limit = max(limit, 1)
    total = len(sessions)
    start = (page - 1) * limit
    end = start + limit
    return {
        "code": 200,
        "count": total,
        "data": sessions[start:end]
    }


@router.post("/system/session/revoke", summary="【管理端】强制下线指定会话")
def revoke_online_session(
        payload: SessionRevokeInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    token_id = payload.token_id.strip()
    if not _is_string_session_key(token_id):
        raise HTTPException(status_code=400, detail="token_id 非法")

    user_id = _load_session_user_id(token_id)
    if user_id:
        redis_client.srem(f"user:active_sessions:{user_id}", token_id)

    redis_client.delete(token_id)
    redis_client.delete(f"sess_meta:{token_id}")

    return {
        "code": 200,
        "message": "会话已强制下线"
    }


@router.post("/system/session/revoke_batch", summary="【管理端】批量强制下线会话")
def revoke_online_sessions_batch(
        payload: SessionBatchRevokeInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    token_ids = []
    for item in payload.token_ids:
        token_id = str(item).strip()
        if not _is_string_session_key(token_id):
            continue
        token_ids.append(token_id)
    if not token_ids:
        raise HTTPException(status_code=400, detail="token_ids 不能为空")

    for token_id in token_ids:
        user_id = _load_session_user_id(token_id)
        if user_id:
            user_set_key = f"user:active_sessions:{user_id}"
            redis_client.srem(user_set_key, token_id)
        redis_client.delete(token_id)
        redis_client.delete(f"sess_meta:{token_id}")

    return {
        "code": 200,
        "message": "批量下线完成",
        "count": len(token_ids)
    }


@router.post("/system/session/revoke_all", summary="【管理端】全量会话下线")
def revoke_online_sessions_all(
        payload: SessionRevokeAllInput,
        sso_session_id: str | None = Cookie(None),
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    keep_current = bool(payload.keep_current)
    current_token = (sso_session_id or "").strip()
    revoked_count = 0

    for raw_key in redis_client.scan_iter("sess_*"):
        token_id = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)

        if not _is_string_session_key(token_id):
            continue

        if keep_current and current_token and token_id == current_token:
            continue

        user_id = _load_session_user_id(token_id)
        if user_id:
            redis_client.srem(f"user:active_sessions:{user_id}", token_id)

        redis_client.delete(token_id)
        redis_client.delete(f"sess_meta:{token_id}")
        revoked_count += 1

    return {
        "code": 200,
        "message": "全部下线完成",
        "count": revoked_count
    }


@router.get("/system/captcha", summary="【公共】获取登录验证码")
def get_login_captcha():
    token, image = issue_captcha(redis_client)
    return {
        "code": 200,
        "data": {
            "token": token,
            "image": image
        }
    }


def _get_or_create_site_setting(db: Session) -> SystemSiteSetting:
    setting = db.query(SystemSiteSetting).first()
    if setting:
        return setting

    setting = SystemSiteSetting(
        site_name="OnAuth 云中台",
        domain="https://localhost:8000",
        copyright=""
    )
    db.add(setting)
    db.commit()
    db.refresh(setting)
    return setting


@router.get("/system/settings/site", summary="【管理端】获取站点基本信息")
def get_site_basic_settings(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    setting = _get_or_create_site_setting(db)
    return {
        "code": 200,
        "data": {
            "site_name": setting.site_name,
            "domain": setting.domain,
            "copyright": setting.copyright or ""
        }
    }


@router.post("/system/settings/site/update", summary="【管理端】更新站点基本信息")
def update_site_basic_settings(
        payload: SiteSettingUpdateInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    site_name = payload.site_name.strip()
    domain = payload.domain.strip()
    copyright_text = (payload.copyright or "").strip()

    if not site_name:
        raise HTTPException(status_code=400, detail="站点名称不能为空")
    if not domain:
        raise HTTPException(status_code=400, detail="控制台主域名不能为空")

    setting = _get_or_create_site_setting(db)
    setting.site_name = site_name
    setting.domain = domain
    setting.copyright = copyright_text
    setting.updated_by = current_user.username
    db.commit()

    return {
        "code": 200,
        "message": "站点基本信息已保存",
        "data": {
            "site_name": setting.site_name,
            "domain": setting.domain,
            "copyright": setting.copyright or ""
        }
    }


def _normalize_announcement_type(type_value: str) -> str:
    normalized = (type_value or "notice").strip().lower()
    if normalized not in {"notice", "bulletin"}:
        raise HTTPException(status_code=400, detail="公告类型仅支持 notice 或 bulletin")
    return normalized


def _normalize_announcement_status(status_value: str) -> str:
    normalized = (status_value or "published").strip().lower()
    if normalized not in {"published", "draft"}:
        raise HTTPException(status_code=400, detail="公告状态仅支持 published 或 draft")
    return normalized


def _format_announcement_item(item: SystemAnnouncement) -> dict:
    return {
        "id": item.id,
        "title": item.title,
        "content": item.content,
        "type": item.type,
        "is_pinned": item.is_pinned,
        "status": item.status,
        "creator": item.creator,
        "creator_id": item.creator_id,
        "created_at": item.created_at.strftime("%Y-%m-%d %H:%M:%S") if item.created_at else None,
        "updated_at": item.updated_at.strftime("%Y-%m-%d %H:%M:%S") if item.updated_at else None
    }


def _format_announcement_feed_item(item: SystemAnnouncement) -> dict:
    return {
        "id": item.id,
        "title": item.title,
        "content": item.content,
        "type": item.type,
        "is_pinned": item.is_pinned,
        "created_at": item.created_at.strftime("%Y-%m-%d %H:%M:%S") if item.created_at else None,
    }


def _build_announcement_feed_payload(items: list[SystemAnnouncement], notice_limit: int = 3) -> dict:
    broadcast = None
    notices: list[dict] = []

    for item in items:
        if item.type == "bulletin" and broadcast is None:
            broadcast = _format_announcement_feed_item(item)
            continue
        if item.type == "notice" and len(notices) < max(1, notice_limit):
            notices.append(_format_announcement_feed_item(item))

    return {
        "broadcast": broadcast,
        "notices": notices,
    }


def _require_logged_in_user_by_session(sso_session_id: str | None, db: Session) -> User:
    token = str(sso_session_id or "").strip()
    if not token or not token.startswith("sess_"):
        raise HTTPException(status_code=401, detail="请先登录")

    raw_user_id = redis_client.get(token)
    if not raw_user_id:
        raise HTTPException(status_code=401, detail="登录状态已过期")

    try:
        user_id = int(raw_user_id.decode("utf-8") if isinstance(raw_user_id, bytes) else raw_user_id)
    except Exception:
        raise HTTPException(status_code=401, detail="登录会话异常")

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="用户不存在或已被冻结")
    return user


@router.get("/system/announcement", summary="【管理端】拉取系统公告列表")
def list_system_announcements(
        page: int = 1,
        limit: int = 10,
        title: str | None = None,
        type: str | None = None,
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(SystemAnnouncement)

    title_filter = (title or "").strip()
    if title_filter:
        query = query.filter(SystemAnnouncement.title.contains(title_filter))

    if type:
        normalized_type = _normalize_announcement_type(type)
        query = query.filter(SystemAnnouncement.type == normalized_type)

    total = query.count()
    announcements = query.order_by(
        SystemAnnouncement.is_pinned.desc(),
        SystemAnnouncement.created_at.desc(),
        SystemAnnouncement.id.desc()
    ).offset((max(page, 1) - 1) * max(limit, 1)).limit(max(limit, 1)).all()

    return {
        "code": 200,
        "count": total,
        "data": [_format_announcement_item(item) for item in announcements]
    }


@router.get("/api/v1/announcement/feed", summary="【前台】拉取公告与大喇叭信息流")
def get_announcement_feed(
        limit: int = 3,
        sso_session_id: str | None = Cookie(None),
        db: Session = Depends(get_db)
):
    _require_logged_in_user_by_session(sso_session_id, db)
    safe_limit = min(max(limit, 1), 10)

    items = db.query(SystemAnnouncement).filter(
        SystemAnnouncement.status == "published"
    ).order_by(
        SystemAnnouncement.is_pinned.desc(),
        SystemAnnouncement.created_at.desc(),
        SystemAnnouncement.id.desc(),
    ).limit(50).all()

    return {
        "status": "success",
        "data": _build_announcement_feed_payload(items, notice_limit=safe_limit),
    }


@router.post("/system/announcement/create", summary="【管理端】创建系统公告")
def create_system_announcement(
        payload: AnnouncementCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    title = payload.title.strip()
    content = payload.content.strip()
    if not title:
        raise HTTPException(status_code=400, detail="公告标题不能为空")
    if not content:
        raise HTTPException(status_code=400, detail="公告正文不能为空")

    announcement = SystemAnnouncement(
        title=title,
        content=content,
        type=_normalize_announcement_type(payload.type),
        is_pinned=payload.is_pinned,
        status=_normalize_announcement_status(payload.status),
        creator=current_user.username,
        creator_id=current_user.id
    )
    db.add(announcement)
    db.commit()
    db.refresh(announcement)

    return {
        "code": 200,
        "message": "公告创建成功",
        "data": {
            "id": announcement.id
        }
    }


@router.post("/system/announcement/update", summary="【管理端】更新系统公告")
def update_system_announcement(
        payload: AnnouncementUpdateInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    announcement = db.query(SystemAnnouncement).filter(SystemAnnouncement.id == payload.id).first()
    if not announcement:
        raise HTTPException(status_code=404, detail="公告不存在")

    title = payload.title.strip()
    content = payload.content.strip()
    if not title:
        raise HTTPException(status_code=400, detail="公告标题不能为空")
    if not content:
        raise HTTPException(status_code=400, detail="公告正文不能为空")

    announcement.title = title
    announcement.content = content
    announcement.type = _normalize_announcement_type(payload.type)
    announcement.is_pinned = payload.is_pinned
    announcement.status = _normalize_announcement_status(payload.status)
    db.commit()

    return {
        "code": 200,
        "message": "公告更新成功"
    }


@router.delete("/system/announcement/{announcement_id}", summary="【管理端】删除系统公告")
def delete_system_announcement(
        announcement_id: int,
        current_user: User = Depends(RBACChecker("admin:delete")),
        db: Session = Depends(get_db)
):
    announcement = db.query(SystemAnnouncement).filter(SystemAnnouncement.id == announcement_id).first()
    if not announcement:
        raise HTTPException(status_code=404, detail="公告不存在")

    db.delete(announcement)
    db.commit()
    return {
        "code": 200,
        "message": "公告删除成功"
    }


@router.post("/system/risk/expression/validate", summary="【管理端】校验风控表达式")
def validate_risk_expression(
        payload: dict,
        current_user: User = Depends(RBACChecker("admin:read"))
):
    expression = str(payload.get("match_key") or "").strip()
    ok, err = validate_match_expression(expression)
    if not ok:
        return {
            "code": 400,
            "message": f"表达式不合法: {err}"
        }
    return {
        "code": 200,
        "message": "表达式校验通过"
    }


@router.get("/system/risk/stats", summary="【管理端】风险概览统计")
def get_risk_stats(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    today_start = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    blocks_today = db.query(RiskEvent).filter(
        RiskEvent.created_at >= today_start,
        RiskEvent.action == "BLOCK"
    ).count()
    rules_active = db.query(RiskRule).filter(RiskRule.status.is_(True)).count()
    avg_latency = db.query(func.avg(RiskEvent.latency_ms)).filter(RiskEvent.created_at >= today_start).scalar() or 0
    return {
        "code": 200,
        "data": {
            "blocks_today": blocks_today,
            "rules_active": rules_active,
            "avg_latency_ms": round(float(avg_latency), 2)
        }
    }


@router.get("/system/risk/rules", summary="【管理端】拉取风控规则列表")
def list_risk_rules(
        page: int = 1,
        limit: int = 10,
        rule_name: str | None = None,
        action_type: str | None = None,
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    query = db.query(RiskRule)
    if rule_name:
        query = query.filter(RiskRule.name.contains(rule_name.strip()))
    if action_type:
        query = query.filter(RiskRule.action == action_type.strip())

    total = query.count()
    rules = query.order_by(RiskRule.id.desc()).offset((max(page, 1) - 1) * max(limit, 1)).limit(max(limit, 1)).all()
    data = [
        {
            "id": rule.id,
            "name": rule.name,
            "rule_type": rule.rule_type,
            "target_key": rule.target_key,
            "match_key": rule.match_key,
            "threshold_count": rule.threshold_count,
            "threshold_window": rule.threshold_window,
            "action": rule.action,
            "status": rule.status,
            "updated_at": rule.updated_at.strftime("%Y-%m-%d %H:%M:%S") if rule.updated_at else None
        }
        for rule in rules
    ]
    return {
        "code": 200,
        "count": total,
        "data": data
    }


@router.post("/system/risk/rules", summary="【管理端】新增风控规则")
def create_risk_rule(
        payload: RiskRuleCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    expression = payload.match_key.strip()
    ok, err = validate_match_expression(expression)
    if not ok:
        raise HTTPException(status_code=400, detail=f"表达式不合法: {err}")

    new_rule = RiskRule(
        name=payload.name.strip(),
        rule_type=payload.rule_type.strip(),
        target_key=(payload.target_key.strip() if payload.target_key else None),
        match_key=expression,
        threshold_count=payload.threshold_count,
        threshold_window=payload.threshold_window,
        action=payload.action.strip(),
        status=payload.status,
        creator_id=current_user.id
    )
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)
    return {
        "code": 200,
        "message": "规则创建成功",
        "data": {
            "id": new_rule.id
        }
    }


@router.put("/system/risk/rules/{rule_id}", summary="【管理端】更新风控规则")
def update_risk_rule(
        rule_id: int,
        payload: RiskRuleUpdateInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    rule = db.query(RiskRule).filter(RiskRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")

    update_data = payload.model_dump(exclude_unset=True)
    if "name" in update_data:
        rule.name = update_data["name"].strip()
    if "rule_type" in update_data:
        rule.rule_type = update_data["rule_type"].strip()
    if "target_key" in update_data:
        rule.target_key = update_data["target_key"].strip() if update_data["target_key"] else None
    if "match_key" in update_data:
        expr_value = update_data["match_key"].strip()
        ok, err = validate_match_expression(expr_value)
        if not ok:
            raise HTTPException(status_code=400, detail=f"表达式不合法: {err}")
        rule.match_key = expr_value
    if "threshold_count" in update_data:
        rule.threshold_count = update_data["threshold_count"]
    if "threshold_window" in update_data:
        rule.threshold_window = update_data["threshold_window"]
    if "action" in update_data:
        rule.action = update_data["action"].strip()
    if "status" in update_data:
        rule.status = update_data["status"]

    db.commit()
    return {
        "code": 200,
        "message": "规则已更新"
    }


@router.delete("/system/risk/rules/{rule_id}", summary="【管理端】删除风控规则")
def delete_risk_rule(
        rule_id: int,
        current_user: User = Depends(RBACChecker("admin:delete")),
        db: Session = Depends(get_db)
):
    rule = db.query(RiskRule).filter(RiskRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")
    db.delete(rule)
    db.commit()
    return {
        "code": 200,
        "message": "规则已删除"
    }


@router.patch("/system/risk/rules/{rule_id}/status", summary="【管理端】切换风控规则状态")
def toggle_risk_rule_status(
        rule_id: int,
        payload: RiskRuleStatusInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    rule = db.query(RiskRule).filter(RiskRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")
    rule.status = payload.status
    db.commit()
    return {
        "code": 200,
        "message": "规则状态已更新",
        "data": {
            "status": rule.status
        }
    }


@router.get("/system/risk/global_melt", summary="【管理端】获取全局熔断状态")
def get_global_melt_state(
        current_user: User = Depends(RBACChecker("admin:read")),
        db: Session = Depends(get_db)
):
    setting = db.query(RiskGlobalSetting).first()
    is_active = setting.is_melt if setting else False
    return {
        "code": 200,
        "data": {
            "is_active": is_active
        }
    }


@router.put("/system/risk/global_melt", summary="【管理端】更新全局熔断状态")
def update_global_melt_state(
        payload: RiskGlobalMeltInput,
        current_user: User = Depends(RBACChecker("admin:update")),
        db: Session = Depends(get_db)
):
    setting = db.query(RiskGlobalSetting).first()
    if not setting:
        setting = RiskGlobalSetting(is_melt=payload.is_active)
        db.add(setting)
    else:
        setting.is_melt = payload.is_active
    db.commit()
    return {
        "code": 200,
        "message": "全局熔断状态已更新",
        "data": {
            "is_active": setting.is_melt
        }
    }


@router.post("/system/risk/events", summary="【管理端】写入风控事件")
def create_risk_event(
        payload: RiskEventCreateInput,
        current_user: User = Depends(RBACChecker("admin:create")),
        db: Session = Depends(get_db)
):
    if payload.rule_id:
        rule = db.query(RiskRule).filter(RiskRule.id == payload.rule_id).first()
        if not rule:
            raise HTTPException(status_code=404, detail="规则不存在")

    event = RiskEvent(
        rule_id=payload.rule_id,
        action=payload.action.strip(),
        latency_ms=payload.latency_ms,
        ip=payload.ip,
        path=payload.path,
        risk_level=(payload.risk_level or "medium").strip()
    )
    db.add(event)
    db.commit()
    return {
        "code": 200,
        "message": "事件已记录"
    }

