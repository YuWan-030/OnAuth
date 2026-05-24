import json
import time
import hmac
import hashlib
import threading
import uuid
import os
import requests
from typing import List, Optional
from pydantic import BaseModel, HttpUrl
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db, WebhookConfig, WebhookLog, SessionLocal, User
from middlewares.rbac import RBACChecker

router = APIRouter(tags=["【系统集成】Webhook 异步回调事件中心"])

ALLOWED_EVENT_TYPES = {
    "auth.login",
    "user.create",
    "user.delete",
    "role.update",
    "tenant_admin.create",
    "tenant_user.invite",
    "tenant_space.apply",
    "tenant_space.toggle",
    "tenant_space.review",
    "tenant_space.assign",
    "tenant_app.create",
    "tenant_credential.create",
}

WEBHOOK_MAX_RETRIES = max(0, int(os.getenv("WEBHOOK_MAX_RETRIES", "2")))
WEBHOOK_RETRY_BACKOFF_SECONDS = max(1, int(os.getenv("WEBHOOK_RETRY_BACKOFF_SECONDS", "1")))


def _normalize_event_names(events: List[str]) -> List[str]:
    normalized = []
    seen = set()
    for raw in events or []:
        name = str(raw or "").strip()
        if not name:
            continue
        if name not in ALLOWED_EVENT_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"不支持的事件类型: {name}"
            )
        if name not in seen:
            normalized.append(name)
            seen.add(name)
    if not normalized:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="events 至少需要一个合法事件类型")
    return normalized


def _is_super_admin_user(user_obj: User | None) -> bool:
    if not user_obj:
        return False
    return any(role.name == "super_admin" for role in (user_obj.roles or []))


# ============================ 📋 Pydantic 传参校验拓扑 ============================

class WebhookCreateSchema(BaseModel):
    name: str
    url: HttpUrl
    secret: Optional[str] = None
    events: List[str]  # 例如: ["user.create", "user.delete"]
    is_active: Optional[bool] = True


class WebhookUpdateSchema(BaseModel):
    id: int
    name: Optional[str] = None
    url: Optional[HttpUrl] = None
    secret: Optional[str] = None
    events: Optional[List[str]] = None
    is_active: Optional[bool] = None


# ============================ 🔓 核心配置管理网关 (CRUD) ============================


@router.get("/api/v1/webhook/signature.spec", summary="【集成接口】Webhook 签名协议说明")
def webhook_signature_spec(current_user=Depends(RBACChecker("webhook:list", "admin:read"))):
    return {
        "status": "success",
        "data": {
            "algorithm": "HMAC-SHA256",
            "headers": {
                "X-OnAuth-Timestamp": "Unix 秒级时间戳",
                "X-OnAuth-Event": "事件类型",
                "X-OnAuth-Signature": "hex(hmac_sha256(secret, f'{timestamp}.{event_type}.' + raw_body))",
                "X-OnAuth-Signature-Alg": "hmac-sha256"
            },
            "notes": [
                "接收端应校验时间戳漂移（建议 <= 300 秒）",
                "仅在配置了 secret 时发送签名头"
            ]
        }
    }

@router.post("/api/v1/webhook/config.create", summary="【集成接口】注册全新 Webhook 订阅端点")
def create_webhook_config(
        payload: WebhookCreateSchema,
        db: Session = Depends(get_db),
        # 🌟 注入当前登录用户凭证（假设您的认证中间件返回的对象包含 id 和 username，如 current_user.id）
        current_user=Depends(RBACChecker("webhook:create", "admin:write"))
):
    normalized_events = _normalize_event_names(payload.events)
    events_str = json.dumps(normalized_events)

    # 获取当前操作人的物理 ID
    operator_id = getattr(current_user, 'id', None) or getattr(current_user, 'user_id', None)
    if not operator_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="安全风控拦截：无法提取合法的创建者身份凭证"
        )

    new_config = WebhookConfig(
        name=payload.name,
        url=str(payload.url),
        secret=payload.secret,
        events=events_str,
        is_active=payload.is_active,
        creator_id=operator_id  # 🌟 物理绑定：记录是谁创建的，此资产属于谁
    )

    try:
        db.add(new_config)
        db.commit()
        db.refresh(new_config)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库写入异常，订阅事务已回滚: {str(e)}"
        )

    return {
        "status": "success",
        "message": f"Webhook 订阅端点 [{new_config.name}] 已成功绑定至您的账户！",
        "data": {
            "id": new_config.id,
            "creator_id": new_config.creator_id
        }
    }


@router.post("/api/v1/webhook/config.update", summary="【集成接口】修调 Webhook 订阅配置细则")
def update_webhook_config(
        payload: WebhookUpdateSchema,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("webhook:update", "admin:write"))
):
    config = db.query(WebhookConfig).filter(WebhookConfig.id == payload.id).first()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"更新失败：未找到 ID 为 [{payload.id}] 的配置网格"
        )

    # 🔒 安全越权校验：非创建者本人（且非超级管理员）禁止修改
    operator_id = getattr(current_user, 'id', None) or getattr(current_user, 'user_id', None)
    is_admin = getattr(current_user, 'is_admin', False) or getattr(current_user, 'role_id', 0) == 1
    if config.creator_id != operator_id and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足：您不是该 Webhook 的创建者，无权修改此资产"
        )

    if payload.name is not None: config.name = payload.name
    if payload.url is not None: config.url = str(payload.url)
    if payload.secret is not None: config.secret = payload.secret
    if payload.is_active is not None: config.is_active = payload.is_active
    if payload.events is not None:
        config.events = json.dumps(_normalize_event_names(payload.events))

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据库更新异常: {str(e)}"
        )

    return {"status": "success", "message": f"Webhook 配置 [{config.name}] 已成功同步更新！"}


@router.get("/api/v1/webhook/config.list", summary="【集成接口】拉取 Webhook 订阅网格列表")
def list_webhook_configs(
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("webhook:list", "admin:read"))
):
    operator_id = getattr(current_user, 'id', None) or getattr(current_user, 'user_id', None)
    is_admin = getattr(current_user, 'is_admin', False) or getattr(current_user, 'role_id', 0) == 1

    # 👑 数据隔离策略：超级管理员可见全域 Webhook，普通租户/用户仅能看到属于自己的 Webhook
    if is_admin:
        configs = db.query(WebhookConfig).all()
    else:
        configs = db.query(WebhookConfig).filter(WebhookConfig.creator_id == operator_id).all()

    return {
        "status": "success",
        "data": [
            {
                "id": c.id,
                "name": c.name,
                "url": c.url,
                "secret": c.secret,
                "is_active": c.is_active,
                "creator_id": c.creator_id,  # 前端表格可据此展示归属人
                "events": json.loads(c.events) if c.events else []
            }
            for c in configs
        ]
    }


@router.delete("/api/v1/webhook/config.delete", summary="【集成接口】断开/注销 Webhook 订阅端点")
def delete_webhook_config(
        id: int,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("webhook:delete", "admin:write"))
):
    config = db.query(WebhookConfig).filter(WebhookConfig.id == id).first()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="删除失败：目标订阅端点不存在"
        )

    # 🔒 安全垂直越权拦截
    operator_id = getattr(current_user, 'id', None) or getattr(current_user, 'user_id', None)
    is_admin = getattr(current_user, 'is_admin', False) or getattr(current_user, 'role_id', 0) == 1
    if config.creator_id != operator_id and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="核心风控熔断：您无权物理清退不属于您的安全资产"
        )

    try:
        db.delete(config)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"数据粉碎异常: {str(e)}"
        )
    return {"status": "success", "message": f"您名下的订阅配置 [{config.name}] 已安全清退并粉碎！"}


@router.get("/api/v1/webhook/logs.list", summary="【审计接口】获取 Webhook 事件全维分发历史日志")
def list_webhook_logs(
        webhook_id: Optional[int] = None,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("webhook:logs", "admin:read"))
):
    operator_id = getattr(current_user, 'id', None) or getattr(current_user, 'user_id', None)
    is_admin = getattr(current_user, 'is_admin', False) or getattr(current_user, 'role_id', 0) == 1

    query = db.query(WebhookLog).join(WebhookConfig, WebhookLog.webhook_id == WebhookConfig.id)

    # 🔒 日志全维审计隔离：非超管只能看自己拥有的 Webhook 发送日志
    if not is_admin:
        query = query.filter(WebhookConfig.creator_id == operator_id)

    if webhook_id:
        query = query.filter(WebhookLog.webhook_id == webhook_id)

    logs = query.order_by(WebhookLog.created_at.desc()).limit(100).all()
    return {
        "status": "success",
        "data": [
            {
                "log_id": l.id,
                "webhook_id": l.webhook_id,
                "event_type": l.event_type,
                "payload": json.loads(l.payload) if l.payload else {},
                "response_body": l.response_body,
                "status_code": l.status_code,
                "is_success": l.is_success,
                "duration_ms": l.duration,
                "timestamp": l.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for l in logs
        ]
    }


# ============================ ⚡ 核心动力流：异步事件投递中心 ============================

def _async_http_post_worker(webhook_id: int, target_url: str, secret: Optional[str],
                            event_type: str, payload_data: dict, creator_id: int):
    """
    异步工作线程：发送 HTTP 请求并落盘审计日志
    """
    db = SessionLocal()
    payload_bytes = json.dumps(payload_data, ensure_ascii=False).encode('utf-8')
    timestamp = str(int(time.time()))

    headers = {"Content-Type": "application/json", "User-Agent": "OnAuth-Engine/1.0"}
    headers["X-OnAuth-Timestamp"] = timestamp
    headers["X-OnAuth-Event"] = event_type
    headers["X-OnAuth-Signature-Alg"] = "hmac-sha256"

    # 签名逻辑 (如果接收端支持 HMAC 验签)
    if secret:
        sign = hmac.new(secret.encode('utf-8'), f"{timestamp}.{event_type}.".encode('utf-8') + payload_bytes,
                        hashlib.sha256).hexdigest()
        headers["X-OnAuth-Signature"] = sign

    start_time = time.time()
    resp = None
    is_success = False
    response_text = ""
    status_code = 0
    try:
        for attempt in range(WEBHOOK_MAX_RETRIES + 1):
            try:
                resp = requests.post(target_url, data=payload_bytes, headers=headers, timeout=10)
                status_code = int(getattr(resp, "status_code", 0) or 0)
                is_success = 200 <= status_code < 300
                response_text = (resp.text or "")[:2000]
                if is_success:
                    break
                if attempt < WEBHOOK_MAX_RETRIES:
                    time.sleep(WEBHOOK_RETRY_BACKOFF_SECONDS * (attempt + 1))
            except Exception as e:
                response_text = f"Gateway Error: {str(e)}"
                status_code = 0
                if attempt < WEBHOOK_MAX_RETRIES:
                    time.sleep(WEBHOOK_RETRY_BACKOFF_SECONDS * (attempt + 1))
                else:
                    raise
    except Exception as e:
        is_success = False
        response_text = (response_text or f"Gateway Error: {str(e)}")[:2000]

    # 记录审计日志
    try:
        log = WebhookLog(
            webhook_id=webhook_id,
            event_type=event_type,
            payload=json.dumps(payload_data, ensure_ascii=False),
            response_body=response_text,
            status_code=status_code,
            is_success=is_success,
            duration=int((time.time() - start_time) * 1000),
            creator_id=creator_id  # 修复：确保 creator_id 不为空
        )
        db.add(log)
        db.commit()
    except Exception as e:
        print(f"[审计日志写入失败] {e}")
    finally:
        db.close()


def dispatch_webhook_event(event_type: str, payload: dict, db: Session):
    if event_type not in ALLOWED_EVENT_TYPES:
        return

    configs = db.query(WebhookConfig).filter(WebhookConfig.is_active == True).all()
    event_group_id = payload.get("group_id")
    creator_group_cache: dict[int, int | None] = {}
    creator_is_super_cache: dict[int, bool] = {}

    for config in configs:
        subscribed_events = json.loads(config.events) if config.events else []
        if event_type in subscribed_events:
            # 租户隔离：携带 group_id 的事件仅投递给同组创建者；super_admin 作为全局观察者可接收
            if event_group_id is not None:
                creator_id = int(config.creator_id)
                if creator_id not in creator_group_cache:
                    creator_user = db.query(User).filter(User.id == creator_id).first()
                    creator_group_cache[creator_id] = getattr(creator_user, "group_id", None)
                    creator_is_super_cache[creator_id] = _is_super_admin_user(creator_user)

                creator_group_id = creator_group_cache.get(creator_id)
                is_creator_super = creator_is_super_cache.get(creator_id, False)
                if not is_creator_super and str(creator_group_id) != str(event_group_id):
                    continue

            event_payload = {
                "event_id": f"evt_{uuid.uuid4().hex}",
                "event_type": event_type,
                "sent_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "payload": payload,
            }

            threading.Thread(
                target=_async_http_post_worker,
                args=(config.id, config.url, config.secret, event_type, event_payload, config.creator_id)
            ).start()