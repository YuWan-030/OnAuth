import json
import time
import hmac
import hashlib
import threading
import requests
from typing import List, Optional
from pydantic import BaseModel, HttpUrl
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db, WebhookConfig, WebhookLog, SessionLocal
from middlewares.rbac import RBACChecker

router = APIRouter(tags=["【系统集成】Webhook 异步回调事件中心"])


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

@router.post("/api/v1/webhook/config.create", summary="【集成接口】注册全新 Webhook 订阅端点")
def create_webhook_config(
        payload: WebhookCreateSchema,
        db: Session = Depends(get_db),
        # 🌟 注入当前登录用户凭证（假设您的认证中间件返回的对象包含 id 和 username，如 current_user.id）
        current_user=Depends(RBACChecker("webhook:create", "admin:write"))
):
    events_str = json.dumps(payload.events)

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
    if payload.events is not None: config.events = json.dumps(payload.events)

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
    # 将字典转为符合微信规范的 JSON
    payload_bytes = json.dumps(payload_data, ensure_ascii=False).encode('utf-8')
    timestamp = str(int(time.time()))

    headers = {"Content-Type": "application/json", "User-Agent": "OnAuth-Engine/1.0"}

    # 签名逻辑 (如果接收端支持 HMAC 验签)
    if secret:
        sign = hmac.new(secret.encode('utf-8'), f"{timestamp}.".encode('utf-8') + payload_bytes,
                        hashlib.sha256).hexdigest()
        headers["X-OnAuth-Signature"] = sign

    start_time = time.time()
    try:
        resp = requests.post(target_url, data=payload_bytes, headers=headers, timeout=10)
        is_success = 200 <= resp.status_code < 300
        response_text = resp.text[:2000]
    except Exception as e:
        is_success = False
        response_text = f"Gateway Error: {str(e)}"

    # 记录审计日志
    try:
        log = WebhookLog(
            webhook_id=webhook_id,
            event_type=event_type,
            payload=json.dumps(payload_data, ensure_ascii=False),
            response_body=response_text,
            status_code=getattr(resp, 'status_code', 0),
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
    configs = db.query(WebhookConfig).filter(WebhookConfig.is_active == True).all()

    for config in configs:
        subscribed_events = json.loads(config.events) if config.events else []
        if event_type in subscribed_events:
            # 严格按照你提供的标准格式进行构造
            wechat_payload = {
                "touser": "@all",
                "msgtype": "template_card",
                "template_card": {
                    "card_type": "text_notice",
                    "source": {
                        "icon_url": "https://wework.qpic.cn/wwpic/252813_jOfDHtcISzuodLa_1629280209/0",
                        "desc": "OnAuth 安全中台",
                        "desc_color": 0
                    },
                    "main_title": {
                        "title": "系统事件提醒",
                        "desc": f"触发事件: {event_type}"
                    },
                    "emphasis_content": {
                        "title": "重要",
                        "desc": "事件级别"
                    },
                    "quote_area": {
                        "type": 1,
                        "url": "https://work.weixin.qq.com/",
                        "title": "事件审计详情",
                        "quote_text": f"用户: {payload.get('username')}\nIP: {payload.get('ip_address')}"
                    },
                    "sub_title_text": "系统已捕获该动作，请注意防范风险。",
                    "horizontal_content_list": [
                        {"keyname": "触发时间", "value": time.strftime("%Y-%m-%d %H:%M:%S")},
                        {"keyname": "操作入口", "value": payload.get('entry_point', '未知')},
                        {"keyname": "User ID", "value": str(payload.get('user_id', ''))}
                    ],
                    "jump_list": [
                        {"type": 1, "url": "https://onauth.com/logs", "title": "查看审计日志"}
                    ],
                    "card_action": {
                        "type": 1,
                        "url": "https://onauth.com"
                    }
                }
            }

            threading.Thread(
                target=_async_http_post_worker,
                args=(config.id, config.url, config.secret, event_type, wechat_payload, config.creator_id)
            ).start()