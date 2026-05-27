import json
import time
import hmac
import hashlib
import threading
import uuid
import os
import requests
from typing import Any, List, Optional
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

EVENT_TYPE_LABELS = {
    "auth.login": "用户登录",
    "user.create": "用户创建",
    "user.delete": "用户删除",
    "role.update": "角色更新",
    "tenant_admin.create": "租户管理员创建",
    "tenant_user.invite": "租户用户邀请",
    "tenant_space.apply": "租户空间申请",
    "tenant_space.toggle": "租户空间启停",
    "tenant_space.review": "租户空间审核",
    "tenant_space.assign": "租户空间分配",
    "tenant_app.create": "租户应用创建",
    "tenant_credential.create": "租户凭证签发",
}

WEBHOOK_MAX_RETRIES = max(0, int(os.getenv("WEBHOOK_MAX_RETRIES", "2")))
WEBHOOK_RETRY_BACKOFF_SECONDS = max(1, int(os.getenv("WEBHOOK_RETRY_BACKOFF_SECONDS", "1")))

WEBHOOK_TEMPLATE_ONAUTH_DEFAULT = "onauth_default"
WEBHOOK_TEMPLATE_WECOM_MARKDOWN = "wecom_markdown"
WEBHOOK_TEMPLATE_WECOM_TEMPLATE_CARD = "wecom_template_card"
WEBHOOK_TEMPLATE_DINGTALK_MARKDOWN = "dingtalk_markdown"
WEBHOOK_TEMPLATE_FEISHU_TEXT = "feishu_text"
WEBHOOK_TEMPLATE_CUSTOM_JSON = "custom_json"

DEFAULT_CUSTOM_JSON_TEMPLATE = {
    "msgtype": "markdown",
    "markdown": {
        "content": "**OnAuth 事件通知**\\n> 事件: `{event_display}`\\n> 时间: {sent_at}\\n> 明细:\\n{payload_lines}"
    }
}

PAYLOAD_FIELD_LABELS = {
    "user_id": "用户ID",
    "username": "用户名称",
    "ip_address": "IP",
    "ip": "IP",
    "browser": "浏览器",
    "os": "操作系统",
    "device_type": "终端类型",
    "entry_point": "入口",
    "login_at": "登录时间",
    "user_agent": "UA",
}

ALLOWED_TEMPLATE_TYPES = {
    WEBHOOK_TEMPLATE_ONAUTH_DEFAULT,
    WEBHOOK_TEMPLATE_WECOM_MARKDOWN,
    WEBHOOK_TEMPLATE_WECOM_TEMPLATE_CARD,
    WEBHOOK_TEMPLATE_DINGTALK_MARKDOWN,
    WEBHOOK_TEMPLATE_FEISHU_TEXT,
    WEBHOOK_TEMPLATE_CUSTOM_JSON,
}


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


def _normalize_template_type(template_type: Optional[str]) -> str:
    normalized = str(template_type or WEBHOOK_TEMPLATE_ONAUTH_DEFAULT).strip().lower()
    if normalized not in ALLOWED_TEMPLATE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"不支持的模板类型: {template_type}"
        )
    return normalized


def _validate_custom_template(template_type: str, custom_template: Optional[str]) -> Optional[str]:
    raw = (custom_template or "").strip()
    if template_type == WEBHOOK_TEMPLATE_CUSTOM_JSON:
        if not raw:
            return json.dumps(DEFAULT_CUSTOM_JSON_TEMPLATE, ensure_ascii=False)
        try:
            parsed = json.loads(raw)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="custom_template 必须是合法 JSON") from exc
        if not isinstance(parsed, (dict, list)):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="custom_template 顶层必须是 JSON 对象或数组")
        return raw
    return raw or None


def _parse_subscription_payload(events_raw: str | None) -> tuple[list[str], str, Optional[str]]:
    if not events_raw:
        return [], WEBHOOK_TEMPLATE_ONAUTH_DEFAULT, None
    try:
        parsed = json.loads(events_raw)
    except Exception:
        return [], WEBHOOK_TEMPLATE_ONAUTH_DEFAULT, None

    if isinstance(parsed, list):
        return [str(item) for item in parsed], WEBHOOK_TEMPLATE_ONAUTH_DEFAULT, None

    if isinstance(parsed, dict):
        events = parsed.get("events")
        events_list = [str(item) for item in events] if isinstance(events, list) else []
        try:
            template_type = _normalize_template_type(parsed.get("template_type"))
        except HTTPException:
            template_type = WEBHOOK_TEMPLATE_ONAUTH_DEFAULT
        custom_template = (str(parsed.get("custom_template") or "").strip() or None)
        return events_list, template_type, custom_template

    return [], WEBHOOK_TEMPLATE_ONAUTH_DEFAULT, None


def _build_subscription_payload(events: list[str], template_type: str, custom_template: Optional[str]) -> str:
    return json.dumps(
        {
            "events": events,
            "template_type": template_type,
            "custom_template": custom_template,
        },
        ensure_ascii=False,
    )


def _event_display_name(event_type: str) -> str:
    return EVENT_TYPE_LABELS.get(event_type, event_type)


def _event_template_context(event_payload: dict[str, Any]) -> dict[str, str]:
    payload = event_payload.get("payload") if isinstance(event_payload.get("payload"), dict) else {}
    event_type = str(event_payload.get("event_type") or "")
    event_name = _event_display_name(event_type)
    payload_lines = format_payload_to_human_lines(payload)
    context = {
        "event_id": str(event_payload.get("event_id") or ""),
        "event_type": event_type,
        "event_name": event_name,
        "event_display": f"{event_name} ({event_type})" if event_type else event_name,
        "sent_at": str(event_payload.get("sent_at") or ""),
        "payload_json": json.dumps(payload, ensure_ascii=False),
        "payload_lines": payload_lines,
    }
    for key, value in payload.items():
        context[f"payload_{key}"] = "" if value is None else str(value)
    return context


class _SafeFormatDict(dict):
    def __missing__(self, key):
        return "{" + str(key) + "}"


def _render_template_value(raw: Any, context: dict[str, str]) -> Any:
    if isinstance(raw, str):
        return raw.format_map(_SafeFormatDict(context))
    if isinstance(raw, list):
        return [_render_template_value(item, context) for item in raw]
    if isinstance(raw, dict):
        return {str(key): _render_template_value(value, context) for key, value in raw.items()}
    return raw


def _format_payload_markdown_lines(payload_obj: dict[str, Any]) -> str:
    text = format_payload_to_human_lines(payload_obj)
    if not text:
        return "- (empty)"
    return "\n".join(f"- {line}" for line in text.split("\n") if line)


def format_payload_to_human_lines(payload_obj: dict[str, Any]) -> str:
    """把 payload JSON 转成多行可读文本（中文字段名优先）。"""
    if not isinstance(payload_obj, dict):
        return ""

    lines: list[str] = []
    for key, value in payload_obj.items():
        display_key = PAYLOAD_FIELD_LABELS.get(str(key), str(key))
        if isinstance(value, (dict, list)):
            text_value = json.dumps(value, ensure_ascii=False)
        else:
            text_value = "" if value is None else str(value)
        lines.append(f"{display_key}: {text_value}")
    return "\n".join(lines)


def _build_delivery_payload(
    template_type: str,
    event_payload: dict[str, Any],
    custom_template: Optional[str],
) -> dict[str, Any] | list[Any]:
    context = _event_template_context(event_payload)
    event_type = context.get("event_type", "")
    event_display = context.get("event_display", event_type)
    sent_at = context.get("sent_at", "")
    payload_lines = context.get("payload_lines", "")
    payload_obj = event_payload.get("payload") if isinstance(event_payload.get("payload"), dict) else {}

    if template_type == WEBHOOK_TEMPLATE_WECOM_MARKDOWN:
        markdown_lines = _format_payload_markdown_lines(payload_obj)
        content = (
            f"**OnAuth 事件通知**\n"
            f"> 事件: `{event_display}`\n"
            f"> 时间: {sent_at}\n"
            f"> 明细:\n"
            f"> {markdown_lines.replace(chr(10), chr(10) + '> ')}"
        )
        return {"msgtype": "markdown", "markdown": {"content": content}}

    if template_type == WEBHOOK_TEMPLATE_WECOM_TEMPLATE_CARD:
        detail_items = []
        for key, value in payload_obj.items():
            if value is None:
                continue
            detail_items.append({"keyname": str(key), "value": str(value)})
            if len(detail_items) >= 6:
                break

        return {
            "msgtype": "template_card",
            "template_card": {
                "card_type": "text_notice",
                "source": {
                    "icon_url": "https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/wechat.svg",
                    "desc": "OnAuth",
                    "desc_color": 0,
                },
                "main_title": {
                    "title": f"OnAuth 事件: {event_display}",
                    "desc": f"发送时间: {sent_at}",
                },
                "emphasis_content": {
                    "title": event_type or "unknown",
                    "desc": "事件类型",
                },
                "sub_title_text": payload_lines or "-",
                "horizontal_content_list": detail_items,
                "jump_list": [
                    {
                        "type": 1,
                        "url": "https://8.8.8.8/audit",
                        "title": "打开审计页面"
                    }
                ],
                "card_action": {
                    "type": 1,
                    "url": "https://localhost:8000/system/callbacks",
                },
            },
        }

    if template_type == WEBHOOK_TEMPLATE_DINGTALK_MARKDOWN:
        text = (
            f"### OnAuth 事件通知\n"
            f"- 事件: `{event_display}`\n"
            f"- 时间: {sent_at}\n"
            f"- 明细:\n{_format_payload_markdown_lines(payload_obj)}"
        )
        return {
            "msgtype": "markdown",
            "markdown": {
                "title": f"OnAuth {event_display}",
                "text": text,
            },
        }

    if template_type == WEBHOOK_TEMPLATE_FEISHU_TEXT:
        text = f"OnAuth 事件 {event_display}\n时间: {sent_at}\n明细:\n{payload_lines}"
        return {"msg_type": "text", "content": {"text": text}}

    if template_type == WEBHOOK_TEMPLATE_CUSTOM_JSON:
        try:
            raw_obj = json.loads(custom_template or "{}")
        except Exception:
            raw_obj = {"msg": "invalid custom_template", "event": event_payload}
        rendered = _render_template_value(raw_obj, context)
        return rendered if isinstance(rendered, (dict, list)) else {"message": str(rendered)}

    return {
        "event_id": context.get("event_id", ""),
        "event_type": event_type,
        "event_name": context.get("event_name", event_type),
        "event_display": event_display,
        "sent_at": sent_at,
        "payload": payload_obj,
        "payload_lines": payload_lines,
    }


# ============================ 📋 Pydantic 传参校验拓扑 ============================

class WebhookCreateSchema(BaseModel):
    name: str
    url: HttpUrl
    secret: Optional[str] = None
    events: List[str]  # 例如: ["user.create", "user.delete"]
    is_active: Optional[bool] = True
    template_type: Optional[str] = WEBHOOK_TEMPLATE_ONAUTH_DEFAULT
    custom_template: Optional[str] = None


class WebhookUpdateSchema(BaseModel):
    id: int
    name: Optional[str] = None
    url: Optional[HttpUrl] = None
    secret: Optional[str] = None
    events: Optional[List[str]] = None
    is_active: Optional[bool] = None
    template_type: Optional[str] = None
    custom_template: Optional[str] = None


class WebhookTestPushSchema(BaseModel):
    id: int
    event_type: Optional[str] = None
    payload: Optional[dict[str, Any]] = None


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
    template_type = _normalize_template_type(payload.template_type)
    custom_template = _validate_custom_template(template_type, payload.custom_template)
    events_str = _build_subscription_payload(normalized_events, template_type, custom_template)

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


@router.get("/api/v1/webhook/template.options", summary="【集成接口】Webhook 模板类型选项")
def list_webhook_template_options(current_user=Depends(RBACChecker("webhook:list", "admin:read"))):
    event_options = [
        {"value": event_type, "label": _event_display_name(event_type)}
        for event_type in sorted(ALLOWED_EVENT_TYPES)
    ]
    return {
        "status": "success",
        "data": [
            {"value": WEBHOOK_TEMPLATE_ONAUTH_DEFAULT, "label": "OnAuth 默认 JSON"},
            {"value": WEBHOOK_TEMPLATE_WECOM_MARKDOWN, "label": "企业微信 Markdown"},
            {"value": WEBHOOK_TEMPLATE_WECOM_TEMPLATE_CARD, "label": "企业微信 文本通知模板卡片"},
            {"value": WEBHOOK_TEMPLATE_DINGTALK_MARKDOWN, "label": "钉钉 Markdown"},
            {"value": WEBHOOK_TEMPLATE_FEISHU_TEXT, "label": "飞书 Text"},
            {"value": WEBHOOK_TEMPLATE_CUSTOM_JSON, "label": "自定义 JSON 模板"},
        ],
        "event_labels": EVENT_TYPE_LABELS,
        "event_options": event_options,
        "notes": {
            "custom_json": "使用 {event_type} / {event_name} / {event_display} / {sent_at} / {payload_json} / {payload_lines} 以及 {payload_xxx} 占位符",
            "wecom_template_card": "企业微信文本通知模板卡片，适合移动端高可读提醒"
        }
    }


@router.post("/api/v1/webhook/test.push", summary="【集成接口】测试推送单个 Webhook 端点")
def test_push_webhook(
        payload: WebhookTestPushSchema,
        db: Session = Depends(get_db),
        current_user=Depends(RBACChecker("webhook:update", "admin:write"))
):
    config = db.query(WebhookConfig).filter(WebhookConfig.id == payload.id).first()
    if not config:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="测试失败：目标 Webhook 不存在")

    operator_id = getattr(current_user, 'id', None) or getattr(current_user, 'user_id', None)
    is_admin = getattr(current_user, 'is_admin', False) or getattr(current_user, 'role_id', 0) == 1
    if config.creator_id != operator_id and not is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="权限不足：无法测试不属于您的 Webhook")

    subscribed_events, template_type, custom_template = _parse_subscription_payload(config.events)
    event_type = str(payload.event_type or "").strip()
    if not event_type:
        event_type = subscribed_events[0] if subscribed_events else "auth.login"
    if event_type not in ALLOWED_EVENT_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"不支持的测试事件类型: {event_type}")

    event_payload = {
        "event_id": f"evt_test_{uuid.uuid4().hex}",
        "event_type": event_type,
        "sent_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "payload": {
            "test": True,
            "message": "This is a test push from OnAuth",
            "operator": getattr(current_user, "username", "unknown"),
            "webhook_name": config.name,
            **(payload.payload or {}),
        },
    }

    threading.Thread(
        target=_async_http_post_worker,
        args=(
            config.id,
            config.url,
            config.secret,
            event_type,
            event_payload,
            config.creator_id,
            template_type,
            custom_template,
        )
    ).start()

    return {
        "status": "success",
        "message": f"测试推送已发起，事件 [{event_type}] 正在投递",
        "data": {
            "webhook_id": config.id,
            "event_type": event_type,
            "template_type": template_type,
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
    current_events, current_template_type, current_custom_template = _parse_subscription_payload(config.events)

    next_events = current_events
    if payload.events is not None:
        next_events = _normalize_event_names(payload.events)

    next_template_type = current_template_type
    if payload.template_type is not None:
        next_template_type = _normalize_template_type(payload.template_type)

    next_custom_template = current_custom_template
    if payload.custom_template is not None:
        next_custom_template = payload.custom_template

    if (payload.events is not None) or (payload.template_type is not None) or (payload.custom_template is not None):
        validated_custom_template = _validate_custom_template(next_template_type, next_custom_template)
        config.events = _build_subscription_payload(next_events, next_template_type, validated_custom_template)

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

    data = []
    for c in configs:
        events, template_type, custom_template = _parse_subscription_payload(c.events)
        data.append(
            {
                "id": c.id,
                "name": c.name,
                "url": c.url,
                "secret": c.secret,
                "is_active": c.is_active,
                "creator_id": c.creator_id,
                "events": events,
                "template_type": template_type,
                "custom_template": custom_template,
            }
        )

    return {
        "status": "success",
        "data": data
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
                            event_type: str, payload_data: dict, creator_id: int,
                            template_type: str = WEBHOOK_TEMPLATE_ONAUTH_DEFAULT,
                            custom_template: Optional[str] = None):
    """
    异步工作线程：发送 HTTP 请求并落盘审计日志
    """
    db = SessionLocal()
    delivery_payload = _build_delivery_payload(template_type, payload_data, custom_template)
    payload_bytes = json.dumps(delivery_payload, ensure_ascii=False).encode('utf-8')
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
            payload=json.dumps(delivery_payload, ensure_ascii=False),
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
        subscribed_events, template_type, custom_template = _parse_subscription_payload(config.events)
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
                args=(
                    config.id,
                    config.url,
                    config.secret,
                    event_type,
                    event_payload,
                    config.creator_id,
                    template_type,
                    custom_template,
                )
            ).start()