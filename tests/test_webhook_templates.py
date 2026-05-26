from __future__ import annotations

import json

from routers import webhook


def _sample_event_payload() -> dict:
    return {
        "event_id": "evt_xxx",
        "event_type": "auth.login",
        "sent_at": "2026-05-26 12:00:00",
        "payload": {
            "username": "alice",
            "group_id": 7,
            "ip": "114.66.48.61",
        },
    }


def test_parse_subscription_payload_supports_legacy_list() -> None:
    events, template_type, custom_template = webhook._parse_subscription_payload(
        json.dumps(["auth.login", "user.create"])
    )

    assert events == ["auth.login", "user.create"]
    assert template_type == webhook.WEBHOOK_TEMPLATE_ONAUTH_DEFAULT
    assert custom_template is None


def test_parse_subscription_payload_supports_template_object() -> None:
    raw = json.dumps(
        {
            "events": ["auth.login"],
            "template_type": webhook.WEBHOOK_TEMPLATE_FEISHU_TEXT,
            "custom_template": None,
        }
    )

    events, template_type, custom_template = webhook._parse_subscription_payload(raw)

    assert events == ["auth.login"]
    assert template_type == webhook.WEBHOOK_TEMPLATE_FEISHU_TEXT
    assert custom_template is None


def test_build_delivery_payload_wecom_markdown() -> None:
    payload = webhook._build_delivery_payload(
        webhook.WEBHOOK_TEMPLATE_WECOM_MARKDOWN,
        _sample_event_payload(),
        None,
    )

    assert isinstance(payload, dict)
    assert payload["msgtype"] == "markdown"
    assert "auth.login" in payload["markdown"]["content"]


def test_build_delivery_payload_wecom_template_card() -> None:
    payload = webhook._build_delivery_payload(
        webhook.WEBHOOK_TEMPLATE_WECOM_TEMPLATE_CARD,
        _sample_event_payload(),
        None,
    )

    assert isinstance(payload, dict)
    assert payload["msgtype"] == "template_card"
    assert payload["template_card"]["card_type"] == "text_notice"
    assert "auth.login" in payload["template_card"]["main_title"]["title"]


def test_build_delivery_payload_custom_json_with_placeholders() -> None:
    custom_template = json.dumps(
        {
            "msg_type": "text",
            "content": {
                "text": "事件: {event_type}; 用户: {payload_username}; IP: {payload_ip}",
            },
        },
        ensure_ascii=False,
    )

    payload = webhook._build_delivery_payload(
        webhook.WEBHOOK_TEMPLATE_CUSTOM_JSON,
        _sample_event_payload(),
        custom_template,
    )

    assert isinstance(payload, dict)
    text = payload["content"]["text"]
    assert "auth.login" in text
    assert "alice" in text
    assert "114.66.48.61" in text

