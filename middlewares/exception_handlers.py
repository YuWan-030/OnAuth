from __future__ import annotations

import logging

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from template_env import templates


FIELD_LABELS = {
    "username": "用户名",
    "password": "密码",
    "repassword": "确认密码",
    "nickname": "昵称",
    "group_name": "租户空间名称",
    "group_description": "租户空间说明",
    "group_code": "租户空间识别码",
    "invite_code": "邀请码",
    "invite_token": "邀请链接令牌",
    "client_id": "Client ID",
    "redirect_uri": "回调地址",
}


def _field_label(loc: object) -> str:
    if isinstance(loc, (list, tuple)) and loc:
        field = str(loc[-1])
    else:
        field = str(loc or "")
    return FIELD_LABELS.get(field, field or "参数")


def _translate_validation_error(error: dict) -> str:
    field = _field_label(error.get("loc"))
    err_type = str(error.get("type") or "")
    msg = str(error.get("msg") or "格式不合法")
    ctx = error.get("ctx") if isinstance(error.get("ctx"), dict) else {}

    min_length = ctx.get("min_length")
    max_length = ctx.get("max_length")
    if err_type.endswith("string_too_short") or "at least" in msg:
        return f"{field}至少需要 {min_length or ''} 个字符".replace("  ", " ").strip()
    if err_type.endswith("string_too_long") or "at most" in msg:
        return f"{field}最多允许 {max_length or ''} 个字符".replace("  ", " ").strip()
    if err_type.endswith("missing") or "Field required" in msg:
        return f"{field}不能为空"
    if err_type.endswith("int_parsing"):
        return f"{field}必须是整数"
    if err_type.endswith("bool_parsing"):
        return f"{field}必须是布尔值"

    return f"{field}: {msg}"


async def handle_error_response(request: Request, status_code: int, detail: str):
    accept_header = request.headers.get("accept", "")
    requested_with = request.headers.get("x-requested-with", "")

    is_browser_page_request = "text/html" in accept_header and "application/json" not in accept_header
    if requested_with == "XMLHttpRequest":
        is_browser_page_request = False

    if is_browser_page_request:
        return templates.TemplateResponse(
            request=request,
            name="shared/error.html",
            context={"request": request, "status_code": status_code, "detail": detail},
            status_code=status_code,
        )

    return JSONResponse(
        status_code=status_code,
        content={
            "status": "fail",
            "code": status_code * 100,
            "message": detail,
            "data": None,
        },
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    msg = "参数校验失败: " + "；".join(_translate_validation_error(error) for error in errors[:3]) if errors else "参数校验失败"
    return await handle_error_response(request, 400, msg)


async def global_http_exception_handler(request: Request, exc: StarletteHTTPException):
    detail = "您访问的中台核心路由不存在，请核对接口文档！" if exc.status_code == 404 else str(exc.detail)
    return await handle_error_response(request, exc.status_code, detail)


async def global_generic_exception_handler(request: Request, exc: Exception):
    logging.error(f"🚨 中台核心严重崩溃: {str(exc)}", exc_info=True)
    return await handle_error_response(request, 500, "中台系统执行遭遇阻断，请联系管理员核查日志！")


def register_exception_handlers(app):
    app.exception_handler(RequestValidationError)(validation_exception_handler)
    app.exception_handler(HTTPException)(global_http_exception_handler)
    app.exception_handler(StarletteHTTPException)(global_http_exception_handler)
    app.exception_handler(Exception)(global_generic_exception_handler)

