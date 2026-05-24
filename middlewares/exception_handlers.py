from __future__ import annotations

import logging

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from template_env import templates


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
    msg = f"参数校验失败: {errors[0]['loc'][-1]} - {errors[0]['msg']}" if errors else "参数校验失败"
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

