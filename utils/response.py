from typing import Any
from fastapi.responses import JSONResponse

def unified_response(
    status_code: int = 200,
    status: str = "success",
    code: int = 20000,
    message: str = "操作成功",
    data: Any = None
) -> JSONResponse:
    """
    中台统一标准响应包装器
    """
    return JSONResponse(
        status_code=status_code,
        content={
            "status": status,      # "success" 或 "fail"
            "code": code,          # 内部自定义业务状态码
            "message": message,    # 返回给前端的友好提示信息
            "data": data           # 核心业务数据载荷，无数据时为 None
        }
    )


def unified_paged_response(
    data: list[Any],
    count: int,
    page: int = 1,
    limit: int = 20,
    status_code: int = 200,
    message: str = "操作成功",
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "success",
            "code": 20000,
            "message": message,
            "count": int(count),
            "page": int(page),
            "limit": int(limit),
            "data": data,
        },
    )


def unified_error_response(
    message: str,
    status_code: int = 400,
    code: int | None = None,
    detail: Any = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "fail",
            "code": int(code if code is not None else status_code * 100),
            "message": message,
            "detail": detail,
            "data": None,
        },
    )
