from __future__ import annotations

from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, Field


T = TypeVar("T")


class ErrorResponse(BaseModel):
    code: int = Field(..., description="业务错误码")
    message: str = Field(..., description="错误信息")
    detail: Optional[str] = Field(None, description="详细错误说明")


class PaginationSchema(BaseModel):
    page: int = Field(1, ge=1, description="当前页")
    limit: int = Field(20, ge=1, le=500, description="每页条数")
    count: int = Field(0, ge=0, description="总记录数")


class PageResponseSchema(BaseModel, Generic[T]):
    code: int = Field(200, description="响应码")
    message: str = Field("success", description="响应消息")
    pagination: PaginationSchema
    data: list[T]


class DataResponseSchema(BaseModel, Generic[T]):
    code: int = Field(200, description="响应码")
    message: str = Field("success", description="响应消息")
    data: T


class OAuthTokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    scope: str


class OAuthIntrospectResponseSchema(BaseModel):
    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    token_type: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    iss: Optional[str] = None
    sub: Optional[str] = None


class GenericDictResponseSchema(BaseModel):
    code: int = 200
    message: str = "success"
    data: dict[str, Any] = Field(default_factory=dict)

