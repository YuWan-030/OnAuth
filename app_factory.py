from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from bootstrap import bootstrap_system
from middlewares.exception_handlers import register_exception_handlers
from middlewares.operation_log import operation_log_middleware
from routers import admin, auth_user, business, oauth, permission, system_api, tenant, webhook, invite_admin
from routers.views import router as views_router
from template_env import APP_LOGO_DIR


def create_app() -> FastAPI:
    app = FastAPI(title="企业级标准 OAuth2.0 & License 双轨制融合鉴权平台", docs_url="/docs", redoc_url=None)

    app.mount("/uploads/app_logos", StaticFiles(directory=APP_LOGO_DIR), name="app_logos")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "https://localhost:8000", "https://127.0.0.1:8000",
            "https://localhost:8080", "https://127.0.0.1:8080",
            "https://localhost:8081", "https://127.0.0.1:8081",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.middleware("http")(operation_log_middleware)
    register_exception_handlers(app)

    app.include_router(oauth.router)
    app.include_router(business.router)
    app.include_router(admin.router)
    app.include_router(auth_user.router)
    app.include_router(permission.router)
    app.include_router(webhook.router)
    app.include_router(invite_admin.router)
    app.include_router(tenant.router)
    app.include_router(system_api.router)
    app.include_router(views_router)

    return app


bootstrap_system()
app = create_app()

