from __future__ import annotations

import asyncio

import uvicorn

from app_factory import create_app
from utils.ssl_gen import ensure_ssl_certificates



def _is_benign_windows_connection_reset(context: dict[str, object]) -> bool:
    exc = context.get("exception")
    if isinstance(exc, ConnectionResetError) and getattr(exc, "winerror", None) == 10054:
        return True

    handle = context.get("handle")
    if handle is not None and "_call_connection_lost" in str(handle):
        if isinstance(exc, OSError) and getattr(exc, "winerror", None) == 10054:
            return True

    message = str(context.get("message", ""))
    return ("WinError 10054" in message) or ("ConnectionResetError" in message and "_call_connection_lost" in message)



def _asyncio_exception_handler(loop: asyncio.AbstractEventLoop, context: dict[str, object]) -> None:
    if _is_benign_windows_connection_reset(context):
        return
    loop.default_exception_handler(context)


async def _serve() -> None:
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_asyncio_exception_handler)

    cert_file = "./local_server.crt"
    key_file = "./local_server.key"

    ensure_ssl_certificates(cert_file, key_file)
    asgi_app = create_app()
    config = uvicorn.Config(
        asgi_app,
        host="0.0.0.0",
        port=8000,
        reload=False,
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(_serve())
