from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import secrets
import tempfile

from fastapi import HTTPException, UploadFile
from PIL import Image, UnidentifiedImageError

# 把图片解码后重新编码成 PNG，能有效剥离脚本、EXIF、polyglot 等风险内容
Image.MAX_IMAGE_PIXELS = 4_000_000

BASE_DIR = Path(__file__).resolve().parents[1]
APP_LOGO_DIR = BASE_DIR / "uploads" / "app_logos"
APP_LOGO_PUBLIC_PREFIX = "/uploads/app_logos"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_ICON_SIDE = 512
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}
ALLOWED_FORMATS = {"PNG", "JPEG", "JPG", "WEBP"}


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def ensure_uploaded_logo_reference(app_logo: str | None) -> str | None:
    """
    只允许引用由本系统上传接口生成的图标路径。
    这样可以避免把任意远程 URL 或可疑 data/javascript 片段直接写入数据库。
    """
    if not app_logo:
        return None

    value = app_logo.strip()
    if value.startswith(f"{APP_LOGO_PUBLIC_PREFIX}/") and value.lower().endswith(".png"):
        return value
    raise _bad_request("应用图标必须通过安全上传接口添加")


def save_app_logo_upload(upload_file: UploadFile) -> str:
    if not upload_file:
        raise _bad_request("未收到上传文件")

    content_type = (upload_file.content_type or "").lower().strip()
    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        raise _bad_request("仅支持上传 PNG、JPEG 或 WebP 图片")

    raw = upload_file.file.read(MAX_UPLOAD_BYTES + 1)
    if not raw:
        raise _bad_request("上传文件不能为空")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise _bad_request("图片大小不能超过 2MB")

    try:
        with Image.open(BytesIO(raw)) as image:
            image.load()
            fmt = (image.format or "").upper()
            if fmt not in ALLOWED_FORMATS:
                raise _bad_request("仅支持上传 PNG、JPEG 或 WebP 图片")

            if image.mode not in ("RGB", "RGBA"):
                image = image.convert("RGBA")

            image.thumbnail((MAX_ICON_SIDE, MAX_ICON_SIDE))

            if image.mode not in ("RGB", "RGBA"):
                image = image.convert("RGBA")

            output = BytesIO()
            image.save(output, format="PNG", optimize=True)
            output.seek(0)
    except UnidentifiedImageError as exc:
        raise _bad_request("上传内容不是有效图片") from exc
    except OSError as exc:
        raise _bad_request("图片处理失败，请重新上传") from exc

    APP_LOGO_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{secrets.token_hex(16)}.png"
    target_path = APP_LOGO_DIR / filename
    payload = output.getvalue()

    # 原子写入：先写临时文件，再 replace，避免进程崩溃留下半写入文件
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=str(APP_LOGO_DIR), suffix=".tmp") as tmp:
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = tmp.name
        os.replace(tmp_path, str(target_path))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return f"{APP_LOGO_PUBLIC_PREFIX}/{filename}"

