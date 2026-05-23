import base64
import random
import secrets
import string
from typing import Tuple


def _random_code(length: int = 4) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _render_svg(code: str) -> str:
    width = 120
    height = 40
    chars = "".join(
        f"<text x='{15 + i * 24}' y='26' font-size='20' fill='#1f2937' "
        f"font-family='Arial' font-weight='700'>{ch}</text>"
        for i, ch in enumerate(code)
    )
    lines = "".join(
        f"<line x1='{random.randint(0, width)}' y1='{random.randint(0, height)}' "
        f"x2='{random.randint(0, width)}' y2='{random.randint(0, height)}' "
        f"stroke='#cbd5f5' stroke-width='1'/>"
        for _ in range(4)
    )
    svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' "
        f"width='{width}' height='{height}' viewBox='0 0 {width} {height}'>"
        "<rect width='100%' height='100%' fill='#f8fafc' rx='6' ry='6'/>"
        f"{lines}{chars}</svg>"
    )
    return svg


def issue_captcha(redis_client, ttl_seconds: int = 300) -> Tuple[str, str]:
    token = secrets.token_hex(8)
    code = _random_code(4)
    redis_client.setex(f"captcha:{token}", ttl_seconds, code.lower())
    svg = _render_svg(code)
    encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return token, f"data:image/svg+xml;base64,{encoded}"


def verify_captcha(redis_client, token: str | None, code: str | None) -> bool:
    if not token or not code:
        return False
    key = f"captcha:{token}"
    stored = redis_client.get(key)
    if not stored:
        return False
    if stored.strip().lower() != code.strip().lower():
        return False
    redis_client.delete(key)
    return True

