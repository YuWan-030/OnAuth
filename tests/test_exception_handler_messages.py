from __future__ import annotations

from middlewares.exception_handlers import _translate_validation_error


def test_translate_validation_error_uses_chinese_field_and_message() -> None:
    message = _translate_validation_error({
        "loc": ("body", "username"),
        "msg": "String should have at least 3 characters",
        "type": "string_too_short",
        "ctx": {"min_length": 3},
    })

    assert message == "用户名至少需要 3 个字符"
