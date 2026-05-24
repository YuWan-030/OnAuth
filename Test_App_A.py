from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse

import flet as ft
import requests
import urllib3

# 关闭客户端自签名证书未验证的红色警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_BACKEND_URL = "https://127.0.0.1:8000"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:8990/callback"

# 回调与告警桥接：由主线程在启动时注入
CODE_CAPTURE_HANDLER: Callable[[str], None] | None = None
ALARM_HANDLER: Callable[[str], None] | None = None


def set_event_handlers(code_handler: Callable[[str], None] | None, alarm_handler: Callable[[str], None] | None) -> None:
    global CODE_CAPTURE_HANDLER, ALARM_HANDLER
    CODE_CAPTURE_HANDLER = code_handler
    ALARM_HANDLER = alarm_handler


def notify_code_captured(code: str) -> None:
    handler = CODE_CAPTURE_HANDLER or (lambda _code: None)
    handler(code)


def notify_alarm(message: str) -> None:
    handler = ALARM_HANDLER or (lambda _msg: None)
    handler(message)


class CallbackHandler(BaseHTTPRequestHandler):
    """本地轻量级回调 HTTP 监听器"""

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if parsed.path not in {"/callback", ""}:
            self.send_response(204)
            self.end_headers()
            return

        query_components = parse_qs(parsed.query)
        code = (query_components.get("code") or [""])[0].strip()
        if code:
            notify_code_captured(code)
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            html = """
            <html>
                <body style="font-family: 'Segoe UI', Arial; text-align: center; padding-top: 60px; background: #0f172a; color: #cbd5e1;">
                    <h2 style="color: #22c55e;">✅ PKCE 授权码拦截成功！</h2>
                    <p style="color: #94a3b8;">动态授权码（Code）已成功向本地回环网络投递。现在可以关闭此窗口并返回测试桩客户端。</p>
                </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
            return

        notify_alarm(f"回调收到无效请求：{self.path}，缺少 code 参数")
        self.send_response(400)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write("<html><body><h3>Bad Request: missing code</h3></body></html>".encode("utf-8"))

    def log_message(self, format, *args):
        return


class ThreadedHTTPServer(HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# ==========================================================================
# 🛠️ PKCE 核心加密算法套件
# ==========================================================================
def generate_pkce_verifier() -> str:
    """生成合规的 43~128 位高强度 code_verifier 原始随机串"""
    token = os.urandom(32)
    raw_verifier = base64.urlsafe_b64encode(token).decode("utf-8")
    verifier = re.sub(r"[^a-zA-Z0-9_.-]", "", raw_verifier)
    return verifier[:128]


def generate_pkce_challenge(verifier: str) -> str:
    """通过 SHA256 哈希计算出对应的 code_challenge 挑战码 (S256 模式)"""
    sha256_hash = hashlib.sha256(verifier.encode("utf-8")).digest()
    b64_encoded = base64.urlsafe_b64encode(sha256_hash).decode("utf-8")
    return b64_encoded.replace("=", "")


def safe_json_message(response: requests.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            for key in ("message", "detail", "error"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            return json.dumps(payload, ensure_ascii=False)
    except Exception:
        pass
    text = (response.text or "").strip()
    return text or "空响应"


def build_auth_url(backend_url: str, redirect_uri: str, client_id: str, scope: str, state: str, challenge: str) -> str:
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{backend_url.rstrip('/')}/oauth/authorize?{query}"


def main(page: ft.Page):
    page.title = "OnAuth 标准测试软件 - OAuth 2.0 + PKCE"
    page.window.width = 1120
    page.window.height = 980
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 20
    page.scroll = ft.ScrollMode.AUTO
    page.theme = ft.Theme(font_family="Microsoft YaHei")

    server: HTTPServer | None = None
    server_thread: threading.Thread | None = None
    server_port: int | None = None
    alarm_count = 0
    log_lines: list[str] = []
    last_alarm = "暂无"
    current_flow: dict[str, str] = {
        "backend_url": DEFAULT_BACKEND_URL,
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "client_id": "",
        "client_secret": "",
        "scope": "read",
        "verifier": "",
        "challenge": "",
    }

    # UI 输入区
    backend_url_input = ft.TextField(label="Backend URL", value=DEFAULT_BACKEND_URL, expand=True)
    redirect_uri_input = ft.TextField(label="Redirect URI", value=DEFAULT_REDIRECT_URI, expand=True)
    client_id_input = ft.TextField(label="Client ID", value="", hint_text="从中台签发的公有客户端识别码", expand=True)
    client_secret_input = ft.TextField(
        label="Client Secret（可选）",
        value="",
        password=True,
        can_reveal_password=True,
        hint_text="若后端强制校验机密客户端请填写",
        expand=True,
    )
    scope_input = ft.TextField(label="Scope", value="read", width=180)

    # 状态与结果区
    status_text = ft.Text("等待就绪。请先填写 Client ID 后启动测试。", color=ft.Colors.BLUE_GREY_300, size=13)
    alarm_badge = ft.Text("0", color=ft.Colors.RED_300, size=18, weight=ft.FontWeight.BOLD)
    last_alarm_text = ft.Text("暂无", color=ft.Colors.RED_200, size=12)
    loading_progress = ft.ProgressBar(visible=False, color=ft.Colors.BLUE_400)

    verifier_display = ft.TextField(
        label="PKCE Code Verifier",
        read_only=True,
        value="-",
        text_style=ft.TextStyle(color=ft.Colors.AMBER_300, font_family="monospace"),
        expand=True,
    )
    challenge_display = ft.TextField(
        label="PKCE Code Challenge (S256)",
        read_only=True,
        value="-",
        text_style=ft.TextStyle(color=ft.Colors.CYAN_300, font_family="monospace"),
        expand=True,
    )
    code_display = ft.TextField(label="授权码 Code", read_only=True, value="-", expand=True)
    access_token_display = ft.TextField(label="Access Token", read_only=True, value="-", multiline=True, min_lines=2, max_lines=3, expand=True)
    refresh_token_display = ft.TextField(label="Refresh Token", read_only=True, value="-", multiline=True, min_lines=2, max_lines=3, expand=True)
    expires_display = ft.Text("", color=ft.Colors.GREEN_400, size=12)

    log_console = ft.TextField(
        label="运行日志 / 告警输出",
        value="",
        multiline=True,
        read_only=True,
        min_lines=18,
        max_lines=24,
        expand=True,
        text_style=ft.TextStyle(font_family="monospace", size=12),
    )

    def render_log() -> None:
        log_console.value = "\n".join(log_lines[-400:])

    def emit(level: str, msg: str, alarm: bool = False) -> None:
        nonlocal alarm_count, last_alarm
        ts = time.strftime("%H:%M:%S")
        icon = {"INFO": "ℹ️", "OK": "✅", "WARN": "⚠️", "ALARM": "🚨"}.get(level, "•")
        line = f"[{ts}] {icon} [{level}] {msg}"
        log_lines.append(line)
        render_log()

        status_text.value = msg
        status_text.color = {
            "INFO": ft.Colors.BLUE_GREY_300,
            "OK": ft.Colors.GREEN_400,
            "WARN": ft.Colors.ORANGE_300,
            "ALARM": ft.Colors.RED_400,
        }.get(level, ft.Colors.BLUE_GREY_300)

        if alarm or level == "ALARM":
            alarm_count += 1
            last_alarm = msg
            alarm_badge.value = str(alarm_count)
            last_alarm_text.value = last_alarm
        page.update()

    def emit_info(msg: str) -> None:
        emit("INFO", msg)

    def emit_ok(msg: str) -> None:
        emit("OK", msg)

    def emit_warn(msg: str) -> None:
        emit("WARN", msg, alarm=True)

    def emit_alarm(msg: str) -> None:
        emit("ALARM", msg, alarm=True)

    def stop_callback_server(silent: bool = False) -> None:
        nonlocal server, server_thread, server_port
        if server is None:
            if not silent:
                emit_info("本地回调服务器当前未运行。")
            return

        try:
            server.shutdown()
            server.server_close()
        except Exception as ex:
            emit_alarm(f"停止本地回调服务器失败：{ex}")
            return
        finally:
            server = None
            server_thread = None
            server_port = None

        if not silent:
            emit_ok("本地回调服务器已停止。")

    def start_callback_server(port: int) -> bool:
        nonlocal server, server_thread, server_port
        if server is not None:
            if server_port == port:
                emit_info(f"本地回调服务器已在 127.0.0.1:{port} 运行。")
                return True
            stop_callback_server(silent=True)

        try:
            server = ThreadedHTTPServer(("127.0.0.1", port), CallbackHandler)  # type: ignore[arg-type]
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_port = port
            server_thread.start()
            emit_ok(f"本地回调监听已启动：http://127.0.0.1:{port}/callback")
            return True
        except Exception as ex:
            emit_alarm(f"本地回调服务器启动失败（端口 {port}）：{ex}")
            return False

    def resolve_callback_port(redirect_uri: str) -> int:
        parsed = urlparse((redirect_uri or "").strip())
        if parsed.scheme != "http":
            raise ValueError("redirect_uri 必须是 http 本地回环地址")
        if parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("redirect_uri 仅支持 127.0.0.1 或 localhost")
        if parsed.port is None:
            return 80
        return int(parsed.port)

    def on_code_captured(code: str) -> None:
        code = (code or "").strip()
        if not code:
            emit_alarm("回调收到空授权码，已中断令牌交换。")
            return
        code_display.value = code
        emit_ok("已捕获授权码 Code，正在发起令牌交换。")
        snapshot = current_flow.copy()
        threading.Thread(target=exchange_token_with_pkce, args=(code, snapshot), daemon=True).start()

    def extract_error_hint(response: requests.Response, fallback: str) -> str:
        message = safe_json_message(response)
        return message or fallback

    def exchange_token_with_pkce(code: str, flow_snapshot: dict[str, str]) -> None:
        try:
            backend_url = flow_snapshot["backend_url"]
            redirect_uri = flow_snapshot["redirect_uri"]
            client_id = flow_snapshot["client_id"]
            client_secret = flow_snapshot["client_secret"]
            verifier = flow_snapshot["verifier"]
        except KeyError:
            emit_alarm("PKCE 状态快照丢失，无法继续令牌交换。")
            return

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if client_secret:
            auth_str = f"{client_id}:{client_secret}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {b64_auth}"

        loading_progress.visible = True
        page.update()

        try:
            res = requests.post(f"{backend_url.rstrip('/')}/oauth/token", data=data, headers=headers, verify=False, timeout=20)
        except Exception as ex:
            loading_progress.visible = False
            emit_alarm(f"令牌交换网络异常：{ex}")
            return

        loading_progress.visible = False
        if res.status_code != 200:
            detail = extract_error_hint(res, "令牌交换失败")
            if res.status_code == 401:
                emit_alarm(f"未登录成功 / 授权失败 [401]：{detail}")
            elif res.status_code == 403:
                emit_alarm(f"授权被拒绝 [403]：{detail}")
            else:
                emit_alarm(f"令牌交换失败 [{res.status_code}]：{detail}")
            return

        try:
            res_data = res.json()
        except Exception as ex:
            emit_alarm(f"令牌响应解析失败：{ex} | 原始内容：{res.text[:200]}")
            return

        access_token = res_data.get("access_token")
        refresh_token = res_data.get("refresh_token")
        if not access_token:
            emit_alarm("令牌响应缺少 access_token，测试失败。")
            return

        access_token_display.value = access_token
        refresh_token_display.value = refresh_token or "-"
        expires_display.value = f"✅ 令牌已签发，有效期 {res_data.get('expires_in', '-')} 秒"
        emit_ok("授权成功，Access Token / Refresh Token 已输出。")
        refresh_btn.disabled = not bool(refresh_token)
        page.update()

    def refresh_token_flow(e):
        refresh_token = (refresh_token_display.value or "").strip()
        if not refresh_token or refresh_token == "-":
            emit_alarm("尚未获取 Refresh Token，无法执行刷新测试。")
            return

        snapshot = current_flow.copy()
        backend_url = snapshot["backend_url"]
        client_id = snapshot["client_id"]
        client_secret = snapshot["client_secret"]
        emit_info("正在发起 refresh_token 令牌置换更新...")

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if client_secret:
            auth_str = f"{client_id}:{client_secret}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {b64_auth}"

        try:
            res = requests.post(f"{backend_url.rstrip('/')}/oauth/token", data=data, headers=headers, verify=False, timeout=20)
        except Exception as ex:
            emit_alarm(f"刷新网络异常：{ex}")
            return

        if res.status_code != 200:
            detail = extract_error_hint(res, "刷新失败")
            if res.status_code == 401:
                emit_alarm(f"未登录成功 / 刷新失败 [401]：{detail}")
            elif res.status_code == 403:
                emit_alarm(f"刷新被拒绝 [403]：{detail}")
            else:
                emit_alarm(f"刷新失败 [{res.status_code}]：{detail}")
            return

        try:
            res_data = res.json()
        except Exception as ex:
            emit_alarm(f"刷新响应解析失败：{ex} | 原始内容：{res.text[:200]}")
            return

        access_token = res_data.get("access_token")
        if not access_token:
            emit_alarm("刷新响应缺少 access_token。")
            return

        access_token_display.value = access_token
        emit_ok("刷新成功，Access Token 已更新。")
        page.update()

    def clear_logs(e):
        log_lines.clear()
        log_console.value = ""
        emit_info("日志已清空。")

    def start_pkce_flow(e):
        nonlocal current_flow
        client_id = (client_id_input.value or "").strip()
        backend_url = (backend_url_input.value or DEFAULT_BACKEND_URL).strip()
        redirect_uri = (redirect_uri_input.value or DEFAULT_REDIRECT_URI).strip()
        client_secret = (client_secret_input.value or "").strip()
        scope = (scope_input.value or "read").strip() or "read"

        if not client_id:
            emit_alarm("Client ID 不能为空，无法启动 PKCE 测试。")
            return

        try:
            callback_port = resolve_callback_port(redirect_uri)
        except Exception as ex:
            emit_alarm(f"Redirect URI 不合法：{ex}")
            return

        if not start_callback_server(callback_port):
            return

        verifier = generate_pkce_verifier()
        challenge = generate_pkce_challenge(verifier)
        if len(verifier) < 43:
            emit_alarm("PKCE verifier 生成长度不足，测试中止。")
            return

        current_flow = {
            "backend_url": backend_url,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            "verifier": verifier,
            "challenge": challenge,
        }

        verifier_display.value = verifier
        challenge_display.value = challenge
        access_token_display.value = "-"
        refresh_token_display.value = "-"
        code_display.value = "-"
        expires_display.value = ""
        refresh_btn.disabled = True

        emit_info("PKCE 密钥对已生成，准备跳转授权端。")
        state = f"pkce_flet_{int(time.time())}"
        auth_url = build_auth_url(backend_url, redirect_uri, client_id, scope, state, challenge)

        time.sleep(0.2)
        opened = webbrowser.open(auth_url)
        if not opened:
            emit_alarm(f"浏览器未能自动打开授权地址，请手动复制：{auth_url}")
            return

        emit_ok("授权页面已在浏览器打开，等待 code 回调。")
        page.update()

    def stop_server_click(e):
        stop_callback_server()

    refresh_btn = ft.ElevatedButton(
        "使用 Refresh Token 刷新令牌",
        icon=ft.Icons.REFRESH,
        on_click=refresh_token_flow,
        disabled=True,
    )

    set_event_handlers(on_code_captured, emit_alarm)

    # 首次初始化日志
    emit_ok("标准测试软件已加载完成。所有失败/告警都会写入下方日志面板。")

    page.add(
        ft.Column(
            [
                ft.Container(
                    padding=16,
                    border_radius=10,
                    bgcolor=ft.Colors.BLUE_GREY_900,
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    ft.Text("🧪 OnAuth 标准测试软件", size=20, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_ACCENT),
                                    ft.Container(width=10),
                                    ft.Text("OAuth 2.0 + PKCE / Token 刷新 / 告警输出", size=12, color=ft.Colors.GREY_400),
                                ],
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            ),
                            ft.Divider(height=10),
                            ft.Row(
                                [
                                    ft.Container(
                                        expand=True,
                                        content=ft.Column([backend_url_input, redirect_uri_input]),
                                    ),
                                ]
                            ),
                            ft.Row(
                                [
                                    ft.Container(expand=True, content=client_id_input),
                                    ft.Container(width=14),
                                    ft.Container(width=220, content=scope_input),
                                ]
                            ),
                            ft.Row([client_secret_input]),
                            ft.Row(
                                [
                                    ft.ElevatedButton("启动 PKCE 测试", icon=ft.Icons.LOCK_RESET, on_click=start_pkce_flow, height=44, bgcolor=ft.Colors.BLUE_900, color=ft.Colors.WHITE),
                                    ft.ElevatedButton("停止回调监听", icon=ft.Icons.STOP_CIRCLE_OUTLINED, on_click=stop_server_click, height=44),
                                    ft.OutlinedButton("清空日志", icon=ft.Icons.CLEANING_SERVICES, on_click=clear_logs, height=44),
                                    refresh_btn,
                                ],
                                alignment=ft.MainAxisAlignment.START,
                                wrap=True,
                            ),
                        ]
                    ),
                ),
                ft.Container(height=10),
                ft.Container(
                    padding=16,
                    border_radius=10,
                    bgcolor=ft.Colors.BLUE_GREY_900,
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    ft.Text("状态 / 告警", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.AMBER_400),
                                    ft.Row(
                                        [
                                            ft.Text("告警次数", color=ft.Colors.RED_300, size=12),
                                            alarm_badge,
                                        ],
                                        spacing=6,
                                    ),
                                ],
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            ),
                            status_text,
                            ft.Text("最近一条告警：", size=12, color=ft.Colors.RED_200),
                            last_alarm_text,
                            loading_progress,
                        ]
                    ),
                ),
                ft.Container(height=10),
                ft.Container(
                    padding=16,
                    border_radius=10,
                    bgcolor=ft.Colors.BLUE_GREY_900,
                    content=ft.Column(
                        [
                            ft.Text("PKCE 密钥链路", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.AMBER_400),
                            verifier_display,
                            challenge_display,
                        ]
                    ),
                ),
                ft.Container(height=10),
                ft.Container(
                    padding=16,
                    border_radius=10,
                    bgcolor=ft.Colors.BLUE_GREY_900,
                    content=ft.Column(
                        [
                            ft.Text("令牌输出", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.AMBER_400),
                            code_display,
                            access_token_display,
                            refresh_token_display,
                            expires_display,
                        ]
                    ),
                ),
                ft.Container(height=10),
                ft.Container(
                    padding=16,
                    border_radius=10,
                    bgcolor=ft.Colors.BLACK,
                    content=ft.Column(
                        [
                            ft.Text("运行日志 / 告警输出（所有失败必须在这里出现）", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN_300),
                            log_console,
                        ],
                        expand=True,
                    ),
                    expand=True,
                ),
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )
    )


if __name__ == "__main__":
    ft.app(target=main)

