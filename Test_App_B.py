import base64
import hashlib
import os
import re
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import flet as ft
import requests
import urllib3
import socket

# 关闭客户端自签名证书未验证的红色警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BACKEND_URL = "https://127.0.0.1:8000"
def get_free_port():
    sock = socket.socket()
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port

port = get_free_port()
REDIRECT_URI = f"http://127.0.0.1:{port}/callback"

class CallbackHandler(BaseHTTPRequestHandler):
    """本地轻量级回调 HTTP 监听器"""

    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        if "code" in query_components:
            code = query_components["code"][0]
            # 捕获 code 并通过全局事件通知主线程
            self.server.flet_app.on_code_captured(code)

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
        else:
            self.send_response(400)
            self.end_headers()

    def log_message(self, format, *args):
        return


class ThreadedHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, flet_app):
        super().__init__(server_address, RequestHandlerClass)
        self.flet_app = flet_app


# ==========================================================================
# 🛠️ PKCE 核心加密算法套件
# ==========================================================================
def generate_pkce_verifier() -> str:
    """生成合规的 43~128 位高强度 code_verifier 原始随机串"""
    # 按照 RFC 7636 标准，采用 unreserved 字符集
    token = os.urandom(32)
    raw_verifier = base64.urlsafe_b64encode(token).decode("utf-8")
    return re.sub('[^a-zA-Z0-9_.-]', '', raw_verifier)


def generate_pkce_challenge(verifier: str) -> str:
    """通过 SHA256 哈希计算出对应的 code_challenge 挑战码 (S256 模式)"""
    sha256_hash = hashlib.sha256(verifier.encode('utf-8')).digest()
    # 严格采用 URL 安全型 Base64 编码，且必须剔除末尾填充号 '='
    b64_encoded = base64.urlsafe_b64encode(sha256_hash).decode('utf-8')
    return b64_encoded.replace('=', '')


def main(page: ft.Page):
    page.title = "OAuth 2.0 + PKCE 增强版安全验证桩"
    page.window.width = 780
    page.window.height = 850
    page.theme_mode = "dark"
    page.padding = 24
    page.theme = ft.Theme(font_family="Microsoft YaHei")

    http_server = None

    # 🧬 内存维护的 PKCE 状态锁
    pkce_state = {
        "verifier": "",
        "challenge": ""
    }

    # UI 静态/动态配置域
    client_id_input = ft.TextField(label="Client ID", value="", hint_text="从中控台签发的公有客户端识别码 (Client ID)",
                                   expand=True)
    # 💡 提示：在标准且纯正的 PKCE 场景中，客户端作为不安全环境（如 SPA、桌面客户端），完全可以不提供、不传送 Client Secret
    client_secret_input = ft.TextField(label="Client Secret (可选/用于混合验证模式)", value="", password=True,
                                       can_reveal_password=True, hint_text="若后端强制校验机密客户端请填写",
                                       expand=True)
    scope_input = ft.TextField(label="Scope (权限范围)", value="read", width=140)

    # 监控层
    status_text = ft.Text("等待就绪。PKCE 流已挂载保护机制...", color=ft.Colors.BLUE_GREY_300, size=13)
    loading_progress = ft.ProgressBar(visible=False, color=ft.Colors.BLUE_400)

    # PKCE 实时动态观测窗
    verifier_display = ft.TextField(label="[PKCE 独占] 临时生成的暗号原件 (Code Verifier)", read_only=True, value="-",
                                    text_style=ft.TextStyle(color=ft.Colors.AMBER_300, font_family="monospace"))
    challenge_display = ft.TextField(label="[PKCE 独占] 发往授权端拦截的哈希挑战密文 (Code Challenge)", read_only=True,
                                     value="-",
                                     text_style=ft.TextStyle(color=ft.Colors.CYAN_300, font_family="monospace"))

    # 令牌阶段看板
    code_display = ft.TextField(label="1. 截获的单次授权凭证 (Code)", read_only=True, value="-")
    access_token_display = ft.TextField(label="2. Access Token (Bearer)", read_only=True, value="-", multiline=True,
                                        min_lines=2, max_lines=3)
    refresh_token_display = ft.TextField(label="3. 刷新令牌 (Refresh Token)", read_only=True, value="-")
    expires_display = ft.Text("", color=ft.Colors.GREEN_400, size=12)

    def show_log(msg: str, is_error=False):
        status_text.value = msg
        status_text.color = ft.Colors.RED_400 if is_error else ft.Colors.GREEN_400
        page.update()

    def on_code_captured(code):
        code_display.value = code
        show_log(f"🎉 截获临时 Code！正在注入 Code Verifier 原件申请安全置换...")
        threading.Thread(target=exchange_token_with_pkce, args=(code,), daemon=True).start()

    page.on_code_captured = on_code_captured

    def start_pkce_flow(e):
        nonlocal http_server
        if not client_id_input.value:
            show_log("❌ 错误：公有应用测试必须指定 Client ID！", is_error=True)
            return

        # ⚡ 第一步：动态锻造 PKCE 密钥对
        pkce_state["verifier"] = generate_pkce_verifier()
        pkce_state["challenge"] = generate_pkce_challenge(pkce_state["verifier"])

        # 将动态密码印刻到看板上供审查人员比对
        verifier_display.value = pkce_state["verifier"]
        challenge_display.value = pkce_state["challenge"]

        # 起跑回环侦听
        if http_server is None:
            try:
                http_server = ThreadedHTTPServer(("127.0.0.1", 8990), CallbackHandler, page)
                threading.Thread(target=http_server.handle_request, daemon=True).start()
            except Exception as ex:
                print(f"Server init error: {ex}")

        loading_progress.visible = True
        show_log("⏳ 已将哈希挑战锚定。正在唤醒浏览器重定向到 /oauth/authorize 校验节点...")

        # ⚡ 第二步：在拼接授权地址时，强行追加 code_challenge 与加密算法声明 code_challenge_method=S256
        state = "pkce_flet_flow_2026"
        auth_url = (
            f"{BACKEND_URL}/oauth/authorize?"
            f"client_id={client_id_input.value}&"
            f"redirect_uri={REDIRECT_URI}&"
            f"response_type=code&"
            f"scope={scope_input.value}&"
            f"state={state}&"
            f"code_challenge={pkce_state['challenge']}&"
            f"code_challenge_method=S256"
        )

        time.sleep(0.4)
        webbrowser.open(auth_url)
        page.update()

    def exchange_token_with_pkce(code):
        try:
            # 组装换取 Token 的 Payload
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id_input.value,
                # ⚡ 核心提权要素：不送 Secret，改为推送 Verifier 明文供中台进行二次哈希比对
                "code_verifier": pkce_state["verifier"]
            }

            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            # 兼容混合机密模式：如果用户输入了 Secret，则加上 Basic 认证头
            if client_secret_input.value:
                auth_str = f"{client_id_input.value}:{client_secret_input.value}"
                b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
                headers["Authorization"] = f"Basic {b64_auth}"

            # 后端根据此处的 code_verifier 对先前接收的 code_challenge 进行重组验算
            res = requests.post(f"{BACKEND_URL}/oauth/token", data=data, headers=headers, verify=False)
            loading_progress.visible = False

            if res.status_code == 200:
                res_data = res.json()
                access_token_display.value = res_data.get("access_token")
                refresh_token_display.value = res_data.get("refresh_token")
                expires_display.value = f"✅ PKCE 安全闭环验证通过！令牌有效周期: {res_data.get('expires_in')} 秒"
                show_log("🚀 链路闭环！中台对齐原件散列校验判定合法，已颁发高阶令牌。")
                refresh_btn.disabled = False
            else:
                show_log(f"❌ 令牌换取由于 PKCE 验算断裂失败: {res.text}", is_error=True)
        except Exception as ex:
            show_log(f"❌ 链路级通信异常: {str(ex)}", is_error=True)
            loading_progress.visible = False
        page.update()

    def refresh_token_flow(e):
        show_log("⏳ 正在发起 refresh_token 令牌置换更新...")
        try:
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_display.value,
                "client_id": client_id_input.value
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if client_secret_input.value:
                auth_str = f"{client_id_input.value}:{client_secret_input.value}"
                b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
                headers["Authorization"] = f"Basic {b64_auth}"

            res = requests.post(f"{BACKEND_URL}/oauth/token", data=data, headers=headers, verify=False)
            if res.status_code == 200:
                res_data = res.json()
                access_token_display.value = res_data.get("access_token")
                show_log("⚡ 刷新成功！已使用无感模式下发了全新的 Access Token！")
            else:
                show_log(f"❌ 刷新阻断: {res.text}", is_error=True)
        except Exception as ex:
            show_log(f"❌ 刷新异常: {str(ex)}", is_error=True)
        page.update()

    refresh_btn = ft.ElevatedButton("使用 Refresh Token 刷新令牌", icon=ft.Icons.REFRESH, on_click=refresh_token_flow,
                                    disabled=True)

    # 布局渲染
    page.add(
        ft.Text("🛡️ OAuth 2.0 + PKCE 次世代增强验证终端", size=18, weight="bold", color=ft.Colors.BLUE_ACCENT),
        ft.Text("激活安全防拦截验证 (RFC 7636 Proof Key for Code Exchange)", size=12, color=ft.Colors.GREY_500),
        ft.Divider(height=15),
        ft.Row([client_id_input, scope_input]),
        ft.Row([client_secret_input]),
        ft.Container(height=5),
        ft.ElevatedButton("启动 PKCE 安全核心验证流", icon=ft.Icons.LOCK_RESET, bgcolor=ft.Colors.BLUE_900,
                          color=ft.Colors.WHITE, on_click=start_pkce_flow, height=45),
        ft.Divider(height=20),

        ft.Text("🧬 PKCE 密码学生态链条监视层", size=13, weight="bold", color=ft.Colors.AMBER_400),
        verifier_display,
        challenge_display,
        ft.Divider(height=20),

        ft.Text("🎯 拦截时钟与令牌置换跟踪器", size=13, weight="bold"),
        status_text,
        loading_progress,
        ft.Container(height=5),
        code_display,
        access_token_display,
        refresh_token_display,
        expires_display,
        ft.Divider(height=15),
        ft.Row([refresh_btn], alignment="end")
    )


if __name__ == "__main__":
    ft.app(target=main)