import os
import flet as ft
import requests
import threading
import time
# 🔥【核心修复导入】：用于关闭自签名证书未验证的红色警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 🚀【联动修改】：默认地址自动升级为安全加密的 https
API_BASE_URL = os.getenv("MANAGEMENT_API_URL", "https://127.0.0.1:8000")

# 🔒 【核心安全配置】必须与后端 main.py 中定义的 ADMIN_TOKEN 完全一致
ADMIN_TOKEN = os.getenv("MANAGEMENT_ADMIN_TOKEN")
if not ADMIN_TOKEN:
    raise ValueError("未找到管理员安全暗号！")
ADMIN_HEADERS = {"X-Admin-Token": ADMIN_TOKEN}


def main(page: ft.Page):
    # ==================== 页面全局配置 ====================
    page.title = "应用鉴权管理中台"
    page.theme_mode = "dark"  # 默认深色模式
    page.window.width = 1000  # 稍微加宽，给标准OAuth2作用域留出足够空间
    page.window.height = 820
    page.window.min_height = 700
    page.window.min_width = 1000
    page.padding = 20

    # 全局字体统一为微软雅黑
    page.theme = ft.Theme(font_family="Microsoft YaHei")

    # 🛠️ 纯手工打造的通知悬浮容器
    toast_container = ft.Column(spacing=10, width=320)

    # 将通知容器挂载在右下角的绝对定位浮层中
    toast_overlay = ft.Container(
        content=toast_container,
        right=20,
        bottom=20,
        expand=False
    )

    def show_toast(message: str, is_error: bool = False):
        toast_card = ft.Container(
            content=ft.Row([
                ft.Icon(
                    ft.Icons.ERROR_OUTLINED if is_error else ft.Icons.CHECK_CIRCLE_OUTLINE,
                    color=ft.Colors.WHITE,
                    size=20
                ),
                ft.VerticalDivider(width=1, color=ft.Colors.WHITE30),
                ft.Text(
                    message,
                    color=ft.Colors.WHITE,
                    weight="bold",
                    selectable=True,
                    expand=True
                )
            ], spacing=10, alignment="start"),
            bgcolor=ft.Colors.RED_600 if is_error else ft.Colors.GREEN_600,
            padding=15,
            border_radius=8,
            shadow=ft.BoxShadow(blur_radius=10, color=ft.Colors.BLACK45),
            width=380
        )

        toast_container.controls.append(toast_card)
        page.update()

        def destroy_toast():
            time.sleep(4)
            if toast_card in toast_container.controls:
                toast_container.controls.remove(toast_card)
                page.update()

        threading.Thread(target=destroy_toast, daemon=True).start()

    def copy_to_clipboard(text_value: str, success_message: str):
        try:
            page.set_clipboard_data(ft.ClipboardData(text=str(text_value)))
            show_toast(success_message)
        except Exception:
            try:
                page.clipboard = str(text_value)
                page.update()
                show_toast(success_message)
            except Exception:
                show_toast(f"自动复制受限，请直接在文本框内鼠标拖拽框选复制！", is_error=True)

    # 用于承载主业务应用卡片列表的容器
    apps_container = ft.Column(spacing=15, scroll="auto", expand=True)

    # ==================== 后端数据交互层（带安全头验证 & 绕过自签证书限制） ====================

    def fetch_apps_from_api():
        try:
            # 🔥【关键修复】：增加 verify=False 绕过自签证书拦截
            response = requests.get(f"{API_BASE_URL}/admin/apps/list", headers=ADMIN_HEADERS, timeout=4, verify=False)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                show_toast("中台拒绝访问：管理员安全暗号不匹配！", is_error=True)
                return []
            else:
                return []
        except Exception as e:
            show_toast(f"连接中台API失败，请确认后端已开机。错误原因: {str(e)}", is_error=True)
            return []

    def toggle_app_status_api(app_id: int, current_status: bool):
        try:
            # 🔥【关键修复】：增加 verify=False
            res = requests.put(f"{API_BASE_URL}/admin/apps/{app_id}/status", params={"is_active": not current_status},
                               headers=ADMIN_HEADERS, verify=False)
            if res.status_code == 200:
                show_toast("应用网关状态同步成功")
                render_app_list()
            else:
                show_toast(f"修改失败: {res.text}", is_error=True)
        except Exception as e:
            show_toast(f"请求异常: {str(e)}", is_error=True)

    def delete_app_api(app_id: int):
        try:
            # 🔥【关键修复】：增加 verify=False
            res = requests.delete(f"{API_BASE_URL}/admin/apps/{app_id}", headers=ADMIN_HEADERS, verify=False)
            if res.status_code == 200:
                show_toast(res.json().get("msg", "删除应用成功"))
                render_app_list()
            else:
                show_toast(f"删除应用失败: {res.text}", is_error=True)
        except Exception as e:
            show_toast(f"删除请求异常: {str(e)}", is_error=True)

    def toggle_credential_status_api(client_id: str, current_status: bool):
        try:
            # 🔥【关键修复】：增加 verify=False
            res = requests.put(f"{API_BASE_URL}/admin/credentials/{client_id}/status",
                               params={"is_active": not current_status}, headers=ADMIN_HEADERS, verify=False)
            if res.status_code == 200:
                show_toast("凭证生命周期开关已同步")
                render_app_list()
            else:
                show_toast(f"同步失败: {res.text}", is_error=True)
        except Exception as e:
            show_toast(f"请求异常: {str(e)}", is_error=True)

    def delete_credential_api(client_id: str):
        try:
            # 🔥【关键修复】：增加 verify=False
            res = requests.delete(f"{API_BASE_URL}/admin/credentials/{client_id}", headers=ADMIN_HEADERS, verify=False)
            if res.status_code == 200:
                show_toast(res.json().get("msg", "凭证通道已彻底粉碎清除"))
                render_app_list()
            else:
                show_toast(f"删除凭证失败: {res.text}", is_error=True)
        except Exception as e:
            show_toast(f"删除凭证异常: {str(e)}", is_error=True)

    # ==================== UI 动态列表渲染 ====================

    def render_app_list():
        apps_container.controls.clear()
        data = fetch_apps_from_api()

        th_color = ft.Colors.BLUE_GREY_700 if page.theme_mode == "light" else ft.Colors.BLUE_GREY_200

        if not data:
            apps_container.controls.append(
                ft.Container(
                    content=ft.Text("暂无注册应用，请点击右上角按钮创建专属接入通道", color=ft.Colors.GREY_500, size=16),
                    alignment=ft.Alignment(0, 0),
                    padding=50
                )
            )
            page.update()
            return

        try:
            for app in data:
                app_id = app.get("app_id")
                app_name = app.get("app_name", "未命名应用")
                is_active = app.get("is_active", True)
                credentials = app.get("credentials", [])

                cred_rows = []
                if not credentials:
                    cred_rows.append(ft.Text("   💡 当前应用下暂无分配任何 OAuth2.0 / License 授权凭证", color=ft.Colors.GREY_600, italic=True))
                else:
                    cred_rows.append(
                        ft.Row(
                            [
                                ft.Text("凭证别名", width=120, weight="bold", color=th_color),
                                ft.Text("Client ID (凭证标识)", width=220, weight="bold", color=th_color),
                                ft.Text("标准权限 (Scope)", width=120, weight="bold", color=th_color),
                                ft.Text("到期时间 (订阅截止)", width=160, weight="bold", color=th_color),
                                ft.Text("网关熔断", width=60, weight="bold", color=th_color),
                                ft.Text("高级运维", width=120, weight="bold", color=th_color),
                            ],
                            spacing=15
                        )
                    )

                    for c in credentials:
                        expire_text = c.get("expire_at", "永久有效")
                        client_id = c.get("client_id", "N/A")
                        scope_raw = c.get("scope", "read")
                        cred_name = c.get("credential_name", "基础密钥对")
                        c_active = c.get("is_active", True)

                        client_id_color = ft.Colors.BLUE_700 if page.theme_mode == "light" else ft.Colors.BLUE_200
                        expire_color = ft.Colors.GREY_700 if page.theme_mode == "light" else ft.Colors.GREY_400

                        cred_rows.append(
                            ft.Row(
                                [
                                    ft.Text(cred_name, width=120, max_lines=1, overflow="ellipsis"),
                                    ft.Row([
                                        ft.Text(client_id, color=client_id_color, selectable=True, font_family="Consolas"),
                                        ft.IconButton(
                                            icon=ft.Icons.COPY,
                                            icon_size=14,
                                            icon_color=ft.Colors.BLUE_300,
                                            tooltip="复制 Client ID",
                                            on_click=lambda e, cid=client_id: copy_to_clipboard(cid, "Client ID 已复制")
                                        )
                                    ], spacing=2, width=220),
                                    ft.Container(
                                        content=ft.Text(str(scope_raw), size=12, color=ft.Colors.BLACK, weight="bold"),
                                        bgcolor=ft.Colors.AMBER_400,
                                        padding=4,
                                        border_radius=4,
                                        width=120,
                                        alignment=ft.Alignment(0, 0)
                                    ),
                                    ft.Text(str(expire_text), width=160, color=expire_color, size=13),
                                    ft.Switch(
                                        value=c_active,
                                        width=60,
                                        on_change=lambda e, cid=client_id, status=c_active: toggle_credential_status_api(cid, status)
                                    ),
                                    ft.Row([
                                        ft.IconButton(
                                            icon=ft.Icons.EDIT,
                                            icon_color=ft.Colors.BLUE_300,
                                            tooltip="修改权限 Scope 或续期调配",
                                            on_click=lambda e, cid=client_id, sc=scope_raw, name=cred_name: open_edit_config_dialog(cid, sc, name)
                                        ),
                                        ft.IconButton(
                                            icon=ft.Icons.DELETE_FOREVER,
                                            icon_color=ft.Colors.RED_400,
                                            tooltip="彻底物理销毁此渠道",
                                            on_click=lambda e, cid=client_id, name=cred_name: open_delete_cred_dialog(cid, name)
                                        )
                                    ], spacing=0)
                                ],
                                spacing=15
                            )
                        )

                app_card = ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([
                                ft.Row([
                                    ft.Icon(ft.Icons.APPS, color=ft.Colors.BLUE_400, size=28),
                                    ft.Text(app_name, size=20, weight="bold"),
                                    ft.Text(f"(ID: {app_id})", color=ft.Colors.GREY_500)
                                ], spacing=10),
                                ft.Row([
                                    ft.Text("主通道开关:", size=14),
                                    ft.Switch(
                                        value=is_active,
                                        active_color=ft.Colors.GREEN_ACCENT_400,
                                        on_change=lambda e, aid=app_id, status=is_active: toggle_app_status_api(aid, status)
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.ADD_LINK,
                                        icon_color=ft.Colors.GREEN_400,
                                        tooltip="追加并生成新多轨授权凭证",
                                        on_click=lambda e, aid=app_id: open_add_credential_dialog(aid)
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.DELETE,
                                        icon_color=ft.Colors.RED_700,
                                        tooltip="粉碎整个应用主体及旗下所有卡密凭证",
                                        on_click=lambda e, aid=app_id, name=app_name: open_delete_app_dialog(aid, name)
                                    )
                                ], spacing=10)
                            ], alignment="spaceBetween"),
                            ft.Divider(color=ft.Colors.GREY_800),
                            ft.Container(content=ft.Column(cred_rows, spacing=8),
                                         padding=ft.Padding(left=10, top=5, right=0, bottom=5))
                        ]),
                        padding=20
                    ),
                    margin=ft.Margin(left=0, top=0, right=0, bottom=10)
                )
                apps_container.controls.append(app_card)

            page.update()
        except Exception as compile_err:
            show_toast(f"动态渲染组件树失败，字段契合度存在冲突: {str(compile_err)}", is_error=True)

    # ==================== 弹窗交互控制层 ====================

    # --- 弹窗 1：创建应用 ---
    new_app_name_input = ft.TextField(label="接入应用系统名称（如：WMS仓储系统）")

    def submit_new_app(e):
        if not new_app_name_input.value: return
        add_app_dialog.open = False
        page.update()

        try:
            # 🔥【关键修复】：增加 verify=False
            res = requests.post(f"{API_BASE_URL}/admin/apps", params={"app_name": new_app_name_input.value},
                                headers=ADMIN_HEADERS, verify=False)
            if res.status_code == 200:
                show_toast(f"外包/内部系统 [{new_app_name_input.value}] 成功接入授权链条！")
                new_app_name_input.value = ""
                render_app_list()
            else:
                show_toast(f"添加失败: {res.text}", is_error=True)
        except Exception as ex:
            show_toast(f"后端通信故障: {str(ex)}", is_error=True)

    add_app_dialog = ft.AlertDialog(
        title=ft.Text("新增外部系统接入"), content=new_app_name_input,
        actions=[
            ft.TextButton("取消", on_click=lambda e: setattr(add_app_dialog, "open", False) or page.update()),
            ft.Button("确认创建并下发", on_click=submit_new_app, bgcolor=ft.Colors.BLUE_600, color=ft.Colors.WHITE)
        ]
    )
    page.overlay.append(add_app_dialog)

    # --- 弹窗 2：追加新凭证 ---
    current_target_app_id = [None]
    new_cred_name_input = ft.TextField(label="凭证别名（如：生产线）")
    new_cred_scope_input = ft.TextField(label="标准 OAuth2 权限范围 (Scope)", value="read")
    new_cred_days_input = ft.TextField(label="授权有效订阅天数", value="365")

    def submit_new_credential(e):
        try:
            payload = {
                "credential_name": new_cred_name_input.value,
                "scope": new_cred_scope_input.value,
                "valid_days": int(new_cred_days_input.value)
            }
            # 🔥【关键修复】：增加 verify=False
            res = requests.post(f"{API_BASE_URL}/admin/apps/{current_target_app_id[0]}/credentials", params=payload,
                                headers=ADMIN_HEADERS, verify=False)
            if res.status_code == 200:
                show_toast("多轨融合授权凭证下发成功！")

                res_data = res.json()
                client_id = res_data.get("client_id", "获取失败")
                client_secret = res_data.get("client_secret", "获取失败")
                license_key = res_data.get("license_key", "获取失败")

                id_input = ft.TextField(label="Client ID (OAuth2 客户端唯一标识)", value=client_id, read_only=True,
                                        expand=True)
                secret_input = ft.TextField(label="Client Secret (OAuth2 客户端安全密码)", value=client_secret,
                                            read_only=True, expand=True)
                license_input = ft.TextField(label="License Key (无状态长效直连激活码 JWT)", value=license_key,
                                             read_only=True, multiline=True, min_lines=3, max_lines=5, expand=True)

                add_cred_dialog.title = ft.Text("🚀 统一凭证分发中心", color=ft.Colors.GREEN_400, weight="bold")
                add_cred_dialog.content = ft.Column([
                    ft.Text("提示：密钥生成采取 SHA256 不可逆哈希，关闭此窗口后 Secret 将永远无法二次明文查询！", color=ft.Colors.RED_300, size=12, weight="bold"),
                    ft.Row([id_input, ft.IconButton(ft.Icons.CONTENT_COPY, on_click=lambda e: copy_to_clipboard(client_id, "Client ID已复制"))]),
                    ft.Row([secret_input, ft.IconButton(ft.Icons.CONTENT_COPY, on_click=lambda e: copy_to_clipboard(client_secret, "Client Secret密匙已复制"))]),
                    ft.Row([license_input, ft.IconButton(ft.Icons.CONTENT_COPY, on_click=lambda e: copy_to_clipboard(license_key, "无状态激活码已复制"))]),
                ], tight=True, spacing=15, width=620)

                add_cred_dialog.actions = [
                    ft.Button("我已将上述高危密匙全部安全备份，确认关闭", on_click=lambda e: setattr(add_cred_dialog, "open", False) or render_app_list())
                ]
                page.update()
            else:
                show_toast(f"后端拦截: {res.text}", is_error=True)
        except Exception as ex:
            show_toast(f"下发网络出现灾难性异常: {str(ex)}", is_error=True)

    add_cred_dialog = ft.AlertDialog(
        title=ft.Text("下发融合授权凭证"),
        content=ft.Column([new_cred_name_input, new_cred_scope_input, new_cred_days_input], tight=True, spacing=10),
        modal=True,
        actions=[]
    )
    page.overlay.append(add_cred_dialog)

    def open_add_credential_dialog(app_id: int):
        current_target_app_id[0] = app_id
        new_cred_name_input.value = ""
        add_cred_dialog.title = ft.Text("开通应用次级鉴权链路")
        add_cred_dialog.content = ft.Column([new_cred_name_input, new_cred_scope_input, new_cred_days_input], tight=True, spacing=10)
        add_cred_dialog.actions = [
            ft.TextButton("放弃", on_click=lambda e: setattr(add_cred_dialog, "open", False) or page.update()),
            ft.Button("立刻核发", on_click=submit_new_credential, bgcolor=ft.Colors.GREEN_600, color=ft.Colors.WHITE)
        ]
        add_cred_dialog.open = True
        page.update()

    # --- 弹窗 3：修改凭证配置 ---
    edit_client_id_holder = [None]
    edit_scope_input = ft.TextField(label="调配协议 Scope 权限域")
    edit_days_input = ft.TextField(label="追加充值订阅时长 (天数)")

    def submit_edit_config(e):
        edit_config_dialog.open = False
        page.update()
        try:
            payload = {"scope": edit_scope_input.value, "add_days": int(edit_days_input.value)}
            # 🔥【关键修复】：增加 verify=False
            res = requests.put(f"{API_BASE_URL}/admin/credentials/{edit_client_id_holder[0]}/config", params=payload, headers=ADMIN_HEADERS, verify=False)
            if res.status_code == 200:
                show_toast("高层网关路由策略及 Scope 修改成功并已即时生效！")
                render_app_list()
            else:
                show_toast(f"修改配置阻断: {res.text}", is_error=True)
        except Exception as ex:
            show_toast(f"参数类型捕获错误: {str(ex)}", is_error=True)

    edit_config_dialog = ft.AlertDialog(
        title=ft.Text("调整凭证高级配置"),
        content=ft.Column([
            ft.Text("注：输入的追加天数将会直接在现存有效截止周期的基础上进行加法平移叠加。", size=12, color=ft.Colors.BLUE_GREY_300),
            edit_scope_input,
            edit_days_input
        ], tight=True, spacing=12),
        actions=[
            ft.TextButton("算了吧", on_click=lambda e: setattr(edit_config_dialog, "open", False) or page.update()),
            ft.Button("确认提效", on_click=submit_edit_config, bgcolor=ft.Colors.BLUE_600, color=ft.Colors.WHITE)
        ]
    )
    page.overlay.append(edit_config_dialog)

    def open_edit_config_dialog(client_id: str, current_scope: str, cred_name: str):
        edit_client_id_holder[0] = client_id
        edit_config_dialog.title = ft.Text(f"运维凭证通道: [{cred_name}]")
        edit_scope_input.value = current_scope
        edit_days_input.value = "30"
        edit_config_dialog.open = True
        page.update()

    # --- 弹窗 4：删除凭证确认 ---
    delete_cred_id_holder = [None]
    delete_cred_text = ft.Text("", size=14)

    def confirm_delete_credential(e):
        if delete_cred_id_holder[0]:
            delete_cred_dialog.open = False
            page.update()
            delete_credential_api(delete_cred_id_holder[0])

    delete_cred_dialog = ft.AlertDialog(
        title=ft.Row([ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=ft.Colors.RED_400, size=28),
                      ft.Text(" 凭证删除确认", color=ft.Colors.RED_400, weight="bold")], spacing=5),
        content=delete_cred_text,
        actions=[
            ft.TextButton("取消", on_click=lambda e: setattr(delete_cred_dialog, "open", False) or page.update()),
            ft.Button("确认彻底删除", on_click=confirm_delete_credential, bgcolor=ft.Colors.RED_600, color=ft.Colors.WHITE)
        ]
    )
    page.overlay.append(delete_cred_dialog)

    def open_delete_cred_dialog(client_id: str, cred_name: str):
        delete_cred_id_holder[0] = client_id
        delete_cred_text.value = f"确认要【物理剔除】授权节点 [{cred_name}] 吗？\n该接入端的客户端将瞬时发生 network 崩溃熔断，此操作不可逆！"
        delete_cred_dialog.open = True
        page.update()

    # --- 弹窗 5：删除应用确认 ---
    delete_app_id_holder = [None]
    delete_app_text = ft.Text("", size=14)

    def confirm_delete_app(e):
        if delete_app_id_holder[0]:
            delete_app_dialog.open = False
            page.update()
            delete_app_api(delete_app_id_holder[0])

    delete_app_dialog = ft.AlertDialog(
        title=ft.Row([ft.Icon(ft.Icons.REPORT_PROBLEM_ROUNDED, color=ft.Colors.RED_ACCENT_400, size=28),
                      ft.Text(" 高危：应用主体级联全粉碎", color=ft.Colors.RED_ACCENT_400, weight="bold")], spacing=5),
        content=delete_app_text,
        actions=[
            ft.TextButton("不删了（退出高危区）", on_click=lambda e: setattr(delete_app_dialog, "open", False) or page.update()),
            ft.Button("确定强制注销全网关", on_click=confirm_delete_app, bgcolor=ft.Colors.RED_800, color=ft.Colors.WHITE)
        ]
    )
    page.overlay.append(delete_app_dialog)

    def open_delete_app_dialog(app_id: int, app_name: str):
        delete_app_id_holder[0] = app_id
        delete_app_text.value = f"高危警告！您正在强制下线应用主体：[{app_name}] (ID: {app_id})\n\n该动作在系统级将采用级联触发，自动注销粉碎旗下【所有绑定的 ClientID、安全机密密钥和无状态 Token】！"
        delete_app_dialog.open = True
        page.update()

    # ==================== 核心逻辑：主题切换控制 ====================
    theme_icon = ft.Icons.DARK_MODE if page.theme_mode == "light" else ft.Icons.LIGHT_MODE

    def toggle_theme_mode(e):
        if page.theme_mode == "dark":
            page.theme_mode = "light"
            theme_button.icon = ft.Icons.DARK_MODE
            theme_button.tooltip = "切换至深色模式"
            title_text.color = ft.Colors.BLUE_GREY_900
            subtitle_text.color = ft.Colors.GREY_700
            delete_cred_text.color = ft.Colors.BLUE_GREY_900
            delete_app_text.color = ft.Colors.BLUE_GREY_900
        else:
            page.theme_mode = "dark"
            theme_button.icon = ft.Icons.LIGHT_MODE
            theme_button.tooltip = "切换至明亮模式"
            title_text.color = ft.Colors.BLUE_400
            subtitle_text.color = ft.Colors.GREY_400
            delete_cred_text.color = ft.Colors.WHITE
            delete_app_text.color = ft.Colors.WHITE
        render_app_list()

    theme_button = ft.IconButton(icon=theme_icon, tooltip="切换明暗主题", on_click=toggle_theme_mode)
    title_text = ft.Text("企业级开放中台 · 鉴权管理系统", size=24, weight="bold", color=ft.Colors.BLUE_400)
    subtitle_text = ft.Text("同时支持标准 OAuth2 密钥配对与长效直连卡密激活码鉴权，全链路接口强制拦截保护", color=ft.Colors.GREY_400)

    # ==================== 统一登录交互页面 ====================
    # 🚀【优化】：默认连接文本推荐改为 https 地址
    api_input = ft.TextField(label="中央鉴权网关 Core-API 地址", hint_text="例如：https://127.0.0.1:8000", width=420, value="https://127.0.0.1:8000")
    token_input = ft.TextField(label="系统高级管理员核验密令", password=True, can_reveal_password=True, width=420)

    def verify_login(e):
        global API_BASE_URL, ADMIN_TOKEN, ADMIN_HEADERS

        api = api_input.value.strip()
        token = token_input.value.strip()

        if not api or not token:
            show_toast("缺少必要参数：请完整键入中央网关地址与管理员身份秘钥！", is_error=True)
            return

        try:
            headers = {"X-Admin-Token": token}
            # 🔥【最核心修复】：在这里增加 verify=False，允许客户端与本地自签名 HTTPS 握手
            res = requests.get(f"{api}/admin/apps/list", headers=headers, timeout=5, verify=False)

            if res.status_code == 200:
                API_BASE_URL = api
                ADMIN_TOKEN = token
                ADMIN_HEADERS = headers

                login_view.visible = False
                main_view.visible = True
                page.update()

                render_app_list()
                show_toast("🔐 双轨鉴权中心连接成功，数据链条激活状态已拉取！")
            elif res.status_code in [401, 403]:
                show_toast("身份校验拦截：管理员核心密令核验失败，请核对后重试！", is_error=True)
            else:
                show_toast(f"网关层返回非标准应答，错误码: {res.status_code}", is_error=True)
        except Exception as ex:
            show_toast(f"无法建立握手连线，请核对 IP 地址或确认后端服务是否存活! 追溯原因: {str(ex)}", is_error=True)

    login_view = ft.Container(
        content=ft.Column([
            ft.Container(height=40),
            ft.Icon(ft.Icons.ADMIN_PANEL_SETTINGS, size=90, color=ft.Colors.BLUE_400),
            ft.Text("企业级鉴权管理后台", size=32, weight="bold"),
            ft.Text("请输入开放中台网关地址与高级管理中控安全凭证", color=ft.Colors.GREY_500, size=14),
            ft.Container(height=10),
            api_input,
            token_input,
            ft.Container(height=10),
            ft.Button(
                "建立安全审计连线", icon=ft.Icons.LOCK_OPEN, width=420, height=52,
                bgcolor=ft.Colors.BLUE_700, color=ft.Colors.WHITE, on_click=verify_login
            )
        ], horizontal_alignment="center", spacing=18),
        alignment=ft.Alignment(0, 0), expand=True
    )

    # ==================== 顶部公共区 ====================
    header = ft.Row([
        ft.Column([title_text, subtitle_text]),
        ft.Row([
            theme_button,
            ft.Button("同步刷新", icon=ft.Icons.REFRESH, on_click=lambda e: render_app_list()),
            ft.Button("创建接入系统", icon=ft.Icons.ADD_BOX, bgcolor=ft.Colors.BLUE_700, color=ft.Colors.WHITE,
                      on_click=lambda e: setattr(add_app_dialog, "open", True) or page.update())
        ], spacing=10)
    ], alignment="spaceBetween")

    # ==================== 主后台页面 ====================
    main_view = ft.Column(
        [
            header,
            ft.Divider(color=ft.Colors.GREY_700, height=30),
            apps_container
        ],
        visible=False,
        expand=True
    )

    # ==================== 全局挂载与首期生命周期 ====================
    page.add(login_view, main_view)
    page.overlay.append(toast_overlay)

    # 初始化高危二次确认提示文本的颜色
    delete_cred_text.color = ft.Colors.WHITE
    delete_app_text.color = ft.Colors.WHITE


if __name__ == "__main__":
    ft.run(main)