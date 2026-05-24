from __future__ import annotations


from passlib.context import CryptContext

from database import Permission, RiskRule, Role, SessionLocal, User, init_db

_BOOTSTRAPPED = False


DEFAULT_RISK_RULE_SPECS = (
    {
        "name": "登录失败验证码策略(默认)",
        "rule_type": "LOGIN_FAIL_CAPTCHA",
        "target_key": "username+ip",
        "match_key": "fail_count >= 3",
        "threshold_count": 3,
        "threshold_window": 600,
        "action": "CAPTCHA",
        "status": True,
    },
    {
        "name": "防扫描器策略(默认)",
        "rule_type": "SECURITY_SCANNER_BLOCK",
        "target_key": "user_agent+path",
        "match_key": "contains(lower(user_agent), 'sqlmap') or contains(lower(user_agent), 'nikto') or contains(lower(user_agent), 'nmap') or contains(lower(user_agent), 'masscan') or contains(lower(user_agent), 'acunetix') or contains(lower(user_agent), 'crawler') or contains(lower(user_agent), 'spider') or contains(lower(user_agent), 'bot') or contains(lower(user_agent), 'python-requests') or contains(lower(user_agent), 'curl/') or contains(lower(user_agent), 'wget/')",
        "threshold_count": 1,
        "threshold_window": 60,
        "action": "BLOCK",
        "status": True,
    },
    {
        "name": "防恶意UI/自动化策略(默认)",
        "rule_type": "MALICIOUS_UI_BLOCK",
        "target_key": "user_agent+browser",
        "match_key": "contains(lower(user_agent), 'headless') or contains(lower(user_agent), 'selenium') or contains(lower(user_agent), 'playwright') or contains(lower(user_agent), 'puppeteer') or contains(lower(user_agent), 'phantomjs') or contains(lower(user_agent), 'cypress') or contains(lower(user_agent), 'webdriver')",
        "threshold_count": 1,
        "threshold_window": 60,
        "action": "BLOCK",
        "status": True,
    },
    {
        "name": "防SQL注入策略(默认)",
        "rule_type": "SQL_INJECTION_BLOCK",
        "target_key": "username+path",
        "match_key": "contains(lower(username), ' union ') or contains(lower(username), ' select ') or contains(lower(username), ' insert ') or contains(lower(username), ' update ') or contains(lower(username), ' delete ') or contains(lower(username), ' drop ') or contains(lower(username), ' sleep ') or contains(lower(username), ' benchmark ') or contains(lower(username), '--') or contains(lower(username), '/*') or contains(lower(username), '*/') or contains(lower(username), ' or ')",
        "threshold_count": 1,
        "threshold_window": 60,
        "action": "BLOCK",
        "status": True,
    },
    {
        "name": "防XSS注入策略(默认)",
        "rule_type": "XSS_INJECTION_BLOCK",
        "target_key": "username+path+user_agent",
        "match_key": "contains(lower(username), '<script') or contains(lower(username), 'javascript:') or contains(lower(path), '<script') or contains(lower(path), 'javascript:') or contains(lower(user_agent), '<script') or contains(lower(user_agent), 'javascript:') or contains(lower(path), 'onerror=') or contains(lower(path), 'onload=')",
        "threshold_count": 1,
        "threshold_window": 60,
        "action": "BLOCK",
        "status": True,
    },
    {
        "name": "高危路径探测策略(默认)",
        "rule_type": "SENSITIVE_PATH_BLOCK",
        "target_key": "path+user_agent",
        "match_key": "contains(lower(path), '/.git/') or contains(lower(path), '.env') or contains(lower(path), '/.well-known/') or contains(lower(path), '/admin/setup') or contains(lower(path), '/phpmyadmin') or contains(lower(path), '/wp-admin') or contains(lower(path), '/actuator') or contains(lower(path), '/server-status')",
        "threshold_count": 1,
        "threshold_window": 60,
        "action": "BLOCK",
        "status": True,
    },
)


def configure_windows_event_loop_policy() -> None:
    # Python 3.14+ no longer recommends the legacy selector policy here.
    # Keep the hook so older deployments can extend it if needed, but avoid
    # invoking the deprecated policy by default.
    return


def _seed_default_risk_rules(db, creator_id: int | None) -> None:
    changed = False
    for spec in DEFAULT_RISK_RULE_SPECS:
        exists = db.query(RiskRule).filter(RiskRule.rule_type == spec["rule_type"]).first()
        if exists:
            continue
        db.add(
            RiskRule(
                name=spec["name"],
                rule_type=spec["rule_type"],
                target_key=spec["target_key"],
                match_key=spec["match_key"],
                threshold_count=spec["threshold_count"],
                threshold_window=spec["threshold_window"],
                action=spec["action"],
                status=spec["status"],
                creator_id=creator_id,
            )
        )
        changed = True

    if changed:
        db.commit()


def seed_initial_user() -> None:
    db = SessionLocal()
    try:
        scopes_to_seed = {
            "read": "全局可读权限",
            "write": "全局可写权限",
            "tenant:user:create": "租户管理端-邀请创建使用者账号",
            "tenant:app:read": "租户管理端-查看本租户应用列表",
            "tenant:app:create": "租户管理端-创建本租户应用",
            "tenant:credential:read": "租户管理端-查看本租户应用凭证",
            "tenant:credential:create": "租户管理端-签发本租户应用凭证",
            "tenant:space:review": "超级管理员-审批租户空间与设置到期时间",
            "webhook:create": "Webhook-创建订阅端点",
            "webhook:update": "Webhook-更新订阅端点",
            "webhook:list": "Webhook-查看订阅端点",
            "webhook:delete": "Webhook-删除订阅端点",
            "webhook:logs": "Webhook-查看投递日志",
            "admin:read": "中台管理端-查看组织、应用、用户、权限能力",
            "admin:create": "中台管理端-创建组织、应用、凭证、角色能力",
            "admin:update": "中台管理端-编辑用户、角色、权限与资产",
            "admin:delete": "中台管理端-物理粉碎抹除组织与凭证高危权限",
        }

        seeded_permissions: dict[str, Permission] = {}
        for scope_name, desc in scopes_to_seed.items():
            perm = db.query(Permission).filter(Permission.name == scope_name).first()
            if not perm:
                perm = Permission(name=scope_name, description=desc)
                db.add(perm)
                db.commit()
                db.refresh(perm)
            seeded_permissions[scope_name] = perm

        admin_role = db.query(Role).filter(Role.name == "super_admin").first()
        if not admin_role:
            admin_role = Role(name="super_admin", description="系统最高权力控制组")
            admin_role.permissions = list(seeded_permissions.values())
            db.add(admin_role)
            db.commit()
            db.refresh(admin_role)
        else:
            existing_perm_names = {p.name for p in admin_role.permissions}
            for scope_name, perm_obj in seeded_permissions.items():
                if scope_name not in existing_perm_names:
                    admin_role.permissions.append(perm_obj)
            db.commit()

        if "tenant:space:review" not in {p.name for p in admin_role.permissions}:
            admin_role.permissions.append(seeded_permissions["tenant:space:review"])
            db.commit()

        user_role = db.query(Role).filter(Role.name == "standard_user").first()
        if not user_role:
            user_role = Role(name="standard_user", description="普通注册合规用户组")
            user_role.permissions = [seeded_permissions["read"], seeded_permissions["write"]]
            db.add(user_role)
            db.commit()

        tenant_admin_role = db.query(Role).filter(Role.name == "tenant_admin").first()
        tenant_admin_perm_names = [
            "read", "write", "tenant:user:create", "tenant:app:read", "tenant:app:create",
            "tenant:credential:read", "tenant:credential:create", "webhook:create",
            "webhook:update", "webhook:list", "webhook:delete", "webhook:logs",
        ]
        if not tenant_admin_role:
            tenant_admin_role = Role(name="tenant_admin", description="租户空间管理员")
            tenant_admin_role.permissions = [seeded_permissions[name] for name in tenant_admin_perm_names]
            db.add(tenant_admin_role)
            db.commit()
        else:
            existing_perm_names = {p.name for p in tenant_admin_role.permissions}
            for perm_name in tenant_admin_perm_names:
                if perm_name not in existing_perm_names:
                    tenant_admin_role.permissions.append(seeded_permissions[perm_name])
            db.commit()

        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            print("🌱 检测到干净的数据库环境，正在为您初始化创建多维 RBAC 超级演示账号...")
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            init_username = "admin"
            init_password = "admin@123"
            hashed_pwd = pwd_context.hash(init_password)

            admin_user = User(
                username=init_username,
                password_hash=hashed_pwd,
                nickname="系统超级管理员",
                is_active=True,
            )
            admin_user.roles.append(admin_role)
            db.add(admin_user)
            db.commit()
            print("====================================================")
            print("🎉 包含「全量中台管理Scope」的账号初始化成功！")
            print(f"   👤 账号 (Username): {init_username}")
            print(f"   🔑 密码 (Password): {init_password}")
            print(f"   🛡️ 绑定角色组: {admin_role.name}")
            print(f"   🔓 注入总权限数: {len(admin_role.permissions)} 个")
            print("====================================================")
        else:
            if admin_role not in admin_user.roles:
                admin_user.roles.append(admin_role)
                db.commit()
                print("🔄 [OnAuth RBAC] 成功为已有 admin 账户追补最高权力控制组记录！")

        _seed_default_risk_rules(db, admin_user.id if admin_user else None)

    except Exception as exc:
        print(f"❌ 初始化用户及权限组失败: {exc}")
    finally:
        db.close()


def bootstrap_system() -> None:
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    configure_windows_event_loop_policy()
    init_db()
    seed_initial_user()
    _BOOTSTRAPPED = True

