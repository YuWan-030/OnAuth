import os
import datetime
import logging
import redis
import jwt
from fastapi import Header, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from config import SECRET_KEY, ALGORITHM
# 🌟 核心引入：确保引入了 AppDevice 模型
from database import get_db, AppCredential, AppDevice

security = HTTPBearer()

# 统一初始化 Redis 客户端
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "127.0.0.1"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=0,
    decode_responses=True
)

# 动态获取管理员 TOKEN
ADMIN_TOKEN = os.getenv("PLATFORM_ADMIN_TOKEN")


def verify_admin_rpc(x_admin_token: str = Header(..., alias="X-Admin-Token", description="管理员核心身份令牌")):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="中台权限凭证不合法，拒绝访问管理端！"
        )
    return x_admin_token


def verify_client_token(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        # 🌟 核心拦截：接收客户端硬件设备指纹请求头，设为 None 避免阻断其他常规 B 端 API
        x_device_id: str = Header(None, alias="X-Device-ID", description="客户端硬件设备唯一指纹"),
        db: Session = Depends(get_db)
):
    """
    云端核心网关拦截器：全盘审计 Token 时效、黑名单状态、三层资产安全熔断、以及多开设备指纹限制
    """
    token = credentials.credentials

    # ==================== 🛠️ 防御层 1：Redis 宕机容错与黑名单校验 ====================
    try:
        if redis_client.exists(f"revoked_token:{token}"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="凭证安全拒绝：该身份凭证已被主动注销或拉黑，请重新登录"
            )
    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
        # 降级策略：如果 Redis 临时挂了，记录警告日志，靠 JWT 自包含的时间戳强行防守
        logging.warning("⚠️ Redis 服务失联，黑名单校验临时降级跳过，请尽快检查 Redis 状态！")

    # ==================== 🛡️ 防御层 2：JWT 签名与合法性基础校验 ====================
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="客户端请求携带的令牌已过期失效，请引导重新授权"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="非法令牌，签名篡改校验未通过"
        )

    # 提取载荷元数据
    client_id = payload.get("sub")
    token_type = payload.get("token_type", "license")
    current_time = datetime.datetime.now()

    # 安全阻断：严防死守，绝对不能让客户端拿着 refresh_token 来当 access_token 混过业务 API
    if token_type == "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="安全阻断：不能直接使用刷新令牌访问业务 API"
        )

    # ==================== 🚨 防御层 3：三层金字塔架构多级硬熔断核心审计 ====================
    cred = db.query(AppCredential).filter(AppCredential.client_id == client_id).first()

    if not cred:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="凭证解析成功，但对应的鉴权节点已在数据库中被粉碎级移除"
        )

    # 🚀 【核心修复点】剥洋葱级链路穿透提取
    current_app = cred.app  # 命中中层“独立应用”对象 (例如：A.1程序)
    current_group = current_app.group  # 向上命中顶级“组织/工作室”对象 (例如：A工作室)

    # 🚨 【纵深防御拦截】执行三层资产状态联动联动网关熔断（修复漏判漏洞）
    if not cred.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="安全合规性拒绝：该凭证对应的单独授权密钥通道已被管理员手工封禁关闭！"
        )

    if not current_app.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"安全合规性拒绝：当前独立程序 [{current_app.app_name}] 已被中台强制熔断下线！"
        )

    if not current_group.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"安全合规性拒绝：该应用所属的工作室组织主体 [{current_group.group_name}] 已被中台整体降维封禁！"
        )

    # 【绝对防水线】动态对撞时间戳，解决 OAuth2.0 刷新期内无限白嫖漏洞
    if cred.expire_at and cred.expire_at < current_time:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"您的中台订阅已于 {cred.expire_at.strftime('%Y-%m-%d %H:%M:%S')} 到期，接口访问已实时锁死，请联系管理员续费充值！"
        )

    # ==================== 🔒 防御层 4：设备指纹防多开白嫖审计 ====================
    # 当判定来访的是 JWT 长期激活码轨道（License）时，启动高强度硬件设备对撞
    if token_type == "license":
        # 强制特征收敛：如果客户端死活不传 X-Device-ID 请求头，直接将其定义为非法逆向爬虫请求
        if not x_device_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="合规性阻断：核心硬件设备身份凭证缺失，拒绝接入云中台"
            )

        # 连表检索当前硬件指纹是否已经在该凭证的已知白名单里
        linked_device = db.query(AppDevice).filter(
            AppDevice.credential_id == cred.id,
            AppDevice.device_id == x_device_id
        ).first()

        if linked_device:
            # 合法老设备：高频刷新最近一次的在线活跃时间戳，用于多租户后台监控
            linked_device.last_seen_at = current_time
            db.commit()
        else:
            # 陌生新设备：尝试计算当前凭证已经绑定的硬件机器基数
            current_device_count = db.query(AppDevice).filter(AppDevice.credential_id == cred.id).count()

            # 极限对撞：若已绑数量超过或等于该激活码分配的最高 max_devices 上限，直接触发物理熔断
            if current_device_count >= cred.max_devices:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"安全阻断：该授权码绑定的设备数已达上限（最大 {cred.max_devices} 台）。请在管理后台解绑历史设备或升级多机版！"
                )

            # 水位线未满：说明该激活码还富余绑定名额，允许当前全新设备录入并无感绑定
            new_device = AppDevice(
                credential_id=cred.id,
                device_id=x_device_id,
                activated_at=current_time,
                last_seen_at=current_time
            )
            db.add(new_device)
            db.commit()
            logging.info(f"🌱 [OnAuth] 凭证通道 [{client_id}] 成功完成新硬件设备无感绑定解锁: {x_device_id}")

    # 校验通过，返回合法的数据库凭证对象
    return cred