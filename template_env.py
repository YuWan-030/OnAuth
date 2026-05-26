import os

from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, PrefixLoader

from config import APP_VERSION

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_LOGO_DIR = os.path.normpath(os.path.join(BASE_DIR, "uploads", "app_logos"))
ADMIN_WEB_DIR = os.path.normpath(os.path.join(BASE_DIR, "admin_web"))
WEB_DIR = os.path.normpath(os.path.join(BASE_DIR, "user_web"))
TENANT_WEB_DIR = os.path.normpath(os.path.join(BASE_DIR, "tenant_web"))
TEMPLATES_DIR = os.path.normpath(os.path.join(BASE_DIR, "templates"))

os.makedirs(APP_LOGO_DIR, exist_ok=True)

jinja2_env = Environment(
    loader=PrefixLoader(
        {
            "admin": FileSystemLoader(ADMIN_WEB_DIR),
            "user": FileSystemLoader(WEB_DIR),
            "tenant": FileSystemLoader(TENANT_WEB_DIR),
            "shared": FileSystemLoader(TEMPLATES_DIR),
        }
    ),
    autoescape=True,
)

jinja2_env.globals["APP_VERSION"] = APP_VERSION

templates = Jinja2Templates(env=jinja2_env)

