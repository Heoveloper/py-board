import os
from dotenv import load_dotenv

load_dotenv()

# 연결된 DB 정보
HOST = os.getenv("host")
USER = os.getenv("user")
PASSWORD = os.getenv("password")
DB = os.getenv("db")
CHARSET = os.getenv("charset")

# 앱 시크릿키
APP_SECRET_KEY = os.getenv("app.secret_key")

# JWT 시크릿키
JWT_SECRET_KEY = os.getenv("jwt_secret_key")