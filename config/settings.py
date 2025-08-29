import secrets
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256") # TODO Change to RS256 in future for better security?
OTP_EXPIRY_SECONDS = int(os.getenv("OTP_EXPIRY_SECONDS", 300))
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_ACCESS_LIFESPAN = float(os.getenv("JWT_ACCESS_LIFESPAN", 0.25))
JWT_REFRESH_LIFESPAN = float(os.getenv("JWT_REFRESH_LIFESPAN", 1.0))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
ENV = os.getenv("ENV", "dev")
CSRF_PEPPER = os.getenv("CSRF_TOKEN_PEPPER", secrets.token_hex(32)).encode("utf-8")
DEVICE_LIMIT = os.getenv("DEVICE_GRANT_LIMIT", 5)  # Default to 5 if not set
EVENT_TOKEN_PEPPER = os.getenv("EVENT_TOKEN_PEPPER", secrets.token_hex(32)).encode("utf-8")
INVITE_HOUR_EXPIRY = int(os.getenv("INVITE_HOUR_EXPIRY", 72))  # Default to 72 hours if not set

if DATABASE_URL is None:
    raise ValueError("DATABASE_URL is not set in .env")