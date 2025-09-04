import secrets
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256") # TODO Change to RS256 in future for better security?
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_ACCESS_LIFESPAN = float(os.getenv("JWT_ACCESS_LIFESPAN", 0.25))
JWT_REFRESH_LIFESPAN = float(os.getenv("JWT_REFRESH_LIFESPAN", 1.0))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
ENV = os.getenv("ENV", "dev")
CSRF_PEPPER = os.getenv("CSRF_TOKEN_PEPPER", secrets.token_hex(32)).encode("utf-8")
DEVICE_GRANT_LIMIT = os.getenv("DEVICE_GRANT_LIMIT", 5)  # Default to 5 if not set
EVENT_TOKEN_PEPPER = os.getenv("EVENT_TOKEN_PEPPER", secrets.token_hex(32)).encode("utf-8")
INVITE_HOUR_EXPIRY = int(os.getenv("INVITE_HOUR_EXPIRY", 72))  # Default to 72 hours if not set
MAIL_FROM = os.getenv("MAIL_FROM", "project.e.invites@gmail.com")
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "project.e.invites@gmail.com")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "place-holder-password")
CLIENT_URL = os.getenv("CLIENT_URL", "http://localhost:5173")
USER_GRANT_LIMIT = int(os.getenv("USER_GRANT_LIMIT", 10))

if DATABASE_URL is None:
    raise ValueError("DATABASE_URL is not set in .env")