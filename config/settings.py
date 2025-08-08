from dotenv import load_dotenv
import os

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256") # TODO Change to RS256 in future for better security?
OTP_EXPIRY_SECONDS = int(os.getenv("OTP_EXPIRY_SECONDS", 300))
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_LIFESPAN = float(os.getenv("JWT_LIFESPAN", 1))

if DATABASE_URL is None:
    raise ValueError("DATABASE_URL is not set in .env")