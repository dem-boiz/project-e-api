from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import HTTPException
from config.settings import SECRET_KEY, ALGORITHM, JWT_LIFESPAN

def generate_otp():
    import random
    return str(random.randint(100000, 999999))

def create_jwt(userId: str):
    payload = {
        "sub": userId,
        "exp": datetime.utcnow() + timedelta(hours=JWT_LIFESPAN)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
