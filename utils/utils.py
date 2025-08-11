from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError  # <-- correct import
from fastapi import HTTPException

from config import SECRET_KEY, ALGORITHM, JWT_ACCESS_LIFESPAN, JWT_REFRESH_LIFESPAN


from datetime import datetime, timedelta

def generate_otp():
    import random
    return str(random.randint(100000, 999999))

def create_jwt(userId: str, type="access", remember_me=False):
    if (type == "access"):
        lifespan = timedelta(hours=JWT_ACCESS_LIFESPAN)
    else:
        lifespan = timedelta(days=30) if remember_me else timedelta(hours=JWT_REFRESH_LIFESPAN)
    payload = {
        "sub": userId,
        "exp": datetime.now() + lifespan,
        "rm": remember_me if type == "refresh" else None  # Remember Me flag. This will be checked
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)




# Verifies the token by decoding it and validating it's properties, if present.
# For example, if the token has an exp field, it checks if the token is expired and 
# raises an exception if so. 
def verify_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    
    except ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
