from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.routes import router as auth_router
from auth.utils import verify_jwt

app = FastAPI()
security = HTTPBearer()

app.include_router(auth_router)

@app.get("/")
def read_root():
    return {"message": "Hello, world"}

@app.get("/me")
def get_me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    email = verify_jwt(credentials.credentials)
    return {"email": email}
