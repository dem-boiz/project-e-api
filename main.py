from fastapi import FastAPI
from routes.user_route import router as user_router
from routes.base_route import router as base_router
from routes.otp_route import router as otp_router
from routes.event_route import router as event_router


app = FastAPI() 
app.include_router(user_router)
app.include_router(otp_router)
app.include_router(base_router)
app.include_router(event_router)