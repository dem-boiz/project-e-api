import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from config.logging_config import get_logger

logger = get_logger("api.requests")

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Log the incoming request
        logger.info(f"→ {request.method} {request.url.path} - Client: {request.client.host if request.client else 'unknown'}")
        
        # Call the next middleware/endpoint
        response: Response = await call_next(request)
        
        # Calculate response time
        process_time = time.time() - start_time
        
        # Log the response
        logger.info(f"← {request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.4f}s")
        
        # Add response time header
        response.headers["X-Process-Time"] = str(process_time)
        
        return response
