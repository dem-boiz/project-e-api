# Logging System Documentation

## Overview

This project includes a comprehensive logging system that provides detailed tracking of application behavior, authentication events, API requests, and errors.

## Features

### 1. **Multiple Log Files**
- **`app.log`** - General application logs (all levels)
- **`errors.log`** - Error-level logs only
- **`auth.log`** - Authentication-specific logs
- **`api.log`** - API request/response logs

### 2. **Log Levels**
- **DEBUG** - Detailed debugging information
- **INFO** - General information about application flow
- **WARNING** - Warning messages for potentially problematic situations
- **ERROR** - Error messages for actual problems
- **CRITICAL** - Critical errors that may cause the application to stop

### 3. **Log Rotation**
- Each log file is limited to 10MB
- Up to 5 backup files are kept
- Automatic rotation when size limit is reached

### 4. **Console and File Output**
- Logs are written to both console and files
- Console shows simplified format
- Files contain detailed format with timestamps, log levels, function names, and line numbers

## Configuration

### Environment Variables
- `LOG_LEVEL` - Set the minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  - Default: INFO
  - Example in .env: `LOG_LEVEL=DEBUG`

### Log Directory
- Logs are stored in: `logs/` directory (created automatically)

## Usage Examples

### In Services (e.g., AuthService)
```python
from config.logging_config import get_logger

logger = get_logger("auth")

async def login(self, login_data: LoginRequestSchema):
    logger.info(f"Login attempt for email: {login_data.email}")
    # ... login logic
    logger.info(f"Login successful for host: {host.id}")
```

### In API Routes
```python
from config.logging_config import get_logger

logger = get_logger("api.events")

@router.post("/")
async def create_event(data: EventCreateSchema):
    logger.info(f"Creating new event: {data.name}")
    # ... creation logic
    logger.info(f"Event created successfully: {data.name}")
```

### For Database Operations
```python
logger = get_logger("database")
logger.debug("Executing database query")
```

## Log Format Examples

### Console Output (Simple)
```
2025-08-10 10:51:17 | INFO     | Starting FastAPI application initialization
2025-08-10 10:51:17 | INFO     | → POST /auth/login - Client: 127.0.0.1
```

### File Output (Detailed)
```
2025-08-10 10:51:17 | INFO     | app             | main            |   15 | Starting FastAPI application initialization
2025-08-10 10:51:17 | INFO     | auth            | login           |   57 | Login attempt for email: user@example.com
```

## Middleware Features

### Request Logging Middleware
- Logs all incoming HTTP requests
- Tracks response time
- Adds `X-Process-Time` header to responses
- Format: `→ METHOD /path - Client: IP` (incoming)
- Format: `← METHOD /path - Status: 200 - Time: 0.1234s` (outgoing)

## Best Practices

### 1. **Use Appropriate Log Levels**
- `DEBUG` - Temporary debugging, token details, detailed flow
- `INFO` - Normal operations, successful actions, user actions
- `WARNING` - Authentication failures, validation issues
- `ERROR` - Exceptions, failed operations, unexpected errors

### 2. **Include Context**
- User IDs, email addresses, event IDs
- Action being performed
- Relevant parameters

### 3. **Security Considerations**
- Never log passwords or sensitive tokens
- Be careful with PII (Personally Identifiable Information)
- Use user IDs instead of full user data when possible

## Example Log Outputs

### Authentication Flow
```
2025-08-10 10:51:17 | INFO     | auth            | authenticate_host |   35 | Authentication attempt for email: user@example.com
2025-08-10 10:51:17 | INFO     | auth            | authenticate_host |   45 | Authentication successful for email: user@example.com, host_id: 123e4567-e89b-12d3-a456-426614174000
2025-08-10 10:51:17 | INFO     | auth            | login            |   67 | JWT token created for host: 123e4567-e89b-12d3-a456-426614174000 (user@example.com)
```

### API Request Flow
```
2025-08-10 10:51:20 | INFO     | api.requests    | dispatch         |   12 | → POST /events - Client: 127.0.0.1
2025-08-10 10:51:20 | INFO     | api.events      | create_event     |  127 | Creating new event: My Event for host: 123e4567-e89b-12d3-a456-426614174000
2025-08-10 10:51:20 | INFO     | api.events      | create_event     |  130 | Event created successfully: My Event
2025-08-10 10:51:20 | INFO     | api.requests    | dispatch         |   19 | ← POST /events - Status: 201 - Time: 0.0234s
```

### Error Handling
```
2025-08-10 10:51:25 | WARNING  | auth            | authenticate_host |   39 | Authentication failed: Host not found for email: invalid@example.com
2025-08-10 10:51:25 | ERROR    | auth            | login            |   61 | Login failed for email: invalid@example.com
```

## Monitoring and Debugging

### To Debug Issues
1. Check `errors.log` for error-level messages
2. Set `LOG_LEVEL=DEBUG` in .env for detailed debugging
3. Check `auth.log` for authentication-related issues
4. Check `api.log` for request/response patterns

### Performance Monitoring
- Request timing information in api.log
- Response time headers for frontend monitoring
- Database query performance (if enabled)

## File Locations
- **Configuration**: `config/logging_config.py`
- **Middleware**: `middleware/request_logging.py`
- **Log Files**: `logs/` directory
- **Settings**: `.env` file (`LOG_LEVEL` variable)
