# OTP API Documentation

## Overview

The OTP (One-Time Password) API provides secure authentication functionality for event-based verification. This API allows you to generate, verify, and manage OTP codes for users associated with specific events.

## Base URL

```
http://localhost:8000
```

## Authentication

This API uses event-based OTP authentication. Each OTP is tied to a specific event and email address.

## Data Models

### OTPCreateRequest

```json
{
  "email": "string",
  "event_id": "uuid"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's email address |
| event_id | UUID | Yes | Unique identifier for the event |

### OTPVerifyRequest  

```json
{
  "email": "string",
  "event_id": "uuid",
  "otp_code": "string"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's email address |
| event_id | UUID | Yes | Unique identifier for the event |
| otp_code | string | Yes | 6-digit OTP code |

### OTPResponse

```json
{
  "id": "uuid",
  "email": "string",
  "event_id": "uuid",
  "otp_code": "string",
  "expires_at": "datetime",
  "used": "boolean",
  "created_at": "datetime"
}
```

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique OTP identifier |
| email | string | User's email address |
| event_id | UUID | Associated event identifier |
| otp_code | string | 6-digit verification code |
| expires_at | datetime | OTP expiration timestamp |
| used | boolean | Whether OTP has been used |
| created_at | datetime | OTP creation timestamp |

## API Endpoints

### Generate OTP

Creates a new OTP for a user and event combination.

**Endpoint:** `POST /otp/generate`

**Request Body:**
```json
{
  "email": "user@example.com",
  "event_id": "00000000-0000-0000-0000-000000000001"
}
```

**Response:** `201 Created`
```json
{
  "id": "12345678-1234-1234-1234-123456789012",
  "email": "user@example.com",
  "event_id": "00000000-0000-0000-0000-000000000001",
  "otp_code": "123456",
  "expires_at": "2025-08-04T15:30:00Z",
  "used": false,
  "created_at": "2025-08-04T15:00:00Z"
}
```

**Error Responses:**
- `400 Bad Request` - Invalid request data
- `422 Unprocessable Entity` - Validation errors

### Verify OTP

Verifies an OTP code for a specific user and event.

**Endpoint:** `POST /otp/verify`

**Request Body:**
```json
{
  "email": "user@example.com",
  "event_id": "00000000-0000-0000-0000-000000000001",
  "otp_code": "123456"
}
```

**Response:** `200 OK`
```json
{
  "verified": true,
  "message": "OTP verified successfully"
}
```

**Error Responses:**
- `400 Bad Request` - Invalid OTP code, expired, or already used
- `404 Not Found` - OTP not found
- `422 Unprocessable Entity` - Validation errors

### Delete OTP

Removes an OTP from the system.

**Endpoint:** `DELETE /otp/{otp_code}`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| otp_code | string | Yes | 6-digit OTP code to delete |

**Response:** `200 OK`
```json
{
  "deleted": true,
  "message": "OTP deleted successfully"
}
```

**Error Responses:**
- `404 Not Found` - OTP not found
- `400 Bad Request` - Invalid OTP code format

## Business Logic

### OTP Generation
- Generates a 6-digit numeric code
- Sets expiration time (typically 5-10 minutes from creation)
- Associates OTP with specific email and event combination
- Marks OTP as unused initially

### OTP Verification  
- Validates the OTP code against email and event
- Checks if OTP is not expired
- Ensures OTP hasn't been used previously
- Marks OTP as used after successful verification

### OTP Cleanup
- Allows deletion of specific OTP codes
- Useful for cleanup operations or manual invalidation

## Usage Examples

### Complete OTP Flow

1. **Generate OTP**
```bash
curl -X POST "http://localhost:8000/otp/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "event_id": "00000000-0000-0000-0000-000000000001"
  }'
```

2. **Verify OTP**  
```bash
curl -X POST "http://localhost:8000/otp/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "event_id": "00000000-0000-0000-0000-000000000001",
    "otp_code": "123456"
  }'
```

3. **Delete OTP**
```bash
curl -X DELETE "http://localhost:8000/otp/123456"
```

## Security Considerations

- OTP codes expire automatically for security
- Each OTP can only be used once
- OTPs are tied to specific email and event combinations
- Always use HTTPS in production environments
- Consider implementing rate limiting for OTP generation
- Store OTP codes securely (hashed if possible)

## Error Handling

The API returns standard HTTP status codes:

| Status Code | Description |
|-------------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 404 | Not Found |
| 422 | Unprocessable Entity |
| 500 | Internal Server Error |

Error responses include descriptive messages:
```json
{
  "detail": "Error description here"
}
```

## Testing

The API includes comprehensive test coverage for:
- OTP generation and validation
- OTP verification workflow
- OTP deletion functionality
- Edge cases and error scenarios

Run tests with:
```bash
pytest test_main.py -v
```

## Dependencies

- FastAPI
- SQLAlchemy (async)
- UUID support
- Datetime handling
- Pydantic for data validation

## Environment Setup

For Windows users, the application includes:
```python
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
```

This ensures proper async operation on Windows systems.