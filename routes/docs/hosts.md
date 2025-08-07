# Hosts API Documentation

This document describes the REST API endpoints for managing hosts in the system.

## Base URL
All endpoints are prefixed with `/hosts`

## Authentication
*Note: Authentication requirements are not specified in the provided code.*

## Data Models

### HostCreateSchema
Schema for creating a new host (fields not specified in provided code).

### HostReadSchema
Schema for reading host data (fields not specified in provided code).

### HostUpdateSchema
Schema for updating host data (fields not specified in provided code).

## Endpoints

### Create Host
Creates a new host in the system.

- **URL:** `/hosts/`
- **Method:** `POST`
- **Request Body:** `HostCreateSchema`
- **Response:** `HostReadSchema`
- **Status Code:** `201 Created`

#### Example Request
```json
POST /hosts/
Content-Type: application/json

{
  // HostCreateSchema fields
}
```

#### Example Response
```json
HTTP/1.1 201 Created
Content-Type: application/json

{
  // HostReadSchema fields
}
```

---

### Delete Host
Deletes a host by their unique identifier.

- **URL:** `/hosts/{user_id}`
- **Method:** `DELETE`
- **Path Parameters:**
  - `user_id` (UUID): The unique identifier of the host to delete
- **Response:** No content
- **Status Code:** `204 No Content`

#### Example Request
```json
DELETE /hosts/550e8400-e29b-41d4-a716-446655440000
```

#### Example Response
```json
HTTP/1.1 204 No Content
```

---

### Get Host by ID
Retrieves a host by their unique identifier.

- **URL:** `/hosts/by-id/{user_id}`
- **Method:** `GET`
- **Path Parameters:**
  - `user_id` (UUID): The unique identifier of the host
- **Response:** `HostReadSchema`
- **Status Code:** `200 OK`

#### Example Request
```json
GET /hosts/by-id/550e8400-e29b-41d4-a716-446655440000
```

#### Example Response
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  // HostReadSchema fields
}
```

---

### Get Host by Email
Retrieves a host by their email address.

- **URL:** `/hosts/by-email/{email}`
- **Method:** `GET`
- **Path Parameters:**
  - `email` (EmailStr): The email address of the host
- **Response:** `HostReadSchema`
- **Status Code:** `200 OK`

#### Example Request
```json
GET /hosts/by-email/user@example.com
```

#### Example Response
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  // HostReadSchema fields
}
```

---

### Update Host
Updates an existing host's information.

- **URL:** `/hosts/{user_id}`
- **Method:** `PATCH`
- **Path Parameters:**
  - `user_id` (UUID): The unique identifier of the host to update
- **Request Body:** `HostUpdateSchema`
- **Response:** `HostReadSchema`
- **Status Code:** `200 OK`

#### Example Request
```json
PATCH /hosts/550e8400-e29b-41d4-a716-446655440000
Content-Type: application/json

{
  // HostUpdateSchema fields
}
```

#### Example Response
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  // Updated HostReadSchema fields
}
```

## Error Handling

The API uses standard HTTP status codes to indicate the success or failure of requests:

- **200 OK** - Request successful
- **201 Created** - Resource created successfully
- **204 No Content** - Request successful, no content returned
- **400 Bad Request** - Invalid request data
- **404 Not Found** - Resource not found
- **422 Unprocessable Entity** - Validation error
- **500 Internal Server Error** - Server error

### Error Response Format
```json
{
  "detail": "Error message describing what went wrong"
}
```

## Dependencies

This API uses the following key dependencies:

- **FastAPI** - Web framework
- **SQLAlchemy** - Database ORM with async support
- **Pydantic** - Data validation and serialization
- **UUID** - Unique identifier handling

## Notes

1. All endpoints use async/await patterns for non-blocking operations
2. Database sessions are managed automatically through dependency injection
3. The API uses UUID for unique identifiers
4. Email validation is handled through Pydantic's `EmailStr` type
5. The code contains some naming inconsistencies (e.g., `user_id` in paths but handling hosts)
