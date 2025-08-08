# Events API Documentation

## Overview

The Events API provides endpoints for managing events in the system. It follows RESTful conventions and uses FastAPI with async/await patterns for optimal performance.

**Base URL:** `/events`  
**Tags:** `events`

## Architecture

The API follows a layered architecture pattern:
- **Router Layer**: FastAPI router handling HTTP requests
- **Handler Layer**: Business logic handlers for each endpoint
- **Service Layer**: `EventService` for orchestrating business operations
- **Repository Layer**: `EventRepository` for data access
- **Database Layer**: Async SQLAlchemy session management

## Dependencies

### EventService Dependency
```python
async def get_event_service(session: AsyncSession = Depends(get_async_session)) -> EventService:
    return EventService(session)
```

All endpoints use the `get_event_service` dependency to inject an `EventService` instance with an async database session.

## Endpoints

### 1. Create Event

Creates a new event in the system.

**Endpoints:**
- `POST /events/`
- `POST /events`

**Request Body:**
```json
{
  // EventCreateSchema fields
}
```

**Response:**
- **Status Code:** `201 Created`
- **Body:** Created event details

**Example:**
```bash
curl -X POST "http://localhost:8000/events/" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Tech Conference 2024",
    "description": "Annual technology conference",
    "date": "2024-09-15T09:00:00Z"
  }'
```

---

### 2. Get All Events

Retrieves a list of all events.

**Endpoints:**
- `GET /events/`
- `GET /events`

**Parameters:** None

**Response:**
- **Status Code:** `200 OK`
- **Body:** Array of event objects

**Example:**
```bash
curl -X GET "http://localhost:8000/events/"
```

---

### 3. Get Event by ID

Retrieves a specific event by its unique identifier.

**Endpoint:** `GET /events/get/by-id/{event_id}`

**Path Parameters:**
- `event_id` (string): The unique identifier of the event

**Response:**
- **Status Code:** `200 OK`
- **Body:** Event object

**Example:**
```bash
curl -X GET "http://localhost:8000/events/get/by-id/123e4567-e89b-12d3-a456-426614174000"
```

---

### 4. Get Event by Name

Retrieves a specific event by its name.

**Endpoint:** `GET /events/get/by-name/{name}`

**Path Parameters:**
- `name` (string): The name of the event

**Response:**
- **Status Code:** `200 OK`
- **Body:** Event object

**Example:**
```bash
curl -X GET "http://localhost:8000/events/get/by-name/Tech%20Conference%202024"
```

---

### 5. Update Event

Updates an existing event with new data.

**Endpoint:** `PATCH /events/{event_id}`

**Path Parameters:**
- `event_id` (string): The unique identifier of the event to update

**Request Body:**
```json
{
  // EventUpdateSchema fields (partial update)
}
```

**Response:**
- **Status Code:** `200 OK`
- **Body:** Updated event details

**Example:**
```bash
curl -X PATCH "http://localhost:8000/events/123e4567-e89b-12d3-a456-426614174000" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description for the tech conference"
  }'
```

---

### 6. Delete Event

Deletes an event from the system.

**Endpoint:** `DELETE /events/{event_id}`

**Path Parameters:**
- `event_id` (string): The unique identifier of the event to delete

**Response:**
- **Status Code:** `204 No Content`
- **Body:** Empty

**Example:**
```bash
curl -X DELETE "http://localhost:8000/events/123e4567-e89b-12d3-a456-426614174000"
```

## Schemas

### EventCreateSchema
Used for creating new events. Contains all required fields for event creation.

### EventUpdateSchema  
Used for updating existing events. Supports partial updates - only provided fields will be updated.

## Error Handling

The API uses standard HTTP status codes:

- `200 OK` - Successful GET/PATCH operations
- `201 Created` - Successful POST operations
- `204 No Content` - Successful DELETE operations
- `400 Bad Request` - Invalid request data
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation errors
- `500 Internal Server Error` - Server errors

## Authentication & Authorization

*Note: No authentication/authorization middleware is visible in the provided code. If authentication is required, it should be documented here.*

## Rate Limiting

*Note: No rate limiting is visible in the provided code. If rate limiting is implemented, it should be documented here.*

## Development Notes

### Multiple Route Definitions
Several endpoints define multiple routes for the same functionality:
- `POST /events/` and `POST /events` (with and without trailing slash)
- `GET /events/` and `GET /events`

This provides flexibility for clients but may be simplified if not needed.

### Async Pattern
All endpoints are async and use `await` for database operations, ensuring non-blocking I/O operations.

### Dependency Injection
The API uses FastAPI's dependency injection system to provide `EventService` instances to each endpoint, promoting clean separation of concerns.

## Testing

Example test cases should cover:
- Creating events with valid/invalid data
- Retrieving events that exist/don't exist
- Updating events with partial data
- Deleting events that exist/don't exist
- Edge cases for name-based lookups (special characters, encoding)

## Future Enhancements

Potential improvements could include:
- Pagination for the get all events endpoint
- Filtering and sorting options
- Bulk operations
- Event search functionality
- Authentication and authorization
- Rate limiting
- Caching for frequently accessed events