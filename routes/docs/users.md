# 📘 User API Documentation

This API provides endpoints to manage users, including creating, retrieving, and deleting users.

**Base URL:** `/users`

---

## 📌 Endpoints

### 🔹 Create User

**POST** `/users/create`

Creates a new user if the email is not already registered.

#### Request Body

```json
{
  "email": "example@example.com"
}
```
Response `(201 Created)`
```json 
{
  "id": "uuid",
  "email": "example@example.com"
}
```
Errors
`400 Bad Request – Email already registered.`

🔹 Get User by ID

**GET** `/users/get/by-id/{user_id}`

Retrieves a user by their UUID.

Path Parameters
user_id (UUID): The unique ID of the user.

Response `(200 OK)`
```json 
{
  "id": "uuid",
  "email": "example@example.com"
}
```
Errors
`404 Not Found – User not found.`

🔹 Get User by Email

**GET** `/users/get/by-email/{email}`

Retrieves a user by their email address.

Path Parameters
email (string): The email address of the user.

Response `(200 OK)`
```json 
{
  "id": "uuid",
  "email": "example@example.com"
}
```
Errors
`404 Not Found – User not found.`

🔹 Delete User by ID

**DELETE** `/users/delete/by-id`

Permanently deletes a user by their UUID.

Query Parameters
user_id (UUID): The unique ID of the user to delete.

Response
`204 No Content – Successfully deleted.`

Errors
`404 Not Found – User not found.`

🧱 Models
🔸 UserCreate
```json 
{
  "email": "example@example.com"
}
```
🔸 UserRead
```json  
{
  "id": "uuid",
  "email": "example@example.com"
}
```
