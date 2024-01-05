---
description: API3-Broken Object Property Level Authorization (BOPLA)
---

# Excessive Data Exposure

### API Documentation

Understanding how to use API documentation is crucial for effective testing. API documentation typically includes sections like:

1. **Overview:** Provides a high-level introduction, authentication, and rate-limiting information.
2. **Functionality:** Describes actions using HTTP methods and endpoints.
3. **Request Requirements:** Specifies authentication, parameters, path variables, headers, and body information.

#### API Documentation Conventions

* **Path Variables:** Indicated by a colon (`:`) or curly brackets (`{}`) in the endpoint. Example: `/user/:id` or `/user/{id}`.
* **Optional Input:** Square brackets (`[]`) indicate optional input. Example: `/api/v1/user?find=[name]`.
* **Multiple Values:** Double bars (`|`) represent different possible values. Example: `"blue" | "green" | "red"`.

Understanding these conventions helps in creating well-formed requests and troubleshooting.

### Using Swagger Editor with crAPI

1. Import crAPI Swagger file into Swagger Editor.
2. Visualize API endpoints, parameters, request body, and example responses.
3. Explore various paths and understand object key naming schemes.

### Editing Postman Collection Variables

1. Access collection editor in Postman.
2. Check and update collection variables, especially the `baseUrl`.

### Updating Postman Collection Authorization

1. Use the Authorization tab in the collection editor.
2. Select the appropriate authorization type (e.g., Bearer Token).
3. Obtain a Bearer Token through authentication and update the collection.

### Excessive Data Exposure

#### Ingredients:

* Response includes more information than requested.
* Sensitive information is exposed.

#### Example:

**Request**

```http
GET /api/v1/user?=CloudStrife
```

**Response**

```json
200 OK HTTP 1.1

{"id": "5501",
"fname": "Cloud",
"lname": "Strife",
"privilege": "user",
"representative": [
    {"name": "Don Coreneo",
    "id": "2203",
    "email": "dcorn@gmail.com",
    "privilege": "admin",
    "MFA": false }
]}
```

In this example, sensitive information about an administrator is exposed along with the requested user's information.

#### Identifying Excessive Data Exposure in crAPI

1. Explore GET requests in crAPI Swagger.
2. Check the `GET /identity/api/v2/user/dashboard` request.
3. Identify interesting object key names (e.g., "id", "name", "email").
4. Explore other endpoints, e.g., `GET /community/api/v2/community/posts/recent`.
5. Use Burp Suite's Repeater to intercept API requests and reveal sensitive information.

Understanding API documentation, conventions, and identifying excessive data exposure vulnerabilities are crucial steps in API security testing.
