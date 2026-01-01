# Auth Middleware API Reference

> Complete API documentation for the ConFuse Auth-Middleware

## Base URL

```
Development: http://localhost:3001
Production: https://auth.confuse.io
```

## Authentication

Most endpoints require authentication via:
- **Bearer Token**: `Authorization: Bearer <jwt_token>`
- **API Key**: `X-API-Key: <api_key>` (for service-to-service only)

---

## Endpoints

### Authentication

#### POST /auth/register

Create a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "John Doe"
}
```

**Response (201):**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "createdAt": "2026-01-01T12:00:00Z"
  },
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG...",
  "expiresIn": 3600
}
```

**Errors:**
- `400` - Validation error (weak password, invalid email)
- `409` - Email already registered

---

#### POST /auth/login

Authenticate with email and password.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200):**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe"
  },
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG...",
  "expiresIn": 3600
}
```

**Errors:**
- `400` - Missing credentials
- `401` - Invalid credentials
- `429` - Too many login attempts

---

#### POST /auth/logout

Invalidate current session and tokens.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "message": "Logged out successfully"
}
```

---

#### POST /auth/refresh

Get new access token using refresh token.

**Request:**
```json
{
  "refreshToken": "eyJhbG..."
}
```

**Response (200):**
```json
{
  "accessToken": "eyJhbG...",
  "expiresIn": 3600
}
```

**Errors:**
- `401` - Invalid or expired refresh token

---

#### GET /auth/verify

Verify an access token (used by other services).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "valid": true,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "roles": ["user"]
  }
}
```

**Errors:**
- `401` - Invalid or expired token

---

#### POST /auth/forgot-password

Request password reset email.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "If the email exists, a reset link has been sent"
}
```

---

#### POST /auth/reset-password

Reset password with token from email.

**Request:**
```json
{
  "token": "reset-token-from-email",
  "password": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "message": "Password reset successfully"
}
```

---

### OAuth

#### GET /oauth/:provider

Start OAuth flow for a provider.

**Providers:** `github`, `google`, `gitlab`

**Query Parameters:**
- `redirect_uri` - Where to redirect after auth (optional)
- `state` - CSRF protection token (optional)

**Response:** Redirects to provider's authorization page

---

#### GET /oauth/:provider/callback

OAuth callback endpoint (don't call directly).

**Query Parameters:**
- `code` - Authorization code from provider
- `state` - CSRF token

**Response:** Redirects to frontend with token

---

### API Keys

#### GET /api-keys

List all API keys for current user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "keys": [
    {
      "id": "uuid",
      "name": "Production API Key",
      "prefix": "key_live_abc",
      "scopes": ["read", "write"],
      "lastUsedAt": "2026-01-01T12:00:00Z",
      "expiresAt": "2027-01-01T00:00:00Z",
      "createdAt": "2026-01-01T00:00:00Z"
    }
  ]
}
```

---

#### POST /api-keys

Create a new API key.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "name": "My API Key",
  "scopes": ["read", "write"],
  "expiresInDays": 365
}
```

**Response (201):**
```json
{
  "id": "uuid",
  "name": "My API Key",
  "key": "key_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "scopes": ["read", "write"],
  "expiresAt": "2027-01-01T00:00:00Z",
  "createdAt": "2026-01-01T00:00:00Z"
}
```

> ⚠️ **Important:** The full key is only shown once. Store it securely!

---

#### DELETE /api-keys/:id

Revoke an API key.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "message": "API key revoked"
}
```

---

#### POST /api-keys/validate

Validate an API key (used by other services).

**Request:**
```json
{
  "apiKey": "key_live_xxxx"
}
```

**Response (200):**
```json
{
  "valid": true,
  "userId": "uuid",
  "scopes": ["read", "write"]
}
```

**Errors:**
- `401` - Invalid or expired API key

---

### Sessions

#### GET /sessions

List active sessions for current user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "sessions": [
    {
      "id": "uuid",
      "ipAddress": "192.168.1.1",
      "userAgent": "Mozilla/5.0...",
      "current": true,
      "lastActiveAt": "2026-01-01T12:00:00Z",
      "createdAt": "2026-01-01T00:00:00Z"
    }
  ]
}
```

---

#### DELETE /sessions/:id

Terminate a specific session.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "message": "Session terminated"
}
```

---

#### DELETE /sessions

Terminate all sessions except current.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "message": "All other sessions terminated",
  "count": 3
}
```

---

### User Profile

#### GET /me

Get current user profile.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "avatarUrl": "https://...",
  "connectedProviders": ["github", "google"],
  "createdAt": "2026-01-01T00:00:00Z"
}
```

---

#### PATCH /me

Update current user profile.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "name": "Jane Doe"
}
```

**Response (200):**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "Jane Doe"
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Email or password is incorrect",
    "details": {}
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request body |
| `INVALID_CREDENTIALS` | 401 | Wrong email/password |
| `TOKEN_EXPIRED` | 401 | Token has expired |
| `TOKEN_INVALID` | 401 | Token is malformed |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Rate Limits

| Endpoint | Limit | Window | Headers |
|----------|-------|--------|---------|
| `/auth/login` | 5 | 15 min | X-RateLimit-* |
| `/auth/register` | 3 | 1 hour | X-RateLimit-* |
| `/auth/refresh` | 10 | 1 min | X-RateLimit-* |
| `/api-keys/validate` | 100 | 1 min | X-RateLimit-* |
| Others | 60 | 1 min | X-RateLimit-* |

Response headers:
- `X-RateLimit-Limit`: Maximum requests
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Reset timestamp
