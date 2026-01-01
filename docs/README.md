# Auth Middleware Documentation

## Overview

The auth-middleware service handles all authentication and authorization for the ConFuse platform. It provides JWT-based authentication, OAuth2 integration, and API key management.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     AUTH-MIDDLEWARE                               │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   JWT Service   │  │  OAuth Service  │  │ API Key Service │  │
│  │                 │  │                 │  │                 │  │
│  │ • Sign tokens   │  │ • GitHub OAuth  │  │ • Create keys   │  │
│  │ • Verify tokens │  │ • Google OAuth  │  │ • Validate keys │  │
│  │ • Refresh       │  │ • GitLab OAuth  │  │ • Revoke keys   │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                   │
│  ┌─────────────────┐  ┌─────────────────┐                       │
│  │ Session Manager │  │  Rate Limiter   │                       │
│  │                 │  │                 │                       │
│  │ • Redis-backed  │  │ • Per-user      │                       │
│  │ • TTL handling  │  │ • Per-IP        │                       │
│  └─────────────────┘  └─────────────────┘                       │
│                                                                   │
│                    ┌─────────────────┐                           │
│                    │    Database     │                           │
│                    │                 │                           │
│                    │ • Users table   │                           │
│                    │ • API keys      │                           │
│                    │ • Sessions      │                           │
│                    └─────────────────┘                           │
└──────────────────────────────────────────────────────────────────┘
```

## Authentication Flows

### 1. Email/Password Login

```
Client                    Auth-Middleware              Database
  │                             │                         │
  │ POST /auth/login            │                         │
  │ {email, password}           │                         │
  │────────────────────────────>│                         │
  │                             │ Lookup user             │
  │                             │────────────────────────>│
  │                             │<────────────────────────│
  │                             │                         │
  │                             │ Verify password (bcrypt)│
  │                             │                         │
  │                             │ Generate JWT            │
  │                             │                         │
  │ {token, refreshToken, user} │                         │
  │<────────────────────────────│                         │
```

### 2. OAuth Flow (GitHub Example)

```
Client                    Auth-Middleware              GitHub
  │                             │                         │
  │ GET /oauth/github           │                         │
  │────────────────────────────>│                         │
  │                             │                         │
  │ Redirect to GitHub          │                         │
  │<────────────────────────────│                         │
  │                             │                         │
  │ ──────────────────────────────────────────────────────>
  │                             │    User authorizes     │
  │ <──────────────────────────────────────────────────────
  │                             │                         │
  │ GET /oauth/github/callback  │                         │
  │ ?code=xxx                   │                         │
  │────────────────────────────>│                         │
  │                             │ Exchange code for token │
  │                             │────────────────────────>│
  │                             │<────────────────────────│
  │                             │                         │
  │                             │ Get user info           │
  │                             │────────────────────────>│
  │                             │<────────────────────────│
  │                             │                         │
  │                             │ Create/update user      │
  │                             │ Generate JWT            │
  │                             │                         │
  │ Redirect with token         │                         │
  │<────────────────────────────│                         │
```

### 3. API Key Validation

```
Service                   Auth-Middleware              Database
  │                             │                         │
  │ POST /api-keys/validate     │                         │
  │ {apiKey: "key_xxx"}         │                         │
  │────────────────────────────>│                         │
  │                             │ Hash + lookup key       │
  │                             │────────────────────────>│
  │                             │<────────────────────────│
  │                             │                         │
  │                             │ Check expiry, scope     │
  │                             │                         │
  │ {valid, userId, scopes}     │                         │
  │<────────────────────────────│                         │
```

## JWT Token Structure

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user-uuid",
    "email": "user@example.com",
    "roles": ["user", "admin"],
    "iat": 1704067200,
    "exp": 1704153600
  }
}
```

## API Key Format

```
key_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
│   │    │
│   │    └── 32 random characters
│   └── Environment (live/test)
└── Prefix
```

## Database Schema

```sql
-- Users
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255),
  name VARCHAR(255),
  avatar_url VARCHAR(500),
  provider VARCHAR(50),
  provider_id VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- API Keys
CREATE TABLE api_keys (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  key_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  scopes TEXT[],
  last_used_at TIMESTAMP,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Sessions
CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  refresh_token_hash VARCHAR(255),
  ip_address INET,
  user_agent TEXT,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);
```

## Integration Examples

### From api-backend (Node.js)

```javascript
const authClient = require('./lib/auth-client');

// Middleware to verify JWT
const requireAuth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const result = await authClient.verifyToken(token);
    req.user = result.user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Middleware to verify API key
const requireApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'No API key provided' });
  }
  
  try {
    const result = await authClient.validateApiKey(apiKey);
    req.user = { id: result.userId };
    req.scopes = result.scopes;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid API key' });
  }
};
```

### From Python Services

```python
import httpx

class AuthClient:
    def __init__(self, base_url: str = "http://auth-middleware:3001"):
        self.base_url = base_url
    
    async def verify_token(self, token: str) -> dict:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/auth/verify",
                headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
            return response.json()
    
    async def validate_api_key(self, api_key: str) -> dict:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api-keys/validate",
                json={"apiKey": api_key}
            )
            response.raise_for_status()
            return response.json()
```

## Security Considerations

1. **Password Hashing**: bcrypt with work factor 12
2. **Token Storage**: JWTs are stateless; refresh tokens stored hashed
3. **API Key Storage**: Only hash stored, original shown once on creation
4. **Rate Limiting**: 10 login attempts per IP per minute
5. **HTTPS Only**: All endpoints require TLS in production

## Related Services

| Service | Relationship |
|---------|--------------|
| api-backend | Calls auth-middleware to verify requests |
| client-connector | Uses JWT validation for WebSocket auth |
| data-connector | Uses API key validation for service-to-service |
| frontend | Initiates OAuth flows and stores tokens |
