# ConFuse Auth Middleware

Authentication and authorization service for the ConFuse platform. Handles JWT tokens, OAuth flows, API keys, and user sessions.

## Role in ConFuse

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT REQUEST                              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     AUTH-MIDDLEWARE (This Service)                   │
│                            Port: 3010                               │
│                                                                      │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│   │    JWT      │   │   OAuth2    │   │  API Keys   │              │
│   │ Validation  │   │   Flows     │   │ Management  │              │
│   └─────────────┘   └─────────────┘   └─────────────┘              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ Authenticated Request
                                ▼
                    ┌───────────────────────┐
                    │   Other Services      │
                    │   (api-backend, etc.) │
                    └───────────────────────┘
```

## Features

- **JWT Tokens**: Issue and validate JSON Web Tokens
- **OAuth2 Flows**: GitHub, Google, GitLab OAuth integrations
- **API Keys**: Generate and manage API keys for programmatic access
- **Session Management**: Redis-backed session storage
- **Rate Limiting**: Per-user and per-IP rate limits
- **Audit Logging**: All authentication events logged

## API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | Email/password login |
| `/auth/register` | POST | User registration |
| `/auth/logout` | POST | Invalidate session |
| `/auth/refresh` | POST | Refresh JWT token |
| `/auth/verify` | GET | Verify JWT token |

### OAuth

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/github` | GET | Start GitHub OAuth flow |
| `/oauth/github/callback` | GET | GitHub OAuth callback |
| `/oauth/google` | GET | Start Google OAuth flow |
| `/oauth/google/callback` | GET | Google OAuth callback |

### API Keys

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api-keys` | GET | List user's API keys |
| `/api-keys` | POST | Create new API key |
| `/api-keys/:id` | DELETE | Revoke API key |
| `/api-keys/validate` | POST | Validate API key |

## Quick Start

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env

# Run development server
npm run dev

# Run tests
npm test
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3010` |
| `DATABASE_URL` | PostgreSQL connection | Required |
| `REDIS_URL` | Redis connection | Required |
| `JWT_SECRET` | JWT signing secret | Required |
| `JWT_EXPIRES_IN` | Token expiry | `24h` |
| `FEATURE_TOGGLE_SERVICE_URL` | Feature toggle service | `http://localhost:3099` |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth secret | - |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `GOOGLE_CLIENT_SECRET` | Google OAuth secret | - |

## Logging

The service includes extensive structured logging for debugging:

```
[AUTH-MIDDLEWARE] Starting Auth Middleware Service...
[FEATURE-TOGGLE] Feature toggle client initialized
[AUTH-MIDDLEWARE] [REQUEST] [req_xxx] GET /api/auth/me started
[FEATURE-TOGGLE] Checking if auth bypass is enabled...
[FEATURE-TOGGLE] Auth bypass enabled: true
[FEATURE-TOGGLE] Getting bypass demo user...
 Auth bypass enabled - using demo user: demo@confuse.dev
[AUTH-MIDDLEWARE] [RESPONSE] [req_xxx] [SUCCESS] GET /me 200 794ms
```

Log prefixes:
- `[AUTH-MIDDLEWARE]` - Service-level operations
- `[FEATURE-TOGGLE]` - Feature toggle client operations
- `[REQUEST]` / `[RESPONSE]` - HTTP request lifecycle

## Feature Toggle Integration

The auth-middleware integrates with feature-context-toggle for development features:

| Toggle | Effect |
|--------|--------|
| `authBypass` | Skip authentication, use demo user |
| `debugLogging` | Enable verbose logging |

When `authBypass` is enabled, the `/api/auth/me` endpoint returns a demo user without requiring authentication.

## Integration with Other Services

All ConFuse services call auth-middleware to validate requests:

```javascript
// In api-backend or any other service
const validateToken = async (token) => {
  const response = await fetch('http://auth-middleware:3001/auth/verify', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return response.json();
};
```

## Documentation

See the [docs/](docs/) folder for detailed documentation:
- [Authentication Flow](docs/authentication.md)
- [OAuth Setup](docs/oauth-setup.md)
- [API Key Management](docs/api-keys.md)

## License

MIT