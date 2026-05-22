# ConFuse Auth Middleware

Authentication and authorization service for the ConFuse platform. Handles Auth0 tokens, OAuth flows, API keys, and user sessions.

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
│   │ Auth0      │   │   OAuth2    │   │  API Keys   │              │
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

- **Auth0 Tokens**: Validate Auth0 tokens
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
| `/auth/refresh` | POST | Refresh Auth0 token |
| `/auth/verify` | GET | Verify Auth0 token |


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
| `TOKEN_CACHE_TTL_SECONDS` | Token cache TTL | `900` |
| `FEATURE_TOGGLE_SERVICE_URL` | Feature toggle service | `http://localhost:3099` |


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
- [API Key Management](docs/api-keys.md)

## License

MIT