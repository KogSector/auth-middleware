# ConHub Auth Middleware

Pure JavaScript authentication middleware using Auth0 for all ConHub microservices.

## Features

- **Auth0 Token Exchange**: Convert Auth0 tokens to ConHub JWTs
- **Session Management**: JWT-based with refresh tokens
- **User Management**: Auto-create users on first login
- **Role-Based Access**: Admin and user roles from Auth0 permissions
- **Service-to-Service Auth**: Internal API key verification

## Quick Start

```bash
# Install dependencies
npm install

# Generate Prisma client
npm run prisma:generate

# Push database schema
npm run prisma:push

# Start development server
npm run dev
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | None | Health check |
| `/api/auth/auth0/exchange` | POST | Auth0 Bearer | Exchange Auth0 → ConHub JWT |
| `/api/auth/me` | GET | ConHub Bearer | Get current user |
| `/api/auth/refresh` | POST | None | Refresh access token |
| `/api/auth/logout` | POST | ConHub Bearer | Revoke session |
| `/internal/verify` | POST | X-Api-Key | Verify token (service-to-service) |

## Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Auth0
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://api.conhub.dev

# Database
DATABASE_URL=postgresql://...

# Internal API
INTERNAL_API_KEY=your-secret-key
```

## Using in Other Microservices

### Python (FastAPI/data-connector)

```python
import httpx

async def verify_token(token: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:3010/internal/verify",
            json={"token": token},
            headers={"X-Api-Key": INTERNAL_API_KEY}
        )
        return response.json()
```

### JavaScript (Other Node services)

```javascript
const { verifyConHubToken } = require('conhub-auth-middleware/src/services/jwt');

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  try {
    req.user = verifyConHubToken(token);
    next();
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
}
```

## Docker

```bash
docker build -t conhub-auth-middleware .
docker run -p 3010:3010 --env-file .env conhub-auth-middleware
```