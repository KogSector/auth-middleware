# ConFuse Auth Middleware

> Authentication and Authorization Service for the ConFuse Platform

## What is this service?

The **auth-middleware** is ConFuse's security layer. It handles all authentication (who you are) and authorization (what you can do) for the entire platform.

## Quick Start

```bash
# Clone and install
git clone https://github.com/confuse/auth-middleware.git
cd auth-middleware
npm install

# Configure
cp .env.example .env

# Run migrations
npm run migrate

# Start development server
npm run dev
```

The server starts at `http://localhost:3001`.

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Service design and flows |
| [API Reference](api-reference.md) | Complete endpoint documentation |
| [Configuration](configuration.md) | Environment variables |
| [Integration](integration.md) | How other services use this |
| [Development](development.md) | Local development setup |
| [OAuth Setup](oauth-setup.md) | Setting up OAuth providers |
| [Troubleshooting](troubleshooting.md) | Common issues |

## How It Fits in ConFuse

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                     │
│              Frontend  │  API Backend  │  Other Services                │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    AUTH-MIDDLEWARE (This Service)                        │
│                            Port: 3001                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐             │
│   │     JWT      │    │    OAuth2    │    │   API Keys   │             │
│   │   Handler    │    │    Handler   │    │   Handler    │             │
│   │              │    │              │    │              │             │
│   │ • Sign       │    │ • GitHub     │    │ • Create     │             │
│   │ • Verify     │    │ • Google     │    │ • Validate   │             │
│   │ • Refresh    │    │ • GitLab     │    │ • Revoke     │             │
│   └──────────────┘    └──────────────┘    └──────────────┘             │
│                                                                          │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐             │
│   │   Sessions   │    │ Rate Limiting│    │    Audit     │             │
│   │   (Redis)    │    │              │    │   Logging    │             │
│   └──────────────┘    └──────────────┘    └──────────────┘             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │      PostgreSQL        │
                    │    (Users, Keys)       │
                    └────────────────────────┘
```

## Key Features

### 1. JWT Authentication
- Issue access tokens (short-lived)
- Issue refresh tokens (long-lived)
- Verify tokens on each request
- Token rotation for security

### 2. OAuth2 Integration
- GitHub OAuth for repository access
- Google OAuth for Drive access
- GitLab OAuth for project access
- Extensible for new providers

### 3. API Key Management
- Generate API keys for programmatic access
- Scope-based permissions
- Key rotation
- Usage tracking

### 4. Session Management
- Redis-backed sessions
- Device tracking
- Session invalidation
- Concurrent session limits

### 5. Security Features
- Rate limiting (login attempts, token requests)
- Audit logging (all auth events)
- Password hashing (bcrypt)
- CSRF protection

## Technology Stack

| Technology | Purpose |
|------------|---------|
| Node.js | Runtime |
| Express.js | Web framework |
| TypeScript | Type safety |
| PostgreSQL | User data storage |
| Redis | Session storage, rate limiting |
| bcrypt | Password hashing |
| jsonwebtoken | JWT operations |
| passport.js | OAuth strategies |

## Database Schema

```sql
-- Core tables managed by this service
users          -- User accounts
api_keys       -- API keys for programmatic access
sessions       -- Active login sessions
oauth_tokens   -- OAuth provider tokens
audit_logs     -- Authentication event logs
```

## Related Services

Every ConFuse service depends on auth-middleware:

| Service | How It Uses Auth |
|---------|------------------|
| api-backend | Validates JWT on every request |
| data-connector | Validates API keys for webhooks |
| client-connector | Validates WebSocket connections |
| frontend | Initiates OAuth flows, stores tokens |

## License

MIT - ConFuse Team
