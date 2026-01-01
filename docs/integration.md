# Auth Middleware Integration Guide

> How other ConFuse services integrate with auth-middleware

## Overview

Every ConFuse service depends on auth-middleware for authentication. This guide shows how to integrate.

## Integration Patterns

### Pattern 1: JWT Verification (Most Common)

Used by: api-backend, client-connector, frontend

```
Service                        Auth-Middleware
   │                                 │
   │ GET /auth/verify                │
   │ Authorization: Bearer <token>   │
   │────────────────────────────────>│
   │                                 │
   │  { valid: true, user: {...} }   │
   │<────────────────────────────────│
```

### Pattern 2: API Key Validation

Used by: data-connector (webhooks), service-to-service

```
Service                        Auth-Middleware
   │                                 │
   │ POST /api-keys/validate         │
   │ { apiKey: "key_xxx" }           │
   │────────────────────────────────>│
   │                                 │
   │ { valid: true, userId, scopes } │
   │<────────────────────────────────│
```

### Pattern 3: OAuth Token Access

Used by: data-connector (accessing GitHub/Drive)

```
Service                        Auth-Middleware
   │                                 │
   │ GET /oauth/tokens/:provider     │
   │ X-User-Id: <user_id>            │
   │────────────────────────────────>│
   │                                 │
   │ { accessToken, refreshToken }   │
   │<────────────────────────────────│
```

## Implementation Examples

### Node.js / Express

```typescript
// lib/auth-client.ts
import axios from 'axios';

const authClient = axios.create({
  baseURL: process.env.AUTH_MIDDLEWARE_URL || 'http://localhost:3001',
  timeout: 5000,
});

export interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
}

export interface VerifyResult {
  valid: boolean;
  user?: User;
}

export async function verifyToken(token: string): Promise<VerifyResult> {
  try {
    const response = await authClient.get('/auth/verify', {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      return { valid: false };
    }
    throw error;
  }
}

export async function validateApiKey(apiKey: string): Promise<{
  valid: boolean;
  userId?: string;
  scopes?: string[];
}> {
  try {
    const response = await authClient.post('/api-keys/validate', { apiKey });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      return { valid: false };
    }
    throw error;
  }
}
```

```typescript
// middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import { verifyToken, User } from '../lib/auth-client';

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    const result = await verifyToken(token);
    
    if (!result.valid || !result.user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = result.user;
    next();
  } catch (error) {
    console.error('Auth verification failed:', error);
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
}

// Optional auth - continues even without token
export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      const result = await verifyToken(token);
      if (result.valid && result.user) {
        req.user = result.user;
      }
    } catch (error) {
      // Continue without auth
    }
  }
  
  next();
}
```

### Python / FastAPI

```python
# lib/auth_client.py
import httpx
from typing import Optional
from pydantic import BaseModel
import os

AUTH_MIDDLEWARE_URL = os.getenv("AUTH_MIDDLEWARE_URL", "http://localhost:3001")

class User(BaseModel):
    id: str
    email: str
    name: str
    roles: list[str] = []

class VerifyResult(BaseModel):
    valid: bool
    user: Optional[User] = None

async def verify_token(token: str) -> VerifyResult:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{AUTH_MIDDLEWARE_URL}/auth/verify",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0
            )
            response.raise_for_status()
            return VerifyResult(**response.json())
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return VerifyResult(valid=False)
            raise

async def validate_api_key(api_key: str) -> dict:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{AUTH_MIDDLEWARE_URL}/api-keys/validate",
                json={"apiKey": api_key},
                timeout=5.0
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return {"valid": False}
            raise
```

```python
# middleware/auth.py
from fastapi import Depends, HTTPException, Header
from typing import Optional
from lib.auth_client import verify_token, validate_api_key, User

async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> User:
    # Try JWT first
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        result = await verify_token(token)
        if result.valid and result.user:
            return result.user
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Try API key
    if x_api_key:
        result = await validate_api_key(x_api_key)
        if result.get("valid"):
            # Create minimal user from API key
            return User(
                id=result["userId"],
                email="",
                name="API Key User",
                roles=result.get("scopes", [])
            )
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    raise HTTPException(status_code=401, detail="No authentication provided")

# Optional auth
async def get_optional_user(
    authorization: Optional[str] = Header(None)
) -> Optional[User]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization[7:]
    try:
        result = await verify_token(token)
        return result.user if result.valid else None
    except Exception:
        return None
```

```python
# Usage in routes
from fastapi import APIRouter, Depends
from middleware.auth import get_current_user, User

router = APIRouter()

@router.get("/protected")
async def protected_route(user: User = Depends(get_current_user)):
    return {"message": f"Hello, {user.name}!"}

@router.get("/public")
async def public_route(user: Optional[User] = Depends(get_optional_user)):
    if user:
        return {"message": f"Hello, {user.name}!"}
    return {"message": "Hello, anonymous!"}
```

### Rust

```rust
// src/auth/client.rs
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub user: Option<User>,
}

pub struct AuthClient {
    client: Client,
    base_url: String,
}

impl AuthClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
        }
    }

    pub async fn verify_token(&self, token: &str) -> Result<VerifyResult, reqwest::Error> {
        let response = self.client
            .get(format!("{}/auth/verify", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if response.status() == 401 {
            return Ok(VerifyResult { valid: false, user: None });
        }

        response.json().await
    }

    pub async fn validate_api_key(&self, api_key: &str) -> Result<ApiKeyResult, reqwest::Error> {
        let response = self.client
            .post(format!("{}/api-keys/validate", self.base_url))
            .json(&serde_json::json!({ "apiKey": api_key }))
            .send()
            .await?;

        response.json().await
    }
}
```

## Service-Specific Integration

### API Backend

```typescript
// Verify all incoming requests
app.use('/v1/*', requireAuth);

// Public endpoints (no auth)
app.get('/health', healthHandler);
app.get('/v1/public/*', publicHandler);
```

### Data Connector

```python
# Webhook endpoints use API key
@router.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_api_key: str = Header(...)
):
    result = await validate_api_key(x_api_key)
    if not result["valid"]:
        raise HTTPException(401)
    # Process webhook...
```

### Client Connector

```python
# WebSocket authentication
async def websocket_auth(websocket: WebSocket):
    token = websocket.query_params.get("token")
    api_key = websocket.query_params.get("key")
    
    if token:
        result = await verify_token(token)
        if result.valid:
            return result.user
    elif api_key:
        result = await validate_api_key(api_key)
        if result["valid"]:
            return create_user_from_key(result)
    
    await websocket.close(code=4001)
    return None
```

## Health Check Integration

Always check auth-middleware availability:

```typescript
async function checkAuthHealth(): Promise<boolean> {
  try {
    const response = await authClient.get('/health');
    return response.status === 200;
  } catch {
    return false;
  }
}

// In your health endpoint
app.get('/health', async (req, res) => {
  const authHealthy = await checkAuthHealth();
  
  res.json({
    status: authHealthy ? 'healthy' : 'degraded',
    services: {
      auth: authHealthy ? 'connected' : 'unavailable'
    }
  });
});
```

## Error Handling

Handle auth service failures gracefully:

```typescript
try {
  const result = await verifyToken(token);
  // ...
} catch (error) {
  if (error.code === 'ECONNREFUSED') {
    // Auth service is down
    return res.status(503).json({
      error: 'Authentication service temporarily unavailable'
    });
  }
  
  if (error.code === 'ETIMEDOUT') {
    // Auth service is slow
    return res.status(504).json({
      error: 'Authentication timed out'
    });
  }
  
  throw error;
}
```
