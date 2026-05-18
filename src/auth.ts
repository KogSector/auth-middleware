/**
 * ConFuse Auth Middleware - Complete Authentication System
 * 
 * Consolidated authentication, OAuth, and token management
 * Merged from: services/auth0.ts, services/oauth.ts, middleware/auth.ts, routes/auth.ts
 */

import { Router, type Request, type Response } from 'express';
import type { Response as ExpressResponse, NextFunction } from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { Redis } from 'ioredis';
import { randomBytes, createHash } from 'crypto';
import { logger } from './utils/logger.js';

import { config } from './config.js';
import { tokenCache } from './services/cache.js';
import { findOrCreateByAuth0, findByAuth0Sub, toProfile } from './services/user.js';
import prisma from './infra/db/client.js';
import type { AuthenticatedRequest, AuthExchangeResponse, TokenVerifyResponse, Auth0Claims, Auth0UserInfo, CacheStats } from './types/index.js';

// ============================================================================
// OAUTH STATE MANAGEMENT (from services/oauth.ts)
// ============================================================================

export interface OAuthState {
    provider: string;
    userId?: string;
    redirectUri: string;
    codeVerifier?: string;
    createdAt: number;
    expiresAt: number;
}

export class OAuthStateService {
    private redis: Redis;
    private readonly PREFIX = 'oauth:state:';
    private readonly TTL = 600; // 10 minutes

    constructor() {
        this.redis = new Redis(config.redisUrl, {
            keepAlive: 10000,
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            }
        });

        this.redis.on('error', (err: Error) => {
            logger.error('[OAUTH-STATE] Redis connection error', { error: err.message });
        });

        this.redis.on('connect', () => {
            logger.info('[OAUTH-STATE] Redis connected');
        });
    }

    /**
     * Generate secure random state
     */
    generateState(): string {
        return randomBytes(32).toString('hex');
    }

    /**
     * Generate PKCE Code Verifier and Challenge
     */
    generatePKCE(): { codeVerifier: string; codeChallenge: string } {
        const codeVerifier = randomBytes(32).toString('base64url');
        const codeChallenge = createHash('sha256')
            .update(codeVerifier)
            .digest('base64url');
        return { codeVerifier, codeChallenge };
    }

    /**
     * Store OAuth state in Redis
     */
    async storeState(state: string, data: Omit<OAuthState, 'createdAt' | 'expiresAt'>): Promise<void> {
        const stateData: OAuthState = {
            ...data,
            createdAt: Date.now(),
            expiresAt: Date.now() + (this.TTL * 1000)
        };

        await this.redis.setex(
            `${this.PREFIX}${state}`,
            this.TTL,
            JSON.stringify(stateData)
        );
    }

    /**
     * Validate OAuth state
     */
    async validateState(state: string): Promise<OAuthState | null> {
        const data = await this.redis.get(`${this.PREFIX}${state}`);
        if (!data) return null;

        try {
            const stateData = JSON.parse(data) as OAuthState;
            
            // Check if expired
            if (Date.now() > stateData.expiresAt) {
                await this.redis.del(`${this.PREFIX}${state}`);
                return null;
            }

            return stateData;
        } catch {
            return null;
        }
    }

    /**
     * Consume OAuth state (delete after use)
     */
    async consumeState(state: string): Promise<void> {
        await this.redis.del(`${this.PREFIX}${state}`);
    }
}

// ============================================================================
// AUTH0 TOKEN MANAGEMENT (from services/auth0.ts)
// ============================================================================

// JWKS remote key set (cached by jose library)
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

/**
 * Get or create JWKS cache
 */
function getJWKS() {
    if (!jwks) {
        jwks = createRemoteJWKSet(
            new URL(`https://${config.auth0.domain}/.well-known/jwks.json`)
        );
    }
    return jwks;
}

/**
 * Hash token for cache key
 */
export function hashToken(token: string): string {
    let hash = 5381;
    for (let i = 0; i < token.length; i++) {
        hash = ((hash << 5) + hash) ^ token.charCodeAt(i);
    }
    return hash.toString(36);
}

/**
 * Verify Auth0 JWT token
 */
export async function verifyAuth0Token(token: string): Promise<Auth0Claims> {
    // Check cache first
    const tokenHash = hashToken(token);
    const cached = await tokenCache.getToken(tokenHash);
    if (cached) {
        // Convert CachedToken back to Auth0Claims format
        return {
            sub: cached.userId,
            email: cached.email,
            roles: cached.roles,
        } as Auth0Claims;
    }

    const jwks = getJWKS();
    
    try {
        const { payload } = await jwtVerify(token, jwks, {
            issuer: `https://${config.auth0.domain}/`,
            audience: config.auth0.audience,
        });

        // Normalize payload to Auth0Claims for downstream use
        const claims = payload as Auth0Claims;

        // Cache the validated token
        await tokenCache.setToken(tokenHash, {
            userId: claims.sub || '',
            email: claims.email || '',
            roles: extractRoles(claims),
            validatedAt: Date.now(),
            expiresAt: Date.now() + (config.tokenCacheTtlSeconds * 1000),
        });

        return claims;
    } catch (error) {
        throw new Error(`Invalid token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Extract user info from Auth0 claims
 */
export function extractUserInfo(claims: Auth0Claims): Auth0UserInfo {
    return {
        auth0Sub: claims.sub,
        email: claims.email || '',
        name: claims.name || claims.email || null,
        picture: claims.picture || null,
    };
}

/**
 * Extract roles from Auth0 claims
 */
export function extractRoles(claims: Auth0Claims): string[] {
    const asRecord = claims as unknown as Record<string, unknown>;
    const rolesValue = asRecord['roles'] ?? asRecord['https://confuse.dev/roles'] ?? asRecord['http://confuse.dev/roles'] ?? [];
    return Array.isArray(rolesValue) ? (rolesValue as string[]) : [];
}

/**
 * Auth0 Management API Client
 */
export class Auth0ManagementClient {
    private static instance: Auth0ManagementClient;
    private accessToken: string | null = null;
    private tokenExpiresAt: number = 0;

    static getInstance(): Auth0ManagementClient {
        if (!Auth0ManagementClient.instance) {
            Auth0ManagementClient.instance = new Auth0ManagementClient();
        }
        return Auth0ManagementClient.instance;
    }

    private async getAccessToken(): Promise<string> {
        if (this.accessToken && Date.now() < this.tokenExpiresAt) {
            return this.accessToken;
        }

        try {
            const response = await fetch(`https://${config.auth0.domain}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_id: config.auth0.clientId,
                    client_secret: config.auth0.clientSecret,
                    audience: `https://${config.auth0.domain}/api/v2/`,
                    grant_type: 'client_credentials'
                })
            });

            if (!response.ok) {
                throw new Error('Failed to get Auth0 management token');
            }

            const data = await response.json();
            this.accessToken = data.access_token;
            this.tokenExpiresAt = Date.now() + (data.expires_in * 1000) - 60000; // 1min buffer

            if (this.accessToken) {
                return this.accessToken;
            }
            throw new Error('No access token received');
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Auth0 management auth failed: ${message}`);
        }
    }

    async getUserProfile(userId: string): Promise<Record<string, unknown>> {
        const token = await this.getAccessToken();
        
        const response = await fetch(`https://${config.auth0.domain}/api/v2/users/${userId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`Failed to get user profile: ${response.statusText}`);
        }

        return response.json();
    }

    async getUsersByEmail(email: string): Promise<Record<string, unknown>[]> {
        const token = await this.getAccessToken();
        
        const response = await fetch(`https://${config.auth0.domain}/api/v2/users-by-email?email=${encodeURIComponent(email)}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`Failed to get users by email: ${response.statusText}`);
        }

        return response.json();
    }
}

/**
 * Get token cache statistics
 */
export function getTokenCacheStats(): CacheStats {
    const stats = tokenCache.getStats();
    return {
        hits: stats.hits,
        misses: stats.misses,
        hitRate: stats.hitRate,
        size: 0, // Not tracked in TokenCacheService
        capacity: 0, // Not tracked in TokenCacheService
    };
}

// ============================================================================
// AUTHENTICATION MIDDLEWARE (from middleware/auth.ts)
// ============================================================================

/**
 * Extract bearer token from Authorization header
 */
export function extractBearerToken(req: Request): string | null {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    return authHeader.slice(7);
}

/**
 * Require Auth0 Access Token authentication
 */
export async function requireAuth(
    req: Request,
    res: ExpressResponse,
    next: NextFunction
): Promise<void> {
    // Check if authBypass is enabled
    try {
        const bypassResponse = await fetch(`${config.featureToggleServiceUrl}/api/toggles/auth-bypass/user`);
        if (bypassResponse.ok) {
            const result = await bypassResponse.json();
            if (result.success && result.data) {
                const demoUser = result.data;
                logger.info('[AUTH-MIDDLEWARE] requireAuth: Bypassing authentication using demo user', { user: demoUser });
                
                const claims: Auth0Claims = {
                    sub: demoUser.id || 'user-rishabh-001',
                    email: demoUser.email || 'rishabh.babi@gmail.com',
                    name: demoUser.name || 'Rishabh Babi',
                    roles: demoUser.roles || ['user', 'developer', 'admin'],
                };
                (req as AuthenticatedRequest).user = claims;
                return next();
            }
        }
    } catch (err) {
        logger.debug('[AUTH-MIDDLEWARE] requireAuth: Feature toggle service bypass check failed or unavailable', { error: err instanceof Error ? err.message : String(err) });
    }

    const token = extractBearerToken(req);

    if (!token) {
        res.status(401).json({
            error: 'Authentication required',
            message: 'Please provide a valid Bearer token in the Authorization header',
        });
        return;
    }

    try {
        const claims = await verifyAuth0Token(token);
        // Augment claims with roles
        const claimsTyped = claims as Auth0Claims;
        claimsTyped.roles = extractRoles(claimsTyped);
        (req as AuthenticatedRequest).user = claimsTyped;
        next();
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid token';
        res.status(401).json({
            error: 'Invalid token',
            message,
        });
    }
}

/**
 * Optional authentication - doesn't fail if no token
 */
export async function optionalAuth(
    req: Request,
    res: ExpressResponse,
    next: NextFunction
): Promise<void> {
    // Check if authBypass is enabled
    try {
        const bypassResponse = await fetch(`${config.featureToggleServiceUrl}/api/toggles/auth-bypass/user`);
        if (bypassResponse.ok) {
            const result = await bypassResponse.json();
            if (result.success && result.data) {
                const demoUser = result.data;
                logger.info('[AUTH-MIDDLEWARE] optionalAuth: Bypassing authentication using demo user', { user: demoUser });
                
                const claims: Auth0Claims = {
                    sub: demoUser.id || 'user-rishabh-001',
                    email: demoUser.email || 'rishabh.babi@gmail.com',
                    name: demoUser.name || 'Rishabh Babi',
                    roles: demoUser.roles || ['user', 'developer', 'admin'],
                };
                (req as AuthenticatedRequest).user = claims;
                return next();
            }
        }
    } catch (err) {
        logger.debug('[AUTH-MIDDLEWARE] optionalAuth: Feature toggle service bypass check failed or unavailable', { error: err instanceof Error ? err.message : String(err) });
    }

    const token = extractBearerToken(req);

    if (token) {
        try {
            const claims = await verifyAuth0Token(token);
            (req as AuthenticatedRequest).user = claims;
        } catch {
            // Ignore errors for optional auth
        }
    }

    next();
}

/**
 * Require specific roles
 */
export function requireRoles(...requiredRoles: string[]) {
    return (req: Request, res: ExpressResponse, next: NextFunction): void => {
        const reqUser = (req as AuthenticatedRequest).user;
        if (!reqUser) {
            res.status(401).json({
                error: 'Authentication required',
            });
            return;
        }

        const userRoles = reqUser.roles || [];
        // DSA: O(1) Set.has() replaces O(n) Array.includes() for role membership checks.
        // Converts user roles to a Set once, then each required role check is O(1).
        const roleSet = new Set(userRoles);
        const hasRole = requiredRoles.length === 0 ||
            requiredRoles.some(role => roleSet.has(role));

        if (!hasRole) {
            res.status(403).json({
                error: 'Insufficient permissions',
                requiredRoles,
                userRoles,
            });
            return;
        }

        next();
    };
}

// ============================================================================
// AUTHENTICATION ROUTES (from routes/auth.ts)
// ============================================================================

// Standardized error response functions
function sendUserNotFound(res: Response, message?: string) {
    res.status(404).json({
        error: 'User not found',
        message: message || 'User not found'
    });
}

function sendConnectionNotFound(res: Response, provider: string) {
    res.status(404).json({ 
        error: `Connection for ${provider} not found or missing access token` 
    });
}

function sendInvalidApiKey(res: Response) {
    res.status(403).json({ error: 'Invalid API key' });
}

// Create router
export const authRouter = Router();

// Initialize OAuth state service
export const oAuthStateService = new OAuthStateService();

/**
 * POST /auth/login
 * Verify Auth0 token, sync user to DB, and return profile
 */
authRouter.post('/login', async (req: Request, res: Response) => {
    try {
        // Check if authBypass is active
        try {
            const bypassResponse = await fetch(`${config.featureToggleServiceUrl}/api/toggles/auth-bypass/user`);
            if (bypassResponse.ok) {
                const result = await bypassResponse.json();
                if (result.success && result.data) {
                    const demoUser = result.data;
                    logger.info('[AUTH-LOGIN] Bypassing login using demo user', { user: demoUser });
                    
                    // Return the mocked profile for the demo user
                    return res.json({
                        user: {
                            id: demoUser.id || 'user-rishabh-001',
                            auth0Sub: demoUser.id || 'user-rishabh-001',
                            email: demoUser.email || 'rishabh.babi@gmail.com',
                            name: demoUser.name || 'Rishabh Babi',
                            picture: '',
                            roles: demoUser.roles || ['user', 'developer', 'admin'],
                            createdAt: new Date().toISOString(),
                            updatedAt: new Date().toISOString()
                        }
                    });
                }
            }
        } catch (err) {
            logger.debug('[AUTH-LOGIN] Feature toggle bypass check failed', { error: err instanceof Error ? err.message : String(err) });
        }

        // Extract Auth0 token using middleware function
        const auth0Token = extractBearerToken(req);
        if (!auth0Token) {
            res.status(401).json({
                error: 'Missing or invalid Authorization header',
                message: "Expected 'Authorization: Bearer <auth0_access_token>'",
            });
            return;
        }

        // Verify Auth0 token
        let claims;
        try {
            claims = await verifyAuth0Token(auth0Token);
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            logger.warn('[AUTH-LOGIN] Auth0 token verification failed', { message });
            res.status(401).json({
                error: 'Invalid Auth0 token',
                message,
            });
            return;
        }

        // Fetch user profile from Auth0 /userinfo endpoint
        let userInfo: Record<string, unknown> = {};
        try {
            const userInfoRes = await fetch(`https://${config.auth0.domain}/userinfo`, {
                headers: { 'Authorization': `Bearer ${auth0Token}` }
            });
            if (userInfoRes.ok) {
                userInfo = await userInfoRes.json();
            }

            // Fetch from Auth0 Management API to get IdP access tokens for direct Google/Microsoft queries
            try {
                const mgmtClient = Auth0ManagementClient.getInstance();
                const fullProfile = await mgmtClient.getUserProfile(claims.sub);

                userInfo = { ...userInfo, ...(fullProfile as Record<string, unknown>) };

                // Directly query Google or Microsoft APIs for the full name if access token is available
                const identities: Array<Record<string, unknown>> = Array.isArray((fullProfile as Record<string, unknown>).identities)
                    ? ((fullProfile as Record<string, unknown>).identities as Array<Record<string, unknown>>)
                    : [];
                for (const identity of identities) {
                    const provider = String(identity['provider'] ?? '');
                    const accessToken = typeof identity['access_token'] === 'string' ? identity['access_token'] as string : '';
                    if (provider === 'google-oauth2' && accessToken) {
                        const googleRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
                            headers: { Authorization: `Bearer ${accessToken}` }
                        });
                        if (googleRes.ok) {
                            const googleUser = await googleRes.json() as Record<string, unknown>;
                            userInfo['name'] = (typeof googleUser['name'] === 'string' ? googleUser['name'] as string : userInfo['name']);
                            userInfo['picture'] = (typeof googleUser['picture'] === 'string' ? googleUser['picture'] as string : userInfo['picture']);
                        }
                    } else if (provider === 'windowslive' && accessToken) {
                        const msRes = await fetch('https://graph.microsoft.com/v1.0/me', {
                            headers: { Authorization: `Bearer ${accessToken}` }
                        });
                        if (msRes.ok) {
                            const msUser = await msRes.json() as Record<string, unknown>;
                            userInfo['name'] = (typeof msUser['displayName'] === 'string' ? msUser['displayName'] as string : userInfo['name']);
                        }
                    }
                }
            } catch (mgmtError) {
                logger.warn('[AUTH-LOGIN] Failed to fetch full Auth0 profile', { error: mgmtError });
            }

            // (provider extraction removed — not used)

        } catch (error) {
            logger.warn('[AUTH-LOGIN] Failed to fetch user info from Auth0', { error });
        }

        const email = typeof userInfo['email'] === 'string' ? userInfo['email'] as string : (typeof claims.email === 'string' ? claims.email : '');
        const name = typeof userInfo['name'] === 'string' ? userInfo['name'] as string : (typeof claims.name === 'string' ? claims.name : undefined);
        const picture = typeof userInfo['picture'] === 'string' ? userInfo['picture'] as string : (typeof claims.picture === 'string' ? claims.picture : undefined);

        const user = await findOrCreateByAuth0({
            auth0Sub: claims.sub,
            email,
            name,
            picture,
            roles: extractRoles(claims),
        });

        const response: AuthExchangeResponse = {
            user: toProfile(user),
        };

        res.json(response);

    } catch (error) {
        logger.error('[AUTH-LOGIN] Login error', { error });
        res.status(500).json({
            error: 'Internal server error',
            message: error instanceof Error ? error.message : 'Unknown error',
        });
    }
});

/**
 * GET /auth/me
 * Get current authenticated user
 */
authRouter.get('/me', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        // Normal flow - req.user is Auth0Claims
        const claims = req.user as Auth0Claims;
        
        // If claims has our demo user ID or name, mock the DB check!
        if (claims.sub === 'user-rishabh-001' || claims.sub === 'demo-user-id' || claims.sub.startsWith('user-rishabh-')) {
            return res.json({
                user: {
                    id: claims.sub,
                    auth0Sub: claims.sub,
                    email: claims.email || 'rishabh.babi@gmail.com',
                    name: claims.name || 'Rishabh Babi',
                    picture: '',
                    roles: claims.roles || ['user', 'developer', 'admin'],
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString()
                }
            });
        }

        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            // Should not happen if /login was called, but if token is valid but user not in DB
            // We could try to create here, but for now 404
            sendUserNotFound(res, 'Please call /auth/login first to sync user');
            return;
        }

        res.json({
            user: toProfile(user),
        });

    } catch (error) {
        logger.error('[AUTH-ME] Get user error', { error });
        res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/verify
 * Verify token without syncing user
 */
authRouter.post('/verify', async (req: Request, res: Response) => {
    try {
        // Check if authBypass is active
        try {
            const bypassResponse = await fetch(`${config.featureToggleServiceUrl}/api/toggles/auth-bypass/user`);
            if (bypassResponse.ok) {
                const result = await bypassResponse.json();
                if (result.success && result.data) {
                    const demoUser = result.data;
                    logger.info('[AUTH-VERIFY] Bypassing token verification using demo user', { user: demoUser });
                    
                    return res.json({
                        valid: true,
                        claims: {
                            sub: demoUser.id || 'user-rishabh-001',
                            email: demoUser.email || 'rishabh.babi@gmail.com',
                            name: demoUser.name || 'Rishabh Babi',
                            roles: demoUser.roles || ['user', 'developer', 'admin']
                        }
                    });
                }
            }
        } catch (err) {
            logger.debug('[AUTH-VERIFY] Feature toggle bypass check failed', { error: err instanceof Error ? err.message : String(err) });
        }

        const token = req.body?.token || extractBearerToken(req);

        if (!token) {
            res.status(400).json({
                error: 'Missing token',
            });
            return;
        }

        const claims = await verifyAuth0Token(token);

        const response: TokenVerifyResponse = {
            valid: true,
            claims: claims,
        };

        res.json(response);

    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid token';
        const response: TokenVerifyResponse = {
            valid: false,
            error: message,
        };
        res.json(response);
    }
});

/**
 * GET /auth/connections
 * Get user's social connections
 */
authRouter.get('/connections', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            sendUserNotFound(res);
            return;
        }

        const connections = await prisma.account.findMany({
            where: { userId: user.id },
            select: {
                provider: true,
                providerAccountId: true,
                type: true,
                scope: true,
            }
        });

        const data = connections.map(c => ({
            id: c.providerAccountId,
            platform: c.provider,
            type: c.type,
            scope: c.scope,
            username: null,
            is_active: true,
        }));

        res.json({
            success: true,
            data,
        });

    } catch (error) {
        logger.error('[AUTH-CONNECTIONS] Connections fetch error', { error });
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

/**
 * GET /auth/oauth/url
 * Generate OAuth URL for providers
 */
authRouter.get('/oauth/url', async (req: Request, res: Response) => {
    try {
        const { provider } = req.query;
        if (provider === 'github') {
            const clientId = 'Ov23liL3MQoIiV6bgA5w';
            const redirectUri = `${config.frontendUrl}/api/auth/oauth/callback`;
            const state = randomBytes(16).toString('hex');
            res.json({ url: `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&scope=repo` });
        } else {
            res.status(400).json({ error: 'Unsupported provider' });
        }
    } catch (error) {
        logger.error('[AUTH-OAUTH-URL] Error', { error });
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * POST /auth/oauth/exchange
 * Exchange code for token and save connection
 */
authRouter.post('/oauth/exchange', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);
        
        if (!user) {
            sendUserNotFound(res);
            return;
        }

        const { provider, code } = req.body;
        
        if (provider === 'github') {
            const clientId = 'Ov23liL3MQoIiV6bgA5w';
            const clientSecret = '7e1dd12025ee7c7c43e296192cf16975587729e9';
            
            const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    client_id: clientId,
                    client_secret: clientSecret,
                    code
                })
            });
            
            const tokenData = await tokenRes.json();
            
            if (tokenData.error) {
                logger.error('[AUTH-OAUTH-EXCHANGE] GitHub token error', { error: tokenData.error });
                res.status(400).json({ error: tokenData.error_description || tokenData.error });
                return;
            }
            
            const accessToken = tokenData.access_token;
            
            // Get user info to get providerAccountId
            const userRes = await fetch('https://api.github.com/user', {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            
            const userData = await userRes.json();
            const providerAccountId = String(userData.id);
            
            await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: 'github',
                        providerAccountId
                    }
                },
                update: {
                    type: 'oauth',
                    access_token: accessToken,
                    scope: tokenData.scope || 'repo',
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: 'github',
                    providerAccountId,
                    access_token: accessToken,
                    scope: tokenData.scope || 'repo',
                }
            });
            
            res.json({ success: true, message: 'GitHub connected successfully' });
        } else {
            res.status(400).json({ error: 'Unsupported provider' });
        }
    } catch (error) {
        logger.error('[AUTH-OAUTH-EXCHANGE] Error', { error });
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * GET /auth/oauth/:provider/start
 * Securely start OAuth flow with State/PKCE
 */
authRouter.get('/oauth/:provider/start', async (req: Request, res: Response) => {
    try {
        const { provider } = req.params;
        const { redirect_uri, user_id, use_pkce } = req.query;

        if (!provider || !redirect_uri) {
            res.status(400).json({ error: 'Missing provider or redirect_uri' });
            return;
        }

        const stateIdx = oAuthStateService.generateState();
        let codeVerifier: string | undefined;
        let codeChallenge: string | undefined;

        if (use_pkce === 'true') {
            const pkce = oAuthStateService.generatePKCE();
            codeVerifier = pkce.codeVerifier;
            codeChallenge = pkce.codeChallenge;
        }

        await oAuthStateService.storeState(stateIdx, {
            provider,
            userId: typeof user_id === 'string' ? user_id : undefined,
            redirectUri: redirect_uri as string,
            codeVerifier,
        });

        res.json({
            success: true,
            state: stateIdx,
            code_challenge: codeChallenge,
            message: 'OAuth state generated successfully'
        });

    } catch (error) {
        logger.error('[AUTH-OAUTH-START] OAuth start error', { error });
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * GET /auth/oauth/:provider/callback
 * Validate OAuth callback state
 */
authRouter.get('/oauth/:provider/callback', async (req: Request, res: Response) => {
    try {
        const { provider } = req.params;
        const { state, error } = req.query;

        if (error) {
            res.status(400).json({ error: typeof error === 'string' ? error : 'OAuth error' });
            return;
        }

        if (!state) {
            res.status(400).json({ error: 'Missing state parameter' });
            return;
        }

        const storedState = await oAuthStateService.validateState(state as string);

        if (!storedState) {
            res.status(400).json({ error: 'Invalid or expired state' });
            return;
        }

        if (storedState.provider !== provider) {
            res.status(400).json({ error: 'Provider mismatch' });
            return;
        }

        await oAuthStateService.consumeState(state as string);

        res.json({
            success: true,
            provider,
            redirect_uri: storedState.redirectUri,
            user_id: storedState.userId,
            code_verifier: storedState.codeVerifier,
            message: 'OAuth callback validated successfully'
        });

    } catch (error) {
        logger.error('[AUTH-OAUTH-CALLBACK] OAuth callback error', { error });
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * DELETE /auth/connections/:provider
 * Disconnect a social provider
 */
authRouter.delete('/connections/:provider', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const { provider } = req.params;

        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            sendUserNotFound(res);
            return;
        }

        await prisma.account.deleteMany({
            where: {
                userId: user.id,
                provider,
            },
        });

        res.json({
            success: true,
            message: `Disconnected ${provider} successfully`,
        });

    } catch (error) {
        logger.error('[AUTH-CONNECTIONS-DISCONNECT] Disconnect error', { error });
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/connections/sync
 * Sync user identities from Auth0 Management API
 */
authRouter.post('/connections/sync', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            sendUserNotFound(res);
            return;
        }

        const targetProvider = req.body.targetProvider as string | undefined;
        logger.info('[AUTH-CONNECTIONS] Starting sync', { email: user.email, targetProvider });

        const mgmtClient = Auth0ManagementClient.getInstance();
        // Step 1: Query Auth0 for all users that share the exact same email
        let auth0Users: Array<Record<string, unknown>> = [];
        if (user.email && user.email.trim() !== '') {
            auth0Users = await mgmtClient.getUsersByEmail(user.email);
        } else {
            const profile = await mgmtClient.getUserProfile(claims.sub);
            if (profile) {
                auth0Users = [profile];
            }
        }

        const results = [];

        // Step 2: Iterate over every matching user profile, and every identity within those profiles
        for (const auth0User of auth0Users) {
            const identities: Array<Record<string, unknown>> = Array.isArray((auth0User as Record<string, unknown>).identities)
                ? ((auth0User as Record<string, unknown>).identities as Array<Record<string, unknown>>)
                : [];

            for (const identity of identities) {
                const _providerName = String(identity['provider'] ?? '').replace('-oauth2', '');

                if (targetProvider) {
                    const normalizedTarget = targetProvider.replace('-oauth2', '').replace('google_drive', 'google').replace('windowslive', 'windowslive');
                    if (_providerName !== normalizedTarget) {
                        logger.info('[AUTH-CONNECTIONS] Skipping provider during sync', { provider: _providerName, targetProvider });
                        continue;
                    }
                }

                logger.info('[AUTH-CONNECTIONS] Syncing identity', { provider: _providerName, targetProvider });

                // Identity provider access tokens may not be present depending on Auth0 scope settings
                // We still want to record the connection so the UI updates and other parts can fallback to ENV tokens

                // Upsert the account record
                    const providerAccountId = typeof identity['user_id'] === 'string' ? identity['user_id'] as string : String(identity['user_id']);
                    const accessToken = typeof identity['access_token'] === 'string' ? identity['access_token'] as string : null;
                    const refreshToken = typeof identity['refresh_token'] === 'string' ? identity['refresh_token'] as string : null;
                    const scopeVal = typeof identity['scope'] === 'string' ? identity['scope'] as string : '';
                    const expiresAt = typeof identity['expires_at'] === 'number' ? Math.floor((identity['expires_at'] as number) * 1000) : (typeof identity['expires_at'] === 'string' && !isNaN(Number(identity['expires_at'])) ? Math.floor(Number(identity['expires_at']) * 1000) : null);

                    const result = await prisma.account.upsert({
                    where: {
                        provider_providerAccountId: {
                                provider: _providerName,
                            providerAccountId: providerAccountId,
                        }
                    },
                    update: {
                        type: 'oauth',
                            provider: _providerName,
                        providerAccountId: providerAccountId,
                        access_token: accessToken,
                        refresh_token: refreshToken,
                        scope: scopeVal,
                        expires_at: expiresAt,
                    },
                    create: {
                        userId: user.id,
                        type: 'oauth',
                        provider: _providerName,
                        providerAccountId: providerAccountId,
                        access_token: accessToken,
                        refresh_token: refreshToken,
                        scope: scopeVal,
                        expires_at: expiresAt,
                    },
                });
                results.push(result);
            }
        }

        res.json({
            success: true,
            synced: results.length,
            connections: results.map(c => ({
                id: c.providerAccountId,
                platform: c.provider,
                is_active: true,
            })),
        });

    } catch (error) {
        console.error('Sync connections error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

/**
 * GET /auth/connections/:provider/token
 * Fetch the decrypted access token for a connected provider
 */
authRouter.get('/connections/:provider/token', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const { provider } = req.params;
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            sendUserNotFound(res);
            return;
        }

        // We lookup the account that matches this user and provider
        const account = await prisma.account.findFirst({
            where: {
                userId: user.id,
                provider: provider,
            }
        });

        if (!account || !account.access_token) {
            sendConnectionNotFound(res, provider);
            return;
        }

        res.json({
            success: true,
            provider,
            access_token: account.access_token
        });

    } catch (error) {
        console.error('Get token error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/internal/tokens
 * Fetch the decrypted access token for a connected provider using internal API key
 */
authRouter.post('/internal/tokens', async (req: Request, res: Response) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== config.internalApiKey) {
            sendInvalidApiKey(res);
            return;
        }

        const { userId, provider } = req.body;

        if (!userId || !provider) {
            res.status(400).json({ error: 'Missing userId or provider' });
            return;
        }

        const account = await prisma.account.findFirst({
            where: {
                userId,
                provider,
            }
        });

        if (!account || !account.access_token) {
            sendConnectionNotFound(res, provider);
            return;
        }

        res.json({
            success: true,
            provider,
            access_token: account.access_token,
            refresh_token: account.refresh_token,
            token_type: 'Bearer' // Add if needed
        });

    } catch (error) {
        console.error('Internal token error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/validate-api-key
 * Validate internal API key and return mock user
 */
authRouter.post('/validate-api-key', async (req: Request, res: Response) => {
    try {
        const apiKey = req.headers['x-api-key'];
        
        if (apiKey !== config.internalApiKey) {
            sendInvalidApiKey(res);
            return;
        }

        // Return mock user for internal API key validation
        res.json({
            id: 'internal-service-user',
            email: 'internal@confuse.dev',
            name: 'Internal Service',
            roles: ['service'],
            workspace_id: 'system'
        });

    } catch (error) {
        console.error('API key validation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================================
// EXPORTS
// ============================================================================

export default authRouter;
