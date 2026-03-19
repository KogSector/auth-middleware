/**
 * ConFuse Auth Middleware - Complete Authentication System
 * 
 * Consolidated authentication, OAuth, and token management
 * Merged from: services/auth0.ts, services/oauth.ts, middleware/auth.ts, routes/auth.ts
 */

import { Router, type Request, type Response } from 'express';
import type { Response as ExpressResponse, NextFunction } from 'express';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { Redis } from 'ioredis';
import { randomBytes, createHash } from 'crypto';

// Resolve TypeScript error for native fetch in Node 18+
declare const fetch: any;

import { config } from './config.js';
import { tokenCache } from './services/cache.js';
import { findOrCreateByAuth0, findByAuth0Sub, toProfile } from './services/user.js';
import prisma from './db/client.js';
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
    private redis: any;
    private readonly PREFIX = 'oauth:state:';
    private readonly TTL = 600; // 10 minutes

    constructor() {
        const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
        this.redis = new Redis(redisUrl);

        this.redis.on('error', (err: Error) => {
            console.error('Redis connection error:', err);
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

        // Cache the validated token
        await tokenCache.setToken(tokenHash, {
            userId: payload.sub || '',
            email: (payload as any).email || '',
            roles: extractRoles(payload as Auth0Claims),
            validatedAt: Date.now(),
            expiresAt: Date.now() + (config.tokenCacheTtlSeconds * 1000),
        });

        return payload as Auth0Claims;
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
    // Check for roles in different possible locations
    const roles = claims.roles || 
                 claims['https://confuse.dev/roles'] || 
                 (claims as any)['http://confuse.dev/roles'] || 
                 [];
    
    return Array.isArray(roles) ? roles : [];
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

    async getUserProfile(userId: string): Promise<any> {
        const token = await this.getAccessToken();
        
        const response = await fetch(`https://${config.auth0.domain}/api/v2/users/${userId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`Failed to get user profile: ${response.statusText}`);
        }

        return response.json();
    }

    async getUsersByEmail(email: string): Promise<any[]> {
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
export function extractBearerToken(req: AuthenticatedRequest): string | null {
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
    req: AuthenticatedRequest,
    res: ExpressResponse,
    next: NextFunction
): Promise<void> {
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
        (claims as any).roles = extractRoles(claims);
        req.user = claims;
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
    req: AuthenticatedRequest,
    res: ExpressResponse,
    next: NextFunction
): Promise<void> {
    const token = extractBearerToken(req);

    if (token) {
        try {
            const claims = await verifyAuth0Token(token);
            req.user = claims;
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
    return (req: AuthenticatedRequest, res: ExpressResponse, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                error: 'Authentication required',
            });
            return;
        }

        const userRoles = req.user.roles || [];
        const hasRole = requiredRoles.length === 0 ||
            requiredRoles.some(role => userRoles.includes(role));

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
        // Extract Auth0 token using middleware function
        const auth0Token = extractBearerToken(req as any);
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
            console.warn('Auth0 token verification failed:', message);
            res.status(401).json({
                error: 'Invalid Auth0 token',
                message,
            });
            return;
        }

        // Fetch user profile from Auth0 /userinfo endpoint
        let userInfo: any = {};
        let providerName: string | null = null;
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

                userInfo = { ...userInfo, ...fullProfile };

                // Directly query Google or Microsoft APIs for the full name if access token is available
                const identities = fullProfile.identities || [];
                for (const identity of identities) {
                    if (identity.provider === 'google-oauth2' && identity.access_token) {
                        const googleRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
                            headers: { Authorization: `Bearer ${identity.access_token}` }
                        });
                        if (googleRes.ok) {
                            const googleUser = await googleRes.json();
                            userInfo.name = googleUser.name || userInfo.name;
                            userInfo.picture = googleUser.picture || userInfo.picture;
                        }
                    } else if (identity.provider === 'windowslive' && identity.access_token) {
                        const msRes = await fetch('https://graph.microsoft.com/v1.0/me', {
                            headers: { Authorization: `Bearer ${identity.access_token}` }
                        });
                        if (msRes.ok) {
                            const msUser = await msRes.json();
                            userInfo.name = msUser.displayName || userInfo.name;
                        }
                    }
                }
            } catch (mgmtError) {
                console.warn('Failed to fetch full Auth0 profile:', mgmtError);
            }

            // Extract provider from identities
            const identities = userInfo.identities || [];
            if (identities.length > 0) {
                providerName = identities[0].provider;
            }

        } catch (error) {
            console.warn('Failed to fetch user info from Auth0:', error);
        }

        // Sync user to database
        const user = await findOrCreateByAuth0({
            auth0Sub: claims.sub,
            email: claims.email || '',
            name: claims.name,
            picture: claims.picture,
            roles: extractRoles(claims),
        });

        const response: AuthExchangeResponse = {
            user: toProfile(user),
        };

        res.json(response);

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error instanceof Error ? error.message : 'Unknown error',
        });
    }
});

/**
 * GET /auth/me
 * Get current authenticated user (with bypass support)
 */
authRouter.get('/me', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        // Normal flow - req.user is Auth0Claims
        const claims = req.user as Auth0Claims;
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
        console.error('Get user error:', error);
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
        const { token } = req.body;

        if (!token) {
            res.status(400).json({
                error: 'Missing token',
            });
            return;
        }

        const claims = await verifyAuth0Token(token);

        const response: TokenVerifyResponse = {
            valid: true,
            claims: claims as any, // Cast to any to satisfy type
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
authRouter.get('/connections', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
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
        console.error('Connections fetch error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error',
        });
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
        console.error('OAuth start error:', error);
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
        const { code, state, error } = req.query;

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
        console.error('OAuth callback error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * DELETE /auth/connections/:provider
 * Disconnect a social provider
 */
authRouter.delete('/connections/:provider', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
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
        console.error('Disconnect error:', error);
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
authRouter.post('/connections/sync', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            sendUserNotFound(res);
            return;
        }

        const mgmtClient = Auth0ManagementClient.getInstance();
        // Step 1: Query Auth0 for all users that share the exact same email
        const auth0Users = await mgmtClient.getUsersByEmail(user.email);

        const results = [];

        // Step 2: Iterate over every matching user profile, and every identity within those profiles
        for (const auth0User of auth0Users) {
            const identities = auth0User.identities || [];

            for (const identity of identities) {
                const providerName = identity.provider.replace('-oauth2', '');

                if (!identity.access_token) {
                    continue;
                }

                // Upsert the account record
                const result = await prisma.account.upsert({
                    where: {
                        provider_providerAccountId: {
                            provider: providerName,
                            providerAccountId: String(identity.user_id),
                        }
                    },
                    update: {
                        type: 'oauth',
                        provider: providerName,
                        providerAccountId: String(identity.user_id),
                        access_token: identity.access_token,
                        refresh_token: identity.refresh_token,
                        scope: identity.scope || '',
                        expires_at: identity.expires_at ? Math.floor(identity.expires_at * 1000) : null,
                    },
                    create: {
                        userId: user.id,
                        type: 'oauth',
                        provider: providerName,
                        providerAccountId: String(identity.user_id),
                        access_token: identity.access_token,
                        refresh_token: identity.refresh_token,
                        scope: identity.scope || '',
                        expires_at: identity.expires_at ? Math.floor(identity.expires_at * 1000) : null,
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
authRouter.get('/connections/:provider/token', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
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
