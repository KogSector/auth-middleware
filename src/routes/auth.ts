/**
 * ConFuse Auth Middleware - Auth Routes
 * 
 * Authentication endpoints using Auth0 directly
 */

import { Router, type Request, type Response } from 'express';

// Resolve TypeScript error for native fetch in Node 18+
declare const fetch: any;

import { verifyAuth0Token, extractUserInfo, extractRoles } from '../services/auth0.js';
import { findOrCreateByAuth0, findByAuth0Sub, toProfile } from '../services/user.js';
import prisma from '../db/client.js';

import { requireAuth } from '../middleware/auth.js';
import type { AuthenticatedRequest, AuthExchangeResponse, TokenVerifyResponse, Auth0Claims } from '../types/index.js';
import { tokenCache } from '../services/cache.js';
import { Auth0ManagementClient } from '../services/auth0.js';
import { oAuthStateService } from '../services/oauth.js';
import { config } from '../config.js';

const router = Router();

/**
 * POST /auth/login
 * 
 * Verify Auth0 token, sync user to DB, and return profile.
 * Replaced /auth0/exchange
 */
router.post('/login', async (req: Request, res: Response) => {
    try {
        // Extract Auth0 token
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({
                error: 'Missing or invalid Authorization header',
                message: "Expected 'Authorization: Bearer <auth0_access_token>'",
            });
            return;
        }

        const auth0Token = authHeader.slice(7);

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
        // Access tokens often lack 'name' and 'email' claims by default
        let userInfo: any = {};
        let providerName: string | null = null;
        try {
            // @ts-ignore
            const userInfoRes = await fetch(`https://${config.auth0.domain}/userinfo`, {
                headers: { 'Authorization': authHeader }
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
                        // @ts-ignore
                        const googleRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
                            headers: { Authorization: `Bearer ${identity.access_token}` }
                        });
                        if (googleRes.ok) {
                            const googleUser = await googleRes.json();
                            providerName = googleUser.name || `${googleUser.given_name || ''} ${googleUser.family_name || ''}`.trim();
                            if (providerName) break;
                        }
                    } else if (identity.provider === 'windowslive' && identity.access_token) {
                        // @ts-ignore
                        const msRes = await fetch('https://graph.microsoft.com/v1.0/me', {
                            headers: { Authorization: `Bearer ${identity.access_token}` }
                        });
                        if (msRes.ok) {
                            const msUser = await msRes.json();
                            providerName = msUser.displayName || msUser.givenName;
                            if (providerName) break;
                        }
                    }
                }
            } catch (mgmtErr) {
                console.warn('Failed to fetch rich profile from Management API:', mgmtErr);
            }
        } catch (e) {
            console.error('Error fetching /userinfo from Auth0:', e);
        }

        const mergedClaims = { ...claims, ...userInfo } as any;

        // Extract user info
        const { auth0Sub, email, name: extractedName, picture } = extractUserInfo(mergedClaims);
        const roles = extractRoles(mergedClaims);

        const finalName = providerName || extractedName;

        if (!email) {
            res.status(400).json({
                error: 'Missing email',
                message: 'Auth0 token or userinfo must include email claim',
            });
            return;
        }

        // Find or create user
        const user = await findOrCreateByAuth0({
            auth0Sub,
            email,
            name: finalName,
            picture,
            roles,
        });

        console.log(`Auth0 login successful for: ${auth0Sub} -> ${user.id}`);

        const response: AuthExchangeResponse = {
            user: toProfile(user),
        };

        res.json(response);

    } catch (error) {
        console.error('Auth0 login error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to process authentication',
        });
    }
});

/**
 * GET /auth/me
 * 
 * Get current authenticated user (with bypass support)
 */
router.get('/me', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        // Normal flow - req.user is Auth0Claims
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            // Should not happen if /login was called, but if token is valid but user not in DB
            // We could try to create here, but for now 404
            res.status(404).json({
                error: 'User not found',
                message: 'Please call /auth/login first to sync user',
            });
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
 * POST /internal/verify
 * 
 * Verify Auth0 token (service-to-service)
 * Updated to verify Auth0 tokens instead of ConHub tokens
 */
router.post('/verify', async (req: Request, res: Response) => {
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
 * 
 * Get user's social connections
 */
router.get('/connections', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            res.status(404).json({ error: 'User not found' });
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
            username: null,
            is_active: true,
            connected_at: new Date().toISOString(),
            last_sync: null,
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
router.get('/oauth/:provider/start', async (req: Request, res: Response) => {
    try {
        const { provider } = req.params;
        const { redirect_uri, user_id, use_pkce } = req.query;

        if (!redirect_uri || typeof redirect_uri !== 'string') {
            res.status(400).json({ error: 'Missing or invalid redirect_uri' });
            return;
        }

        // Rate limiting
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        const limit = await tokenCache.checkRateLimit(`oauth:start:${ip}`, 10, 900);
        if (!limit.allowed) {
            res.status(429).json({ error: 'Too many OAuth attempts' });
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
            redirectUri: redirect_uri,
            codeVerifier
        });

        res.json({
            state: stateIdx,
            code_verifier: codeVerifier,
            code_challenge: codeChallenge,
            provider
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
router.get('/oauth/:provider/callback', async (req: Request, res: Response) => {
    try {
        const { provider } = req.params;
        const { code, state, error } = req.query;

        if (error) {
            res.status(400).json({ error: typeof error === 'string' ? error : 'OAuth error' });
            return;
        }

        if (!code || typeof code !== 'string' || !state || typeof state !== 'string') {
            res.status(400).json({ error: 'Missing code or state' });
            return;
        }

        // Rate limiting
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        const limit = await tokenCache.checkRateLimit(`oauth:callback:${ip}`, 20, 900);
        if (!limit.allowed) {
            res.status(429).json({ error: 'Too many OAuth callback attempts' });
            return;
        }

        const storedState = await oAuthStateService.validateState(state);

        if (!storedState) {
            res.status(400).json({ error: 'Invalid or expired state' });
            return;
        }

        if (storedState.provider !== provider) {
            res.status(400).json({ error: 'Provider mismatch' });
            return;
        }

        await oAuthStateService.consumeState(state);

        res.json({
            success: true,
            provider,
            code,
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
router.delete('/connections/:provider', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const { provider } = req.params;

        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            res.status(404).json({ error: 'User not found' });
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
            provider,
        });

    } catch (error) {
        console.error('Disconnect error:', error);
        res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/connections/sync
 * Sync user identities from Auth0 Management API
 */
router.post('/connections/sync', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            res.status(404).json({ error: 'User not found' });
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

                const account = await prisma.account.upsert({
                    where: {
                        provider_providerAccountId: {
                            provider: providerName,
                            providerAccountId: String(identity.user_id),
                        },
                    },
                    update: {
                        access_token: identity.access_token,
                        refresh_token: identity.refresh_token || undefined,
                        userId: user.id // Ensure it correctly maps back to the primary ConFuse user
                    },
                    create: {
                        userId: user.id,
                        type: 'oauth',
                        provider: providerName,
                        providerAccountId: String(identity.user_id),
                        access_token: identity.access_token,
                        refresh_token: identity.refresh_token,
                    },
                });
                results.push(account);
            }
        }

        res.json({
            success: true,
            synced: results.length,
            connections: results.map(c => ({
                id: c.providerAccountId,
                platform: c.provider,
                is_active: true,
            }))
        });

    } catch (error) {
        console.error('Sync error:', error);
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
router.get('/connections/:provider/token', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const { provider } = req.params;
        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            res.status(404).json({ error: 'User not found' });
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
            res.status(404).json({ error: `Connection for ${provider} not found or missing access token` });
            return;
        }

        res.json({
            success: true,
            provider,
            access_token: account.access_token
        });

    } catch (error) {
        console.error('Fetch token error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * POST /internal/tokens
 * Fetch the decrypted access token for a connected provider using internal API key
 */
router.post('/internal/tokens', async (req: Request, res: Response) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== config.internalApiKey) {
            res.status(403).json({ error: 'Invalid internal API key' });
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
            res.status(404).json({ error: `Connection for ${provider} not found or missing access token` });
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
        console.error('Internal fetch token error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * POST /auth/validate-api-key
 * Validate internal API key and return mock user
 */
router.post('/validate-api-key', async (req: Request, res: Response) => {
    try {
        const apiKey = req.headers['x-api-key'];
        
        if (apiKey !== config.internalApiKey) {
            res.status(403).json({ error: 'Invalid API key' });
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

export default router;
