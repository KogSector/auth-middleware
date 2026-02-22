/**
 * ConFuse Auth Middleware - Auth Routes
 * 
 * Authentication endpoints using Auth0 directly
 */

import { Router, type Request, type Response } from 'express';
import { verifyAuth0Token, extractUserInfo, extractRoles } from '../services/auth0.js';
import { findOrCreateByAuth0, findByAuth0Sub, toProfile } from '../services/user.js';
import prisma from '../db/client.js';
import { isAuthBypassEnabled, getBypassUser } from '@confuse/feature-toggle-sdk';
import { requireAuth } from '../middleware/auth.js';
import type { AuthenticatedRequest, AuthExchangeResponse, TokenVerifyResponse, Auth0Claims } from '../types/index.js';
import { tokenCache } from '../services/cache.js';
import { Auth0ManagementClient } from '../services/auth0.js';
import { oAuthStateService } from '../services/oauth.js';

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

        // Extract user info
        const { auth0Sub, email, name, picture } = extractUserInfo(claims);
        const roles = extractRoles(claims);

        if (!email) {
            res.status(400).json({
                error: 'Missing email',
                message: 'Auth0 token must include email claim',
            });
            return;
        }

        // Find or create user
        const user = await findOrCreateByAuth0({
            auth0Sub,
            email,
            name,
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
        // If using bypass, return demo user directly
        if (req.user && 'id' in req.user && !('sub' in req.user)) {
            // This is a demo user from bypass (DemoUser type)
            const demoUser = req.user as any;
            res.json({
                user: {
                    id: demoUser.id,
                    email: demoUser.email,
                    name: demoUser.name,
                    roles: demoUser.roles,
                    picture: null,
                    createdAt: new Date().toISOString(),
                },
                bypass: true,
            });
            return;
        }

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
        // Bypass check
        if (req.user && 'id' in req.user && !('sub' in req.user)) {
            res.json({ success: true, data: [] }); // Empty for demo user for now
            return;
        }

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

        // Bypass check
        if (req.user && 'id' in req.user && !('sub' in req.user)) {
            res.json({ success: true, provider });
            return;
        }

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
        // Bypass check
        if (req.user && 'id' in req.user && !('sub' in req.user)) {
            res.json({ success: true, synced: 0, connections: [] });
            return;
        }

        const claims = req.user as Auth0Claims;
        const user = await findByAuth0Sub(claims.sub);

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        const identities = await Auth0ManagementClient.getInstance().getUserIdentities(user.auth0Sub);

        const results = [];

        for (const identity of identities) {
            const providerName = identity.provider.replace('-oauth2', '');

            if (!identity.access_token) {
                continue;
            }

            const account = await prisma.account.upsert({
                where: {
                    provider_providerAccountId: {
                        provider: providerName,
                        providerAccountId: identity.user_id,
                    },
                },
                update: {
                    access_token: identity.access_token,
                    refresh_token: identity.refresh_token || undefined,
                    userId: user.id // Ensure ownership
                },
                create: {
                    userId: user.id,
                    type: 'oauth',
                    provider: providerName,
                    providerAccountId: identity.user_id,
                    access_token: identity.access_token,
                    refresh_token: identity.refresh_token,
                },
            });
            results.push(account);
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

export default router;
