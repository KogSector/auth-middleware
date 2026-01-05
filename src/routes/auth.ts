/**
 * ConFuse Auth Middleware - Auth Routes
 * 
 * Authentication endpoints including Auth0 exchange
 */

import { Router, type Request, type Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { verifyAuth0Token, extractUserInfo, extractRoles } from '../services/auth0.js';
import { generateTokens, verifyConHubToken } from '../services/jwt.js';
import { findOrCreateByAuth0, findById, toProfile, prisma } from '../services/user.js';
import { isAuthBypassEnabled, getBypassUser } from '../services/feature-toggle.js';
import { requireAuth, requireInternalApiKey } from '../middleware/auth.js';
import type { AuthenticatedRequest, AuthExchangeResponse, TokenRefreshResponse, TokenVerifyResponse } from '../types/index.js';

const router = Router();

/**
 * POST /auth/auth0/exchange
 * 
 * Exchange Auth0 access token for ConHub JWT
 */
router.post('/auth0/exchange', async (req: Request, res: Response) => {
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

        // Generate ConHub tokens
        const sessionId = uuidv4();
        const tokens = generateTokens(user.id, user.email, user.roles, sessionId);

        // Store session
        await prisma.session.create({
            data: {
                id: sessionId,
                userId: user.id,
                refreshToken: tokens.refreshToken,
                expiresAt: tokens.refreshExpiresAt,
                userAgent: req.headers['user-agent'] || null,
                ipAddress: req.ip || null,
            },
        });

        console.log(`Auth0 exchange successful for: ${auth0Sub}`);

        const response: AuthExchangeResponse = {
            user: toProfile(user),
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: tokens.expiresAt.toISOString(),
            sessionId,
        };

        res.json(response);

    } catch (error) {
        console.error('Auth0 exchange error:', error);
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
        if (req.user && 'sessionId' in req.user && req.user.id) {
            // This is a demo user from bypass
            const bypassEnabled = await isAuthBypassEnabled();
            if (bypassEnabled) {
                const demoUser = await getBypassUser();
                if (demoUser && demoUser.id === req.user.id) {
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
            }
        }

        // Normal flow - get user from database
        const user = await findById(req.user!.sub);

        if (!user) {
            res.status(404).json({
                error: 'User not found',
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
 * POST /auth/refresh
 * 
 * Refresh access token using refresh token
 */
router.post('/refresh', async (req: Request, res: Response) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            res.status(400).json({
                error: 'Missing refresh token',
            });
            return;
        }

        // Find session
        const session = await prisma.session.findUnique({
            where: { refreshToken },
            include: { user: true },
        });

        if (!session) {
            res.status(401).json({
                error: 'Invalid refresh token',
            });
            return;
        }

        if (session.revokedAt) {
            res.status(401).json({
                error: 'Session revoked',
            });
            return;
        }

        if (session.expiresAt < new Date()) {
            res.status(401).json({
                error: 'Refresh token expired',
            });
            return;
        }

        // Generate new tokens
        const tokens = generateTokens(
            session.user.id,
            session.user.email,
            session.user.roles,
            session.id
        );

        // Update session with new refresh token
        await prisma.session.update({
            where: { id: session.id },
            data: {
                refreshToken: tokens.refreshToken,
                expiresAt: tokens.refreshExpiresAt,
            },
        });

        const response: TokenRefreshResponse = {
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: tokens.expiresAt.toISOString(),
        };

        res.json(response);

    } catch (error) {
        console.error('Refresh token error:', error);
        res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/logout
 * 
 * Revoke current session
 */
router.post('/logout', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        // Skip session revocation for bypass users
        if (req.user && 'id' in req.user && !('sub' in req.user)) {
            res.json({
                message: 'Logged out successfully (bypass mode)',
            });
            return;
        }

        await prisma.session.updateMany({
            where: {
                id: req.user!.sessionId,
                userId: req.user!.sub,
            },
            data: {
                revokedAt: new Date(),
            },
        });

        res.json({
            message: 'Logged out successfully',
        });

    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /internal/verify
 * 
 * Verify ConHub token (service-to-service)
 */
router.post('/verify', requireInternalApiKey as any, async (req: Request, res: Response) => {
    try {
        const { token } = req.body;

        if (!token) {
            res.status(400).json({
                error: 'Missing token',
            });
            return;
        }

        const claims = verifyConHubToken(token);

        const response: TokenVerifyResponse = {
            valid: true,
            claims,
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

export default router;
