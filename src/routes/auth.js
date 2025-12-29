/**
 * ConHub Auth Middleware - Auth Routes
 * 
 * Authentication endpoints including Auth0 exchange
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { verifyAuth0Token, extractUserInfo, extractRoles } = require('../services/auth0');
const { generateTokens, verifyConHubToken } = require('../services/jwt');
const { findOrCreateByAuth0, findById, toProfile, prisma } = require('../services/user');
const { requireAuth, requireInternalApiKey } = require('../middleware/auth');

const router = express.Router();

/**
 * POST /auth/auth0/exchange
 * 
 * Exchange Auth0 access token for ConHub JWT
 */
router.post('/auth0/exchange', async (req, res) => {
    try {
        // Extract Auth0 token
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Missing or invalid Authorization header',
                message: "Expected 'Authorization: Bearer <auth0_access_token>'",
            });
        }

        const auth0Token = authHeader.slice(7);

        // Verify Auth0 token
        let claims;
        try {
            claims = await verifyAuth0Token(auth0Token);
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            console.warn('Auth0 token verification failed:', message);
            return res.status(401).json({
                error: 'Invalid Auth0 token',
                message,
            });
        }

        // Extract user info
        const { auth0Sub, email, name, picture } = extractUserInfo(claims);
        const roles = extractRoles(claims);

        if (!email) {
            return res.status(400).json({
                error: 'Missing email',
                message: 'Auth0 token must include email claim',
            });
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
                userAgent: req.headers['user-agent'],
                ipAddress: req.ip,
            },
        });

        console.log(`Auth0 exchange successful for: ${auth0Sub}`);

        return res.json({
            user: toProfile(user),
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: tokens.expiresAt.toISOString(),
            sessionId,
        });

    } catch (error) {
        console.error('Auth0 exchange error:', error);
        return res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to process authentication',
        });
    }
});

/**
 * GET /auth/me
 * 
 * Get current authenticated user
 */
router.get('/me', requireAuth, async (req, res) => {
    try {
        const user = await findById(req.user.sub);

        if (!user) {
            return res.status(404).json({
                error: 'User not found',
            });
        }

        return res.json({
            user: toProfile(user),
        });

    } catch (error) {
        console.error('Get user error:', error);
        return res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/refresh
 * 
 * Refresh access token using refresh token
 */
router.post('/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({
                error: 'Missing refresh token',
            });
        }

        // Find session
        const session = await prisma.session.findUnique({
            where: { refreshToken },
            include: { user: true },
        });

        if (!session) {
            return res.status(401).json({
                error: 'Invalid refresh token',
            });
        }

        if (session.revokedAt) {
            return res.status(401).json({
                error: 'Session revoked',
            });
        }

        if (session.expiresAt < new Date()) {
            return res.status(401).json({
                error: 'Refresh token expired',
            });
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

        return res.json({
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: tokens.expiresAt.toISOString(),
        });

    } catch (error) {
        console.error('Refresh token error:', error);
        return res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /auth/logout
 * 
 * Revoke current session
 */
router.post('/logout', requireAuth, async (req, res) => {
    try {
        await prisma.session.updateMany({
            where: {
                id: req.user.sessionId,
                userId: req.user.sub,
            },
            data: {
                revokedAt: new Date(),
            },
        });

        return res.json({
            message: 'Logged out successfully',
        });

    } catch (error) {
        console.error('Logout error:', error);
        return res.status(500).json({
            error: 'Internal server error',
        });
    }
});

/**
 * POST /internal/verify
 * 
 * Verify ConHub token (service-to-service)
 */
router.post('/verify', requireInternalApiKey, async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({
                error: 'Missing token',
            });
        }

        const claims = verifyConHubToken(token);

        return res.json({
            valid: true,
            claims,
        });

    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid token';
        return res.json({
            valid: false,
            error: message,
        });
    }
});

module.exports = router;
