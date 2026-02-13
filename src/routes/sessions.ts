/**
 * ConFuse Auth Middleware - Session Management Routes
 * 
 * Endpoints for users to manage their active sessions
 */

import { Router, type Response } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { listUserSessions, revokeSession, revokeAllOtherSessions } from '../services/session.js';
import type { AuthenticatedRequest } from '../types/index.js';
import { logger } from '../utils/logger.js';

const router = Router();

/**
 * GET /auth/sessions
 * 
 * List all active sessions for the authenticated user
 */
router.get('/', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user!.sub; // Current user ID
        const sessionId = req.user!.sessionId; // Current session ID

        const sessions = await listUserSessions(userId, sessionId);

        res.json({
            success: true,
            data: sessions
        });
    } catch (error) {
        logger.error('[SESSIONS] Failed to list sessions:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to retrieve active sessions'
        });
    }
});

/**
 * DELETE /auth/sessions/:id
 * 
 * Revoke a specific session
 */
router.delete('/:id', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user!.sub;
        const targetSessionId = req.params.id;

        // Prevent revoking current session via this endpoint (use logout instead)
        // Or allow it but warn client
        if (targetSessionId === req.user!.sessionId) {
            res.status(400).json({
                error: 'Cannot revoke current session via this endpoint',
                message: 'Please use /auth/logout to end your current session'
            });
            return;
        }

        const revoked = await revokeSession(targetSessionId, userId);

        if (!revoked) {
            res.status(404).json({
                error: 'Session not found',
                message: 'Session does not exist or belongs to another user'
            });
            return;
        }

        res.json({
            success: true,
            message: 'Session revoked successfully'
        });
    } catch (error) {
        logger.error(`[SESSIONS] Failed to revoke session ${req.params.id}:`, error);
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to revoke session'
        });
    }
});

/**
 * DELETE /auth/sessions
 * 
 * Revoke all other sessions except current one
 */
router.delete('/', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user!.sub;
        const currentSessionId = req.user!.sessionId;

        const count = await revokeAllOtherSessions(userId, currentSessionId);

        res.json({
            success: true,
            message: `Revoked ${count} other active sessions`,
            count
        });
    } catch (error) {
        logger.error('[SESSIONS] Failed to revoke all sessions:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to revoke sessions'
        });
    }
});

export default router;
