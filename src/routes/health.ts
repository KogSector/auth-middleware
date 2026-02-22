/**
 * ConFuse Auth Middleware - Health Routes
 */

import { Router, type Request, type Response } from 'express';
import prisma from '../db/client.js';
import { isAuthBypassEnabled } from '@confuse/feature-toggle-sdk';

const router = Router();

/**
 * GET /health
 * 
 * Health check endpoint
 */
router.get('/health', async (_req: Request, res: Response) => {
    let dbStatus = 'unknown';
    let authBypassStatus = 'unknown';

    // Check database connection
    try {
        await prisma.$queryRaw`SELECT 1`;
        dbStatus = 'connected';
    } catch {
        dbStatus = 'disconnected';
    }

    // Check auth bypass status
    try {
        const enabled = await isAuthBypassEnabled();
        authBypassStatus = enabled ? 'enabled' : 'disabled';
    } catch {
        authBypassStatus = 'unavailable';
    }

    res.json({
        status: 'healthy',
        service: 'auth-middleware',
        database: dbStatus,
        authBypass: authBypassStatus,
        timestamp: new Date().toISOString(),
    });
});

export default router;
