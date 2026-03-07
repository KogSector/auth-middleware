/**
 * ConFuse Auth Middleware - Health Routes
 */

import { Router, type Request, type Response } from 'express';
import prisma from '../db/client.js';

const router = Router();

/**
 * GET /health
 * 
 * Health check endpoint
 */
router.get('/health', async (_req: Request, res: Response) => {
    let dbStatus = 'unknown';

    // Check database connection
    try {
        await prisma.$queryRaw`SELECT 1`;
        dbStatus = 'connected';
    } catch {
        dbStatus = 'disconnected';
    }

    res.json({
        status: 'healthy',
        service: 'auth-middleware',
        database: dbStatus,
        timestamp: new Date().toISOString(),
    });
});

export default router;
