/**
 * Consolidated routes for auth-middleware
 * Merges health and onboarding routes to reduce file count
 */

import { Router, type Request, type Response } from 'express';
import prisma from '../infra/db.js';
import { requireAuth } from '../auth.js';
import type { AuthenticatedRequest, Auth0Claims } from '../types/index.js';

// Health routes
const healthRoutes = Router();
healthRoutes.get('/health', async (_req: Request, res: Response) => {
    let dbStatus = 'unknown';

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

// Onboarding routes
const onboardingRoutes = Router();

onboardingRoutes.get('/onboarding', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const user = await prisma.user.findUnique({
            where: { auth0Sub: claims.sub },
            select: {
                onboardingCompleted: true,
                userIntent: true,
                dashboardPreset: true,
            }
        });

        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        res.json({
            success: true,
            data: user,
        });
    } catch (error) {
        console.error('[ONBOARDING] GET error:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

onboardingRoutes.post('/onboarding', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const claims = req.user as Auth0Claims;
        const { userIntent, dashboardPreset, onboardingCompleted } = req.body;

        const user = await prisma.user.update({
            where: { auth0Sub: claims.sub },
            data: {
                userIntent,
                dashboardPreset,
                onboardingCompleted: onboardingCompleted ?? true,
            },
            select: {
                onboardingCompleted: true,
                userIntent: true,
                dashboardPreset: true,
            }
        });

        res.json({
            success: true,
            data: user,
        });
    } catch (error) {
        console.error('[ONBOARDING] POST error:', error);
        res.status(500).json({ error: 'Internal server error', details: error instanceof Error ? error.message : String(error) });
    }
});

export { healthRoutes, onboardingRoutes };
