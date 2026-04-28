import { Router, type Response } from 'express';
import { requireAuth } from '../auth.js';
import prisma from '../db/client.js';
import type { AuthenticatedRequest, Auth0Claims } from '../types/index.js';

const router = Router();

router.get('/onboarding', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
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
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/onboarding', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
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
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;
