/**
 * ConHub Auth Middleware - Health Routes
 */

const express = require('express');
const { prisma } = require('../services/user');

const router = express.Router();

/**
 * GET /health
 * 
 * Health check endpoint
 */
router.get('/health', async (req, res) => {
    let dbStatus = 'unknown';

    try {
        await prisma.$queryRaw`SELECT 1`;
        dbStatus = 'connected';
    } catch {
        dbStatus = 'disconnected';
    }

    return res.json({
        status: 'healthy',
        service: 'auth-middleware',
        database: dbStatus,
        timestamp: new Date().toISOString(),
    });
});

module.exports = router;
