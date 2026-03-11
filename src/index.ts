/**
 * ConFuse Auth Middleware - Main Entry Point
 * 
 * Express application for Auth0-based authentication
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { auth } from 'express-oauth2-jwt-bearer';
import { config } from './config.js';
import authRoutes from './routes/auth.js';
import healthRoutes from './routes/health.js';
import { logger } from './utils/logger.js';
import { rateLimitMiddleware, initRedis } from './middleware/rate-limiter.js';
import { securityHeadersMiddleware } from './middleware/security-headers.js';
import { startGrpcServer } from './grpc.js';

// Initialize Redis for rate limiting
initRedis();

const app = express();

// Auth0 JWT validation middleware (express-oauth2-jwt-bearer)
const jwtCheck = auth({
    audience: config.auth0.audience,
    issuerBaseURL: config.auth0.issuer,
    tokenSigningAlg: config.auth0.jwtAlgorithm,
});

logger.info(`[AUTH-MIDDLEWARE] JWT Check configured — audience: ${config.auth0.audience}, issuer: ${config.auth0.issuer}`);

// Security middleware
logger.info('[AUTH-MIDDLEWARE] Setting up security middleware...');
app.use(helmet());
app.use(securityHeadersMiddleware());

// CORS configuration
app.use(cors({
    origin: config.corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Authorization',
        'Content-Type',
        'X-Api-Key',
        'X-Span-Id',
        'X-Trace-Id',
        'X-Request-Id',
        'X-Correlation-Id'
    ],
}));


// Body parsing
app.use(express.json());

// Rate limiting (after body parsing, before routes)
app.use(rateLimitMiddleware());

// Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    logger.http(`[REQUEST] [${requestId}] ${req.method} ${req.path} started`, {
        headers: { authorization: req.headers.authorization ? 'present' : 'absent', 'x-service-name': req.headers['x-service-name'] },
        ip: req.ip,
    });
    res.on('finish', () => {
        const duration = Date.now() - start;
        const level = res.statusCode >= 400 ? 'error' : 'info';
        const msg = `[RESPONSE] [${requestId}] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`;
        if (level === 'error') {
            logger.error(msg);
        } else {
            logger.http(msg);
        }
    });
    next();
});

// Routes
// Public routes — no JWT required
app.use('/', healthRoutes);

// Protected test endpoint — validates Auth0 JWT via express-oauth2-jwt-bearer
app.get('/authorized', jwtCheck, (req: Request, res: Response) => {
    res.json({
        message: 'Secured Resource',
        timestamp: new Date().toISOString(),
    });
});

// Auth routes — use their own requireAuth middleware internally
app.use('/api/auth', authRoutes);

// Legacy route compatibility
app.use('/auth', authRoutes);

// Internal routes (service-to-service)
app.use('/internal', authRoutes);

// User Stats (Dashboard mock data)
app.get('/api/users/stats', (req: Request, res: Response) => {
    res.json({
        context_requests: 1247,
        security_score: 98,
        total_users: 1,
        active_users: 1,
        api_calls: 3450,
        storage_used: 1024 * 1024 * 50,
        bandwidth_used: 1024 * 1024 * 100
    });
});

// 404 handler
app.use((req: Request, res: Response) => {
    logger.warn(`[AUTH-MIDDLEWARE] [404] Route not found: ${req.method} ${req.path}`);
    res.status(404).json({
        error: 'Not found',
        path: req.path,
    });
});

// Error handler (supports express-oauth2-jwt-bearer UnauthorizedError with status property)
app.use((err: Error & { status?: number }, req: Request, res: Response, _next: NextFunction) => {
    const statusCode = err.status || 500;
    const logLevel = statusCode >= 500 ? 'error' : 'warn';
    logger[logLevel](`[AUTH-MIDDLEWARE] [ERROR] ${err.message}`, { status: statusCode, stack: err.stack });
    res.status(statusCode).json({
        error: statusCode === 401 ? 'Unauthorized' : 'Internal server error',
        message: config.nodeEnv === 'development' ? err.message : undefined,
    });
});

// Start server
const PORT = config.port;

logger.info('[AUTH-MIDDLEWARE] ==================================================');
logger.info('[AUTH-MIDDLEWARE] Starting Auth Middleware Service...');
logger.info('[AUTH-MIDDLEWARE] ==================================================');
logger.info(`[AUTH-MIDDLEWARE] Timestamp: ${new Date().toISOString()}`);
logger.info(`[AUTH-MIDDLEWARE] Node version: ${process.version}`);
logger.info(`[AUTH-MIDDLEWARE] Environment: ${config.nodeEnv}`);

app.listen(PORT, () => {
    logger.info('');
    logger.info('╔══════════════════════════════════════════════════════════╗');
    logger.info('║        🔐 ConFuse Auth Middleware (TypeScript)           ║');
    logger.info('╠══════════════════════════════════════════════════════════╣');
    logger.info(`║  🚀 Server running on http://localhost:${PORT}            ║`);
    logger.info(`║  📊 Environment: ${config.nodeEnv.padEnd(37)}║`);
    logger.info(`║  🌐 Auth0 Domain: ${config.auth0.domain.substring(0, 35).padEnd(36)}║`);
    logger.info('╚══════════════════════════════════════════════════════════╝');
    logger.info('');

    // Start gRPC Server
    startGrpcServer();
});

export default app;
