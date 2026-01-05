/**
 * ConFuse Auth Middleware - Main Entry Point
 * 
 * Express application for Auth0-based authentication
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config } from './config.js';
import authRoutes from './routes/auth.js';
import healthRoutes from './routes/health.js';

const app = express();

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
    origin: config.corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Api-Key'],
}));

// Body parsing
app.use(express.json());

// Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
    });
    next();
});

// Routes
app.use('/', healthRoutes);
app.use('/api/auth', authRoutes);

// Legacy route compatibility
app.use('/auth', authRoutes);

// Internal routes (service-to-service)
app.use('/internal', authRoutes);

// 404 handler
app.use((req: Request, res: Response) => {
    res.status(404).json({
        error: 'Not found',
        path: req.path,
    });
});

// Error handler
app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: config.nodeEnv === 'development' ? err.message : undefined,
    });
});

// Start server
const PORT = config.port;

app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║        🔐 ConFuse Auth Middleware (TypeScript)           ║');
    console.log('╠══════════════════════════════════════════════════════════╣');
    console.log(`║  🚀 Server running on http://localhost:${PORT}            ║`);
    console.log(`║  📊 Environment: ${config.nodeEnv.padEnd(37)}║`);
    console.log(`║  🌐 Auth0 Domain: ${config.auth0.domain.substring(0, 35).padEnd(36)}║`);
    console.log(`║  🎛️  Feature toggles: ${config.featureToggleServiceUrl.substring(0, 31).padEnd(32)}║`);
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');
});

export default app;
