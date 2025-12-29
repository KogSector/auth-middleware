/**
 * ConHub Auth Middleware - Main Entry Point
 * 
 * Express application for Auth0-based authentication
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { config } = require('./config');
const authRoutes = require('./routes/auth');
const healthRoutes = require('./routes/health');

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
app.use((req, res, next) => {
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
app.use((req, res) => {
    res.status(404).json({
        error: 'Not found',
        path: req.path,
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: config.nodeEnv === 'development' ? err.message : undefined,
    });
});

// Start server
const PORT = config.port;

app.listen(PORT, () => {
    console.log(`🚀 Auth Middleware listening on port ${PORT}`);
    console.log(`📊 Environment: ${config.nodeEnv}`);
    console.log(`🔐 Auth0 Domain: ${config.auth0.domain}`);
});

module.exports = app;
