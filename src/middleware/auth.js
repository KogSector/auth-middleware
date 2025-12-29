/**
 * ConHub Auth Middleware - Express Auth Middleware
 * 
 * Middleware functions for protecting routes with ConHub JWT
 */

const { verifyConHubToken } = require('../services/jwt');
const { config } = require('../config');

/**
 * Extract bearer token from Authorization header
 * @param {Object} req - Express request
 * @returns {string|null} - Token or null
 */
function extractBearerToken(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    return authHeader.slice(7);
}

/**
 * Require ConHub JWT authentication
 */
function requireAuth(req, res, next) {
    const token = extractBearerToken(req);

    if (!token) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Please provide a valid Bearer token in the Authorization header',
        });
    }

    try {
        const claims = verifyConHubToken(token);
        req.user = claims;
        next();
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid token';
        return res.status(401).json({
            error: 'Invalid token',
            message,
        });
    }
}

/**
 * Optional authentication - doesn't fail if no token
 */
function optionalAuth(req, res, next) {
    const token = extractBearerToken(req);

    if (token) {
        try {
            const claims = verifyConHubToken(token);
            req.user = claims;
        } catch {
            // Ignore errors for optional auth
        }
    }

    next();
}

/**
 * Require specific roles
 * @param {...string} requiredRoles - Required roles
 * @returns {Function} - Middleware function
 */
function requireRoles(...requiredRoles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
            });
        }

        const hasRole = requiredRoles.length === 0 ||
            requiredRoles.some(role => req.user.roles.includes(role));

        if (!hasRole) {
            return res.status(403).json({
                error: 'Insufficient permissions',
                requiredRoles,
                userRoles: req.user.roles,
            });
        }

        next();
    };
}

/**
 * Internal API key authentication (for service-to-service)
 */
function requireInternalApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey || apiKey !== config.internalApiKey) {
        return res.status(401).json({
            error: 'Invalid API key',
        });
    }

    next();
}

module.exports = {
    extractBearerToken,
    requireAuth,
    optionalAuth,
    requireRoles,
    requireInternalApiKey,
};
