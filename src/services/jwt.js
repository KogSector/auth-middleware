/**
 * ConHub Auth Middleware - JWT Service
 * 
 * Handles ConHub JWT token generation and verification
 */

const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { config } = require('../config');

/**
 * Parse expires-in string to seconds
 * @param {string} expiresIn - Duration string (e.g., "1h", "7d")
 * @returns {number} - Seconds
 */
function parseExpiresIn(expiresIn) {
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) {
        return 3600; // Default 1 hour
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
        case 's': return value;
        case 'm': return value * 60;
        case 'h': return value * 3600;
        case 'd': return value * 86400;
        default: return 3600;
    }
}

/**
 * Generate ConHub JWT tokens
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @param {string[]} roles - User roles
 * @param {string} sessionId - Session ID
 * @returns {Object} - Token pair with expiry dates
 */
function generateTokens(userId, email, roles, sessionId) {
    const jti = uuidv4();

    const payload = {
        sub: userId,
        email,
        roles,
        sessionId,
        jti,
    };

    // Calculate expiry times
    const accessExpiresIn = parseExpiresIn(config.jwt.expiresIn);
    const refreshExpiresIn = parseExpiresIn(config.jwt.refreshExpiresIn);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + accessExpiresIn * 1000);
    const refreshExpiresAt = new Date(now.getTime() + refreshExpiresIn * 1000);

    // Use HMAC if no RSA keys, otherwise RS256
    const algorithm = config.jwt.privateKey ? 'RS256' : 'HS256';
    const secret = config.jwt.privateKey || config.internalApiKey || 'dev-secret-key';

    const signOptions = {
        algorithm,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        expiresIn: config.jwt.expiresIn,
        keyid: 'conhub-auth-key',
    };

    const accessToken = jwt.sign(payload, secret, signOptions);

    // Refresh token has longer expiry
    const refreshPayload = {
        sub: userId,
        sessionId,
        type: 'refresh',
    };

    const refreshToken = jwt.sign(refreshPayload, secret, {
        ...signOptions,
        expiresIn: config.jwt.refreshExpiresIn,
    });

    return {
        accessToken,
        refreshToken,
        expiresAt,
        refreshExpiresAt,
    };
}

/**
 * Verify ConHub JWT token
 * @param {string} token - ConHub JWT token
 * @returns {Object} - Decoded claims
 */
function verifyConHubToken(token) {
    const algorithm = config.jwt.publicKey ? 'RS256' : 'HS256';
    const secret = config.jwt.publicKey || config.internalApiKey || 'dev-secret-key';

    try {
        const payload = jwt.verify(token, secret, {
            algorithms: [algorithm],
            issuer: config.jwt.issuer,
            audience: config.jwt.audience,
        });

        return {
            sub: payload.sub,
            email: payload.email,
            roles: payload.roles,
            sessionId: payload.sessionId,
            jti: payload.jti,
        };
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`ConHub token verification failed: ${message}`);
    }
}

module.exports = {
    generateTokens,
    verifyConHubToken,
    parseExpiresIn,
};
