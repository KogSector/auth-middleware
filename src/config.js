/**
 * ConHub Auth Middleware - Configuration
 * 
 * Loads environment variables with validation
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');

function requireEnv(name) {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

function loadKeyFile(envVar) {
    const keyPath = process.env[envVar];
    if (!keyPath) return null;

    const fullPath = path.resolve(keyPath);
    if (!fs.existsSync(fullPath)) {
        console.warn(`Key file not found: ${fullPath}`);
        return null;
    }

    return fs.readFileSync(fullPath, 'utf-8');
}

const config = {
    // Server
    port: parseInt(process.env.PORT || '3010', 10),
    nodeEnv: process.env.NODE_ENV || 'development',

    // Auth0
    auth0: {
        domain: requireEnv('AUTH0_DOMAIN'),
        issuer: requireEnv('AUTH0_ISSUER'),
        audience: requireEnv('AUTH0_AUDIENCE'),
        jwksUri: process.env.AUTH0_JWKS_URI ||
            `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
    },

    // ConHub JWT
    jwt: {
        privateKey: loadKeyFile('JWT_PRIVATE_KEY_PATH'),
        publicKey: loadKeyFile('JWT_PUBLIC_KEY_PATH'),
        issuer: process.env.JWT_ISSUER || 'conhub-auth',
        audience: process.env.JWT_AUDIENCE || 'conhub-services',
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
        refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    },

    // Database
    databaseUrl: requireEnv('DATABASE_URL'),

    // Internal API
    internalApiKey: process.env.INTERNAL_API_KEY,

    // CORS
    corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3000')
        .split(',')
        .map(s => s.trim()),
};

module.exports = { config };
