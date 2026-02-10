/**
 * ConFuse Auth Middleware - Configuration
 * 
 * Loads environment variables with validation
 */

import 'dotenv/config';
import * as fs from 'fs';
import * as path from 'path';

interface Auth0Config {
    domain: string;
    issuer: string;
    audience: string;
    jwksUri: string;
}

interface JwtConfig {
    privateKey: string | null;
    publicKey: string | null;
    issuer: string;
    audience: string;
    expiresIn: string;
    refreshExpiresIn: string;
}


interface Config {
    port: number;
    nodeEnv: string;
    auth0: Auth0Config;
    jwt: JwtConfig;
    tokenCacheTtlSeconds: number;
    databaseUrl: string;
    internalApiKey: string | undefined;
    corsOrigins: string[];
    featureToggleServiceUrl: string;
    frontendUrl: string;
}

function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

function loadKeyFile(envVar: string): string | null {
    const keyPath = process.env[envVar];
    if (!keyPath) return null;

    const fullPath = path.resolve(keyPath);
    if (!fs.existsSync(fullPath)) {
        console.warn(`Key file not found: ${fullPath}`);
        return null;
    }

    return fs.readFileSync(fullPath, 'utf-8');
}

export const config: Config = {
    // Server
    port: parseInt(process.env.PORT || '3010', 10),
    nodeEnv: process.env.NODE_ENV || 'development',

    // Auth0 (optional when AUTH_BYPASS_ENABLED=true)
    auth0: {
        domain: process.env.AUTH0_DOMAIN || 'dev-placeholder.auth0.com',
        issuer: process.env.AUTH0_ISSUER || 'https://dev-placeholder.auth0.com/',
        audience: process.env.AUTH0_AUDIENCE || 'confuse-api',
        jwksUri: process.env.AUTH0_JWKS_URI ||
            `https://${process.env.AUTH0_DOMAIN || 'dev-placeholder.auth0.com'}/.well-known/jwks.json`,
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

    // Token cache TTL
    tokenCacheTtlSeconds: parseInt(process.env.TOKEN_CACHE_TTL_SECONDS || '900', 10), // 15 minutes

    // Database
    databaseUrl: requireEnv('DATABASE_URL'),

    // Internal API
    internalApiKey: process.env.INTERNAL_API_KEY,

    // CORS
    corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3000')
        .split(',')
        .map(s => s.trim()),

    // Feature Toggle Service
    featureToggleServiceUrl: process.env.FEATURE_TOGGLE_SERVICE_URL || 'http://localhost:3099',

    // Frontend URL for OAuth callbacks
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
};
