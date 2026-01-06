/**
 * ConFuse Auth Middleware - JWT Service
 * 
 * Handles ConHub JWT token generation and verification
 */

import jwt, { type SignOptions, type Algorithm } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config.js';
import type { JwtPayload, RefreshPayload, TokenPair } from '../types/index.js';

/**
 * Parse expires-in string to seconds
 */
export function parseExpiresIn(expiresIn: string): number {
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
 */
export function generateTokens(
    userId: string,
    email: string,
    roles: string[],
    sessionId: string
): TokenPair {
    const jti = uuidv4();

    const payload: JwtPayload = {
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
    const algorithm: Algorithm = config.jwt.privateKey ? 'RS256' : 'HS256';
    const secret = config.jwt.privateKey || config.internalApiKey || 'dev-secret-key';

    const signOptions: SignOptions = {
        algorithm,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        expiresIn: accessExpiresIn,
        keyid: 'conhub-auth-key',
    };

    const accessToken = jwt.sign(payload, secret, signOptions);

    // Refresh token has longer expiry
    const refreshPayload: RefreshPayload = {
        sub: userId,
        sessionId,
        type: 'refresh',
    };

    const refreshToken = jwt.sign(refreshPayload, secret, {
        ...signOptions,
        expiresIn: refreshExpiresIn,
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
 */
export function verifyConHubToken(token: string): JwtPayload {
    const algorithm: Algorithm = config.jwt.publicKey ? 'RS256' : 'HS256';
    const secret = config.jwt.publicKey || config.internalApiKey || 'dev-secret-key';

    try {
        const payload = jwt.verify(token, secret, {
            algorithms: [algorithm],
            issuer: config.jwt.issuer,
            audience: config.jwt.audience,
        }) as jwt.JwtPayload;

        return {
            sub: payload.sub as string,
            email: payload.email as string,
            roles: payload.roles as string[],
            sessionId: payload.sessionId as string,
            jti: payload.jti as string,
        };
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`ConHub token verification failed: ${message}`);
    }
}
