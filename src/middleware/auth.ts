/**
 * ConFuse Auth Middleware - Express Auth Middleware
 * 
 * Middleware functions for protecting routes with Auth0
 * Includes feature toggle bypass support for development
 */

import type { Response, NextFunction } from 'express';
import { verifyAuth0Token, extractRoles } from '../services/auth0.js';
import { isAuthBypassEnabled, getBypassUser } from '../services/feature-toggle.js';
import { config } from '../config.js';
import type { AuthenticatedRequest, Auth0Claims } from '../types/index.js';

/**
 * Extract bearer token from Authorization header
 */
export function extractBearerToken(req: AuthenticatedRequest): string | null {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    return authHeader.slice(7);
}

/**
 * Require Auth0 Access Token authentication
 */
export async function requireAuth(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> {
    // Check if auth bypass is enabled (feature toggle)
    try {
        if (await isAuthBypassEnabled()) {
            const demoUser = await getBypassUser();
            if (demoUser) {
                console.log('🔓 Auth bypass enabled - using demo user:', demoUser.email);
                req.user = demoUser;
                next();
                return;
            }
        }
    } catch (error) {
        // If feature toggle check fails, continue with normal auth
        console.warn('Feature toggle check failed, proceeding with normal auth');
    }

    // Normal authentication flow
    const token = extractBearerToken(req);

    if (!token) {
        res.status(401).json({
            error: 'Authentication required',
            message: 'Please provide a valid Bearer token in the Authorization header',
        });
        return;
    }

    try {
        const claims = await verifyAuth0Token(token);
        // Augment claims with roles
        (claims as any).roles = extractRoles(claims);
        req.user = claims;
        next();
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid token';
        res.status(401).json({
            error: 'Invalid token',
            message,
        });
    }
}

/**
 * Optional authentication - doesn't fail if no token
 */
export async function optionalAuth(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> {
    // Check if auth bypass is enabled
    try {
        if (await isAuthBypassEnabled()) {
            const demoUser = await getBypassUser();
            if (demoUser) {
                req.user = demoUser;
                next();
                return;
            }
        }
    } catch {
        // Ignore feature toggle errors for optional auth
    }

    const token = extractBearerToken(req);

    if (token) {
        try {
            const claims = await verifyAuth0Token(token);
            req.user = claims;
        } catch {
            // Ignore errors for optional auth
        }
    }

    next();
}

/**
 * Require specific roles
 */
export function requireRoles(...requiredRoles: string[]) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                error: 'Authentication required',
            });
            return;
        }

        const userRoles = req.user.roles || [];
        const hasRole = requiredRoles.length === 0 ||
            requiredRoles.some(role => userRoles.includes(role));

        if (!hasRole) {
            res.status(403).json({
                error: 'Insufficient permissions',
                requiredRoles,
                userRoles,
            });
            return;
        }

        next();
    };
}

/**
 * Internal API key authentication (for service-to-service)
 */
export function requireInternalApiKey(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): void {
    const apiKey = req.headers['x-api-key'] as string | undefined;

    if (!apiKey || apiKey !== config.internalApiKey) {
        res.status(401).json({
            error: 'Invalid API key',
        });
        return;
    }

    next();
}
