/**
 * @confuse/feature-toggle-sdk - Express Middleware
 * 
 * Middleware for protecting routes based on toggle state.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { ToggleMiddlewareOptions } from './types.js';
import { getToggleClient } from './client.js';

// =============================================================================
// Toggle Middleware
// =============================================================================

/**
 * Express middleware that gates a route based on toggle state.
 * 
 * @example
 * ```typescript
 * // Block route when toggle is disabled (returns 404)
 * app.get('/beta-feature', requireToggle({ toggle: 'betaFeature' }), handler);
 * 
 * // Custom behavior when disabled
 * app.get('/feature', requireToggle({ 
 *   toggle: 'myFeature',
 *   onDisabled: 'skip' // Just skip to next middleware
 * }), handler);
 * ```
 */
export function requireToggle(options: ToggleMiddlewareOptions): RequestHandler {
    const {
        toggle,
        onDisabled = 'block',
        blockedStatus = 404,
        blockedMessage = 'Feature not available',
    } = options;

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const client = getToggleClient();
            const enabled = await client.isEnabled(toggle);

            if (enabled) {
                next();
                return;
            }

            // Toggle is disabled - handle based on onDisabled option
            if (onDisabled === 'skip') {
                next();
                return;
            }

            if (onDisabled === 'block') {
                res.status(blockedStatus).json({
                    success: false,
                    error: blockedMessage,
                    toggle,
                    timestamp: new Date().toISOString(),
                });
                return;
            }

            // Custom handler
            if (typeof onDisabled === 'function') {
                onDisabled(req, res, next);
                return;
            }

            next();
        } catch (error) {
            // On error, log and continue (fail-open for middleware)
            console.warn(`[FeatureToggle] Error checking toggle '${toggle}':`, error);
            next();
        }
    };
}

/**
 * Express middleware that adds toggle state to request object.
 * 
 * @example
 * ```typescript
 * app.use(attachToggles(['featureA', 'featureB']));
 * 
 * app.get('/api', (req, res) => {
 *   if (req.toggles?.featureA) {
 *     // Feature A logic
 *   }
 * });
 * ```
 */
export function attachToggles(toggleNames: string[]): RequestHandler {
    return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
        try {
            const client = getToggleClient();
            const toggles = await client.areEnabled(toggleNames);

            // Extend request with toggles
            (req as Request & { toggles?: Record<string, boolean> }).toggles = toggles;
        } catch (error) {
            console.warn('[FeatureToggle] Error attaching toggles:', error);
            // Set empty object on error
            (req as Request & { toggles?: Record<string, boolean> }).toggles = {};
        }

        next();
    };
}

/**
 * Express middleware that checks auth bypass toggle and attaches demo user.
 * 
 * @example
 * ```typescript
 * // In auth middleware
 * app.use(checkAuthBypass());
 * 
 * app.use((req, res, next) => {
 *   if (req.bypassUser) {
 *     // Use demo user instead of real auth
 *     req.user = req.bypassUser;
 *   }
 *   next();
 * });
 * ```
 */
export function checkAuthBypass(): RequestHandler {
    return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
        try {
            const client = getToggleClient();
            const enabled = await client.isEnabled('authBypass');

            if (enabled) {
                const demoUser = await client.getDemoUser();
                if (demoUser) {
                    (req as Request & { bypassUser?: unknown }).bypassUser = demoUser;
                }
            }
        } catch (error) {
            console.warn('[FeatureToggle] Error checking auth bypass:', error);
        }

        next();
    };
}

// =============================================================================
// Type Augmentation for Express
// =============================================================================

declare global {
    namespace Express {
        interface Request {
            toggles?: Record<string, boolean>;
            bypassUser?: {
                id: string;
                email: string;
                name: string;
                roles: string[];
                sessionId: string;
            };
        }
    }
}
