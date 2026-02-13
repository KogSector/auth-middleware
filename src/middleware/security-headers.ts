/**
 * ConFuse Auth Middleware - Security Headers
 *
 * Adds comprehensive security headers to all responses.
 * Complements helmet with additional headers for Zero Trust posture.
 */

import type { Request, Response, NextFunction } from 'express';

export function securityHeadersMiddleware() {
    return (_req: Request, res: Response, next: NextFunction): void => {
        // Prevent MIME-type sniffing
        res.setHeader('X-Content-Type-Options', 'nosniff');

        // Clickjacking protection
        res.setHeader('X-Frame-Options', 'DENY');

        // XSS protection (legacy browsers)
        res.setHeader('X-XSS-Protection', '1; mode=block');

        // Strict Transport Security (1 year, include subdomains, preload)
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

        // Referrer policy
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Permissions policy — disable dangerous browser features
        res.setHeader('Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()'
        );

        // Content Security Policy — API-only, no inline scripts needed
        res.setHeader('Content-Security-Policy',
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        );

        // Prevent caching of sensitive auth responses
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        // Remove server fingerprint
        res.removeHeader('X-Powered-By');

        // Cross-Origin isolation headers
        res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
        res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

        next();
    };
}
