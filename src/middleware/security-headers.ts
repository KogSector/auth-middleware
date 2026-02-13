/**
 * ConFuse Auth Middleware - Security Headers
 * 
 * Sets standard security headers for all responses.
 */

import { type Request, type Response, type NextFunction } from 'express';

export function securityHeadersMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
        // HSTS - strict transport security
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

        // Anti-clickjacking
        res.setHeader('X-Frame-Options', 'DENY');

        // XSS Protection
        res.setHeader('X-XSS-Protection', '1; mode=block');

        // Prevent MIME sniffing
        res.setHeader('X-Content-Type-Options', 'nosniff');

        // Referrer Policy
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Content Security Policy (Basic)
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'");

        next();
    };
}
