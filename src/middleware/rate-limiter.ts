/**
 * ConFuse Auth Middleware - Redis-backed Rate Limiter
 *
 * Sliding-window rate limiting using Redis sorted sets.
 * Falls back to in-memory if Redis is unavailable.
 */

import { createClient, type RedisClientType } from 'redis';
import type { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger.js';

// ── Redis Client ──

let redisClient: RedisClientType | null = null;
let redisAvailable = false;

export async function initRedis(): Promise<void> {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
    try {
        redisClient = createClient({ url: redisUrl });
        redisClient.on('error', (err) => {
            if (redisAvailable) {
                logger.warn(`[RATE-LIMIT] Redis error, falling back to in-memory: ${err.message}`);
                redisAvailable = false;
            }
        });
        redisClient.on('connect', () => {
            redisAvailable = true;
            logger.info('[RATE-LIMIT] Redis connected');
        });
        await redisClient.connect();
        redisAvailable = true;
    } catch (err) {
        logger.warn(`[RATE-LIMIT] Redis unavailable, using in-memory fallback: ${err}`);
        redisAvailable = false;
    }
}

// ── In-memory fallback ──

const memoryStore = new Map<string, number[]>();

function memoryCleanupLoop() {
    setInterval(() => {
        const cutoff = Date.now() - 120_000; // 2 min
        for (const [key, timestamps] of memoryStore.entries()) {
            const filtered = timestamps.filter(t => t > cutoff);
            if (filtered.length === 0) memoryStore.delete(key);
            else memoryStore.set(key, filtered);
        }
    }, 60_000);
}
memoryCleanupLoop();

// ── Sliding Window Logic ──

interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    limit: number;
    retryAfterSecs: number;
    resetAt: number;
}

async function checkRateLimit(
    key: string,
    maxRequests: number,
    windowMs: number,
): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - windowMs;
    const resetAt = Math.ceil((now + windowMs) / 1000);

    if (redisAvailable && redisClient) {
        try {
            // Use Redis sorted set for sliding window
            const multi = redisClient.multi();
            multi.zRemRangeByScore(key, '-inf', windowStart.toString());
            multi.zAdd(key, { score: now, value: `${now}:${Math.random().toString(36).slice(2, 8)}` });
            multi.zCard(key);
            multi.pExpire(key, windowMs);
            const results = await multi.exec();
            const count = (results?.[2] as unknown as number) || 0;
            const allowed = count <= maxRequests;
            return {
                allowed,
                remaining: Math.max(0, maxRequests - count),
                limit: maxRequests,
                retryAfterSecs: allowed ? 0 : Math.ceil(windowMs / 1000),
                resetAt,
            };
        } catch {
            // Fall through to memory
        }
    }

    // In-memory fallback
    const timestamps = memoryStore.get(key) || [];
    const filtered = timestamps.filter(t => t > windowStart);
    filtered.push(now);
    memoryStore.set(key, filtered);
    const allowed = filtered.length <= maxRequests;
    return {
        allowed,
        remaining: Math.max(0, maxRequests - filtered.length),
        limit: maxRequests,
        retryAfterSecs: allowed ? 0 : Math.ceil(windowMs / 1000),
        resetAt,
    };
}

// ── Configuration ──

interface RateLimitTier {
    maxRequests: number;
    windowMs: number;
}

const TIERS: Record<string, RateLimitTier> = {
    auth: { maxRequests: 20, windowMs: 60_000 },       // 20 req/min for login/exchange
    refresh: { maxRequests: 30, windowMs: 60_000 },     // 30 req/min for token refresh
    api: { maxRequests: 120, windowMs: 60_000 },        // 120 req/min general API
    sessions: { maxRequests: 30, windowMs: 60_000 },    // 30 req/min for session ops
};

function getTierForPath(path: string): RateLimitTier {
    if (path.includes('/auth0/exchange') || path.includes('/oauth')) return TIERS.auth;
    if (path.includes('/refresh')) return TIERS.refresh;
    if (path.includes('/sessions')) return TIERS.sessions;
    return TIERS.api;
}

// ── Express Middleware ──

function getClientKey(req: Request): string {
    // Prefer authenticated user ID, fall back to IP
    const user = (req as any).user;
    if (user?.sub) return `user:${user.sub}`;
    if (user?.id) return `user:${user.id}`;
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string'
        ? forwarded.split(',')[0].trim()
        : req.ip || 'unknown';
    return `ip:${ip}`;
}

export function rateLimitMiddleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const clientKey = getClientKey(req);
        const tier = getTierForPath(req.path);
        const redisKey = `ratelimit:auth:${clientKey}:${req.path.replace(/\//g, '_')}`;

        const result = await checkRateLimit(redisKey, tier.maxRequests, tier.windowMs);

        // Set standard rate limit headers
        res.setHeader('X-RateLimit-Limit', result.limit.toString());
        res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
        res.setHeader('X-RateLimit-Reset', result.resetAt.toString());

        if (!result.allowed) {
            res.setHeader('Retry-After', result.retryAfterSecs.toString());
            logger.warn(`[RATE-LIMIT] ${clientKey} exceeded ${result.limit} req/window on ${req.path}`);
            res.status(429).json({
                error: 'Too many requests',
                message: `Rate limit exceeded. Try again in ${result.retryAfterSecs}s`,
                retryAfter: result.retryAfterSecs,
            });
            return;
        }

        next();
    };
}

export async function shutdownRedis(): Promise<void> {
    if (redisClient) {
        await redisClient.quit();
        logger.info('[RATE-LIMIT] Redis disconnected');
    }
}
