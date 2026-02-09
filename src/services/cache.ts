/**
 * ConFuse Auth Middleware - Token Cache Service
 * 
 * Provides Redis-based JWT token caching for distributed authentication
 * with 15-minute TTL and cache-first validation pattern.
 */

import { createClient, RedisClientType } from 'redis';
import { config } from '../config.js';
import { logger } from '../utils/logger.js';

// Token cache entry structure
interface CachedToken {
    userId: string;
    email: string;
    roles: string[];
    validatedAt: number;
    expiresAt: number;
}

// Rate limit entry structure
interface RateLimitEntry {
    count: number;
    windowStart: number;
}

// Cache statistics
interface CacheStats {
    hits: number;
    misses: number;
    errors: number;
}

class TokenCacheService {
    private client: RedisClientType | null = null;
    private isConnected = false;
    private stats: CacheStats = { hits: 0, misses: 0, errors: 0 };
    private readonly TOKEN_PREFIX = 'auth:token:';
    private readonly RATE_LIMIT_PREFIX = 'auth:rate:';

    /**
     * Initialize Redis connection
     */
    async initialize(): Promise<void> {
        try {
            this.client = createClient({
                url: config.redis.url,
                password: config.redis.password,
            });

            this.client.on('error', (err: Error) => {
                logger.error('[TOKEN-CACHE] Redis client error:', err);
                this.isConnected = false;
            });

            this.client.on('connect', () => {
                logger.info('[TOKEN-CACHE] Connected to Redis');
                this.isConnected = true;
            });

            this.client.on('disconnect', () => {
                logger.warn('[TOKEN-CACHE] Disconnected from Redis');
                this.isConnected = false;
            });

            await this.client.connect();
            logger.info('[TOKEN-CACHE] Token cache service initialized');
        } catch (error) {
            logger.error('[TOKEN-CACHE] Failed to initialize Redis:', error);
            this.isConnected = false;
        }
    }

    /**
     * Check if cache is available
     */
    isAvailable(): boolean {
        return this.isConnected && this.client !== null;
    }

    /**
     * Get cached token data
     */
    async getToken(tokenHash: string): Promise<CachedToken | null> {
        if (!this.isAvailable()) {
            this.stats.misses++;
            return null;
        }

        try {
            const key = `${this.TOKEN_PREFIX}${tokenHash}`;
            const data = await this.client!.get(key);

            if (data) {
                this.stats.hits++;
                logger.debug(`[TOKEN-CACHE] Cache hit for token hash: ${tokenHash.substring(0, 8)}...`);
                return JSON.parse(data) as CachedToken;
            }

            this.stats.misses++;
            logger.debug(`[TOKEN-CACHE] Cache miss for token hash: ${tokenHash.substring(0, 8)}...`);
            return null;
        } catch (error) {
            this.stats.errors++;
            logger.error('[TOKEN-CACHE] Error getting cached token:', error);
            return null;
        }
    }

    /**
     * Cache validated token data
     */
    async setToken(tokenHash: string, data: CachedToken): Promise<void> {
        if (!this.isAvailable()) {
            return;
        }

        try {
            const key = `${this.TOKEN_PREFIX}${tokenHash}`;
            const ttl = config.redis.tokenCacheTtlSeconds;

            await this.client!.setEx(key, ttl, JSON.stringify(data));
            logger.debug(`[TOKEN-CACHE] Cached token for hash: ${tokenHash.substring(0, 8)}... TTL: ${ttl}s`);
        } catch (error) {
            this.stats.errors++;
            logger.error('[TOKEN-CACHE] Error caching token:', error);
        }
    }

    /**
     * Invalidate cached token
     */
    async invalidateToken(tokenHash: string): Promise<void> {
        if (!this.isAvailable()) {
            return;
        }

        try {
            const key = `${this.TOKEN_PREFIX}${tokenHash}`;
            await this.client!.del(key);
            logger.debug(`[TOKEN-CACHE] Invalidated token hash: ${tokenHash.substring(0, 8)}...`);
        } catch (error) {
            this.stats.errors++;
            logger.error('[TOKEN-CACHE] Error invalidating token:', error);
        }
    }

    /**
     * Invalidate all tokens for a user
     */
    async invalidateUserTokens(userId: string): Promise<number> {
        if (!this.isAvailable()) {
            return 0;
        }

        try {
            const pattern = `${this.TOKEN_PREFIX}*`;
            const keys = await this.client!.keys(pattern);
            let invalidatedCount = 0;

            for (const key of keys) {
                const data = await this.client!.get(key);
                if (data) {
                    const cached = JSON.parse(data) as CachedToken;
                    if (cached.userId === userId) {
                        await this.client!.del(key);
                        invalidatedCount++;
                    }
                }
            }

            logger.info(`[TOKEN-CACHE] Invalidated ${invalidatedCount} tokens for user: ${userId}`);
            return invalidatedCount;
        } catch (error) {
            this.stats.errors++;
            logger.error('[TOKEN-CACHE] Error invalidating user tokens:', error);
            return 0;
        }
    }

    /**
     * Check rate limit for user/IP
     */
    async checkRateLimit(key: string, maxRequests: number, windowSeconds: number): Promise<{ allowed: boolean; remaining: number; retryAfter: number }> {
        if (!this.isAvailable()) {
            // Fail open if cache unavailable
            return { allowed: true, remaining: maxRequests, retryAfter: 0 };
        }

        try {
            const now = Math.floor(Date.now() / 1000);
            const windowStart = Math.floor(now / windowSeconds) * windowSeconds;
            const rateLimitKey = `${this.RATE_LIMIT_PREFIX}${key}:${windowStart}`;

            const count = await this.client!.incr(rateLimitKey);

            // Set expiration on first request
            if (count === 1) {
                await this.client!.expire(rateLimitKey, windowSeconds * 2);
            }

            const allowed = count <= maxRequests;
            const remaining = Math.max(0, maxRequests - count);
            const retryAfter = allowed ? 0 : windowSeconds - (now % windowSeconds);

            if (!allowed) {
                logger.warn(`[TOKEN-CACHE] Rate limit exceeded for key: ${key} (${count}/${maxRequests})`);
            }

            return { allowed, remaining, retryAfter };
        } catch (error) {
            this.stats.errors++;
            logger.error('[TOKEN-CACHE] Error checking rate limit:', error);
            // Fail open
            return { allowed: true, remaining: maxRequests, retryAfter: 0 };
        }
    }

    /**
     * Get cache statistics
     */
    getStats(): CacheStats & { hitRate: number } {
        const total = this.stats.hits + this.stats.misses;
        const hitRate = total > 0 ? (this.stats.hits / total) * 100 : 0;
        return { ...this.stats, hitRate };
    }

    /**
     * Health check
     */
    async healthCheck(): Promise<{ status: string; latencyMs: number }> {
        if (!this.isAvailable()) {
            return { status: 'disconnected', latencyMs: -1 };
        }

        try {
            const start = Date.now();
            await this.client!.ping();
            const latencyMs = Date.now() - start;
            return { status: 'healthy', latencyMs };
        } catch (error) {
            return { status: 'error', latencyMs: -1 };
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown(): Promise<void> {
        if (this.client) {
            await this.client.quit();
            logger.info('[TOKEN-CACHE] Redis connection closed');
        }
    }
}

// Singleton instance
export const tokenCache = new TokenCacheService();

// Hash function for tokens (using simple hash for now)
export function hashToken(token: string): string {
    let hash = 0;
    for (let i = 0; i < token.length; i++) {
        const char = token.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
}
