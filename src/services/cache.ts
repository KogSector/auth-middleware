/**
 * ConFuse Auth Middleware - Token Cache Service
 * 
 * Provides Redis-based token caching for distributed authentication
 * with TTL-based expiration and cache-first validation pattern.
 */

import { Redis } from 'ioredis';
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

// Cache statistics
interface CacheStats {
    hits: number;
    misses: number;
    errors: number;
}

class TokenCacheService {
    private redis: Redis | null = null;
    private isInitialized = false;
    private stats: CacheStats = { hits: 0, misses: 0, errors: 0 };
    private readonly TOKEN_PREFIX = 'auth:token:';
    private readonly USER_INDEX_PREFIX = 'auth:user:tokens:';

    /**
     * Initialize Redis cache
     */
    async initialize(): Promise<void> {
        if (this.isInitialized) return;

        try {
            this.redis = new Redis(config.redisUrl, {
                keepAlive: 10000,
                retryStrategy: (times) => Math.min(times * 50, 2000),
            });

            this.redis.on('error', (err: Error) => {
                logger.error('[TOKEN-CACHE] Redis connection error', { error: err.message });
            });

            this.redis.on('connect', () => {
                logger.info('[TOKEN-CACHE] Redis connected successfully');
            });

            this.isInitialized = true;
            logger.info('[TOKEN-CACHE] Redis token cache service initialized');
        } catch (error) {
            logger.error('[TOKEN-CACHE] Failed to initialize Redis', error);
        }
    }

    /**
     * Check if cache is available
     */
    isAvailable(): boolean {
        return this.isInitialized && this.redis?.status === 'ready';
    }

    /**
     * Get cached token data
     */
    async getToken(tokenHash: string): Promise<CachedToken | null> {
        if (!this.isAvailable() || !this.redis) {
            this.stats.misses++;
            return null;
        }

        try {
            const key = `${this.TOKEN_PREFIX}${tokenHash}`;
            const dataStr = await this.redis.get(key);

            if (dataStr) {
                const data = JSON.parse(dataStr) as CachedToken;
                if (data.expiresAt > Date.now()) {
                    this.stats.hits++;
                    logger.debug(`[TOKEN-CACHE] Cache hit for token hash: ${tokenHash.substring(0, 8)}...`);
                    
                    // Refresh TTL (LRU-like behavior)
                    await this.redis.expire(key, config.tokenCacheTtlSeconds);
                    return data;
                } else {
                    // Cleanup expired manually just in case, though Redis handles TTL
                    await this.invalidateToken(tokenHash);
                }
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
        if (!this.isAvailable() || !this.redis) {
            return;
        }

        try {
            const key = `${this.TOKEN_PREFIX}${tokenHash}`;
            const ttl = config.tokenCacheTtlSeconds;

            const pipeline = this.redis.pipeline();
            pipeline.setex(key, ttl, JSON.stringify(data));
            
            // Maintain the userId → keys secondary index
            const userIndexKey = `${this.USER_INDEX_PREFIX}${data.userId}`;
            pipeline.sadd(userIndexKey, key);
            pipeline.expire(userIndexKey, ttl); // ensure index also expires

            await pipeline.exec();

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
        if (!this.isAvailable() || !this.redis) {
            return;
        }

        try {
            const key = `${this.TOKEN_PREFIX}${tokenHash}`;
            
            // Need to fetch it first to get userId to remove from secondary index
            const dataStr = await this.redis.get(key);
            if (dataStr) {
                const data = JSON.parse(dataStr) as CachedToken;
                const userIndexKey = `${this.USER_INDEX_PREFIX}${data.userId}`;
                
                const pipeline = this.redis.pipeline();
                pipeline.srem(userIndexKey, key);
                pipeline.del(key);
                await pipeline.exec();
            } else {
                await this.redis.del(key);
            }
            
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
        if (!this.isAvailable() || !this.redis) {
            return 0;
        }

        try {
            const userIndexKey = `${this.USER_INDEX_PREFIX}${userId}`;
            const keys = await this.redis.smembers(userIndexKey);

            if (!keys || keys.length === 0) {
                logger.info(`[TOKEN-CACHE] No tokens found for user: ${userId}`);
                return 0;
            }

            const pipeline = this.redis.pipeline();
            for (const key of keys) {
                pipeline.del(key);
            }
            pipeline.del(userIndexKey);
            await pipeline.exec();

            logger.info(`[TOKEN-CACHE] Invalidated ${keys.length} tokens for user: ${userId}`);
            return keys.length;
        } catch (error) {
            this.stats.errors++;
            logger.error('[TOKEN-CACHE] Error invalidating user tokens:', error);
            return 0;
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
        if (!this.isAvailable() || !this.redis) {
            return { status: 'not_initialized', latencyMs: -1 };
        }
        
        try {
            const start = Date.now();
            await this.redis.ping();
            return { status: 'healthy', latencyMs: Date.now() - start };
        } catch (error) {
            return { status: 'error', latencyMs: -1 };
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown(): Promise<void> {
        if (this.redis) {
            await this.redis.quit();
            logger.info('[TOKEN-CACHE] Redis connection closed gracefully');
        }
    }
}

// Singleton instance
export const tokenCache = new TokenCacheService();
