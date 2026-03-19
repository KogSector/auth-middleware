/**
 * ConFuse Auth Middleware - Token Cache Service
 * 
 * Provides in-memory token caching for distributed authentication
 * with TTL-based expiration and cache-first validation pattern.
 */

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

// In-memory cache entry with expiration
interface CacheEntry<T> {
    data: T;
    expiresAt: number;
}

class TokenCacheService {
    private tokenCache: Map<string, CacheEntry<CachedToken>> = new Map();
    private isInitialized = false;
    private stats: CacheStats = { hits: 0, misses: 0, errors: 0 };
    private readonly TOKEN_PREFIX = 'auth:token:';
    private cleanupInterval: ReturnType<typeof setInterval> | null = null;

    /**
     * Initialize in-memory cache
     */
    async initialize(): Promise<void> {
        this.isInitialized = true;

        // Periodic cleanup of expired entries every 60 seconds
        this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);

        logger.info('[TOKEN-CACHE] In-memory token cache service initialized');
    }

    /**
     * Check if cache is available
     */
    isAvailable(): boolean {
        return this.isInitialized;
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
            const entry = this.tokenCache.get(key);

            if (entry && entry.expiresAt > Date.now()) {
                this.stats.hits++;
                logger.debug(`[TOKEN-CACHE] Cache hit for token hash: ${tokenHash.substring(0, 8)}...`);
                return entry.data;
            }

            // Remove expired entry
            if (entry) {
                this.tokenCache.delete(key);
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
            const ttl = config.tokenCacheTtlSeconds;

            this.tokenCache.set(key, {
                data,
                expiresAt: Date.now() + (ttl * 1000),
            });
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
            this.tokenCache.delete(key);
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
            let invalidatedCount = 0;

            for (const [key, entry] of this.tokenCache.entries()) {
                if (entry.data.userId === userId) {
                    this.tokenCache.delete(key);
                    invalidatedCount++;
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
            return { status: 'not_initialized', latencyMs: -1 };
        }
        return { status: 'healthy', latencyMs: 0 };
    }

    /**
     * Clean up expired entries
     */
    private cleanup(): void {
        const now = Date.now();
        let cleaned = 0;
        for (const [key, entry] of this.tokenCache.entries()) {
            if (entry.expiresAt <= now) {
                this.tokenCache.delete(key);
                cleaned++;
            }
        }
        if (cleaned > 0) {
            logger.debug(`[TOKEN-CACHE] Cleaned up ${cleaned} expired entries`);
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown(): Promise<void> {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.tokenCache.clear();
        logger.info('[TOKEN-CACHE] In-memory cache cleared');
    }
}

// Singleton instance
export const tokenCache = new TokenCacheService();

