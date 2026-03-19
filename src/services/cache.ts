/**
 * ConFuse Auth Middleware - Token Cache Service
 * 
 * Provides in-memory token caching for distributed authentication
 * with TTL-based expiration and cache-first validation pattern.
 */

import { config } from '../config.js';
import { logger } from '../utils/logger.js';
import BloomFilter from '../messaging/bloomFilter.js';

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
    // DSA: Secondary index — userId → Set<cacheKey> for O(1) user-token invalidation.
    // Without this, invalidateUserTokens() requires O(n) scan of the entire cache.
    private userKeyIndex: Map<string, Set<string>> = new Map();
    private bloomFilter = new BloomFilter(20000, 0.01); // Capacity for 20k tokens
    private isInitialized = false;
    private stats: CacheStats = { hits: 0, misses: 0, errors: 0 };
    private readonly TOKEN_PREFIX = 'auth:token:';
    private cleanupInterval: ReturnType<typeof setInterval> | null = null;
    private readonly MAX_CACHE_SIZE = 5000; // Limit in-memory cache size

    /**
     * Initialize in-memory cache
     */
    async initialize(): Promise<void> {
        this.isInitialized = true;

        // Periodic cleanup of expired entries every 60 seconds
        this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);

        logger.info('[TOKEN-CACHE] In-memory token cache service initialized (Bloom Filter + LRU active)');
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
            // DSA Optimization 1: Bloom Filter early exit (O(1) probabilistic check)
            if (!this.bloomFilter.check(tokenHash)) {
                this.stats.misses++;
                return null;
            }

            const key = `${this.TOKEN_PREFIX}${tokenHash}`;
            const entry = this.tokenCache.get(key);

            if (entry && entry.expiresAt > Date.now()) {
                // DSA Optimization 2: LRU - Move accessed entry to the end
                this.tokenCache.delete(key);
                this.tokenCache.set(key, entry);

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

            // DSA Optimization 3: Add to Bloom Filter
            this.bloomFilter.add(tokenHash);

            // DSA Optimization 4: LRU Eviction (size-based)
            if (this.tokenCache.size >= this.MAX_CACHE_SIZE && !this.tokenCache.has(key)) {
                // Remove the oldest item (first key in Map iterator)
                const oldestKey = this.tokenCache.keys().next().value;
                if (oldestKey) {
                    // DSA: Also remove from secondary userId index on eviction
                    const evicted = this.tokenCache.get(oldestKey);
                    if (evicted) {
                        const userKeys = this.userKeyIndex.get(evicted.data.userId);
                        if (userKeys) {
                            userKeys.delete(oldestKey);
                            if (userKeys.size === 0) this.userKeyIndex.delete(evicted.data.userId);
                        }
                    }
                    this.tokenCache.delete(oldestKey);
                    logger.debug(`[TOKEN-CACHE] LRU Evicted oldest key: ${oldestKey}`);
                }
            }

            this.tokenCache.set(key, {
                data,
                expiresAt: Date.now() + (ttl * 1000),
            });

            // DSA: Maintain the userId → keys secondary index
            if (!this.userKeyIndex.has(data.userId)) {
                this.userKeyIndex.set(data.userId, new Set());
            }
            this.userKeyIndex.get(data.userId)!.add(key);

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
            // DSA: Remove from secondary userId index before deleting
            const entry = this.tokenCache.get(key);
            if (entry) {
                const userKeys = this.userKeyIndex.get(entry.data.userId);
                if (userKeys) {
                    userKeys.delete(key);
                    if (userKeys.size === 0) this.userKeyIndex.delete(entry.data.userId);
                }
            }
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
            // DSA: O(k) invalidation via secondary index, where k = tokens belonging to this user.
            // Previously O(n) scanning the entire tokenCache Map.
            const userKeys = this.userKeyIndex.get(userId);
            if (!userKeys || userKeys.size === 0) {
                logger.info(`[TOKEN-CACHE] No tokens found for user: ${userId}`);
                return 0;
            }

            const invalidatedCount = userKeys.size;
            for (const key of userKeys) {
                this.tokenCache.delete(key);
            }
            this.userKeyIndex.delete(userId);

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
                // DSA: Maintain userId index during cleanup
                const userKeys = this.userKeyIndex.get(entry.data.userId);
                if (userKeys) {
                    userKeys.delete(key);
                    if (userKeys.size === 0) this.userKeyIndex.delete(entry.data.userId);
                }
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
        this.userKeyIndex.clear();
        logger.info('[TOKEN-CACHE] In-memory cache cleared');
    }
}

// Singleton instance
export const tokenCache = new TokenCacheService();

