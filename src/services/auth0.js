/**
 * ConHub Auth Middleware - Auth0 Service
 * 
 * Handles Auth0 token verification with JWKS caching
 * 
 * DSA Patterns Implemented:
 * - LRU Cache for token verification results (O(1) operations)
 * - TTL-based cache invalidation
 * - Optimized role extraction with Set operations
 */

const { createRemoteJWKSet, jwtVerify } = require('jose');
const { config } = require('../config');

// =============================================================================
// DSA: LRU Cache for Token Verification - O(1) get/set operations
// =============================================================================

/**
 * Simple LRU Cache implementation using Map (which maintains insertion order)
 * Time Complexity: O(1) for get/set operations
 * Space Complexity: O(n) where n = capacity
 */
class TokenCache {
    constructor(capacity = 1000, ttlMs = 60000) {
        this.capacity = capacity;
        this.ttlMs = ttlMs;
        this.cache = new Map();
        this.hits = 0;
        this.misses = 0;
    }

    /**
     * Hash token for cache key (avoid storing full tokens)
     * Using simple djb2 hash - O(n) where n = token length
     */
    hashToken(token) {
        let hash = 5381;
        for (let i = 0; i < token.length; i++) {
            hash = ((hash << 5) + hash) ^ token.charCodeAt(i);
        }
        return hash.toString(36);
    }

    /**
     * Get cached verification result
     * @param {string} token - JWT token
     * @returns {Object|null} Cached payload or null
     */
    get(token) {
        const key = this.hashToken(token);
        const entry = this.cache.get(key);

        if (!entry) {
            this.misses++;
            return null;
        }

        // Check TTL expiration
        if (Date.now() - entry.timestamp > this.ttlMs) {
            this.cache.delete(key);
            this.misses++;
            return null;
        }

        // Move to end (most recently used) - O(1) with Map
        this.cache.delete(key);
        this.cache.set(key, entry);
        this.hits++;

        return entry.payload;
    }

    /**
     * Cache verification result
     * @param {string} token - JWT token
     * @param {Object} payload - Verified payload
     */
    set(token, payload) {
        const key = this.hashToken(token);

        // Evict LRU entry if at capacity - O(1)
        if (this.cache.size >= this.capacity && !this.cache.has(key)) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        this.cache.set(key, {
            payload,
            timestamp: Date.now(),
        });
    }

    /**
     * Get cache statistics
     */
    getStats() {
        const total = this.hits + this.misses;
        return {
            hits: this.hits,
            misses: this.misses,
            hitRate: total > 0 ? this.hits / total : 0,
            size: this.cache.size,
            capacity: this.capacity,
        };
    }
}

// Initialize token cache (1000 tokens, 1 minute TTL)
const tokenCache = new TokenCache(1000, 60000);

// JWKS remote key set (cached by jose library)
let jwks = null;

function getJWKS() {
    if (!jwks) {
        jwks = createRemoteJWKSet(new URL(config.auth0.jwksUri));
    }
    return jwks;
}

/**
 * Verify Auth0 access token with caching
 * @param {string} token - Auth0 access token
 * @returns {Promise<Object>} - Decoded claims
 */
async function verifyAuth0Token(token) {
    // DSA: Check cache first - O(1)
    const cached = tokenCache.get(token);
    if (cached) {
        return cached;
    }

    try {
        const { payload } = await jwtVerify(token, getJWKS(), {
            issuer: config.auth0.issuer,
            audience: config.auth0.audience,
        });

        // DSA: Cache successful verification - O(1)
        tokenCache.set(token, payload);

        return payload;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Auth0 token verification failed: ${message}`);
    }
}

/**
 * Extract user info from Auth0 claims
 * @param {Object} claims - Auth0 JWT claims
 * @returns {Object} - User info
 */
function extractUserInfo(claims) {
    // Try to get email from standard claim or namespaced claims
    let email = claims.email || null;

    // Check for namespaced email claims (Auth0 custom namespace)
    if (!email) {
        const namespaces = ['https://conhub.dev/', 'https://api.conhub.dev/'];
        for (const ns of namespaces) {
            const nsEmail = claims[`${ns}email`];
            if (typeof nsEmail === 'string') {
                email = nsEmail;
                break;
            }
        }
    }

    // Generate synthetic email if not available
    if (!email) {
        const sanitizedSub = claims.sub.replace(/\|/g, '.');
        email = `${sanitizedSub}@auth0.local`;
    }

    return {
        auth0Sub: claims.sub,
        email,
        name: claims.name || null,
        picture: claims.picture || null,
    };
}

/**
 * Extract roles from permissions using Set for O(1) lookup
 * @param {Object} claims - Auth0 JWT claims
 * @returns {string[]} - User roles
 */
function extractRoles(claims) {
    const roles = new Set();

    if (claims.permissions && Array.isArray(claims.permissions)) {
        // DSA: Use Set for O(1) contains check
        const permissionSet = new Set(claims.permissions);

        // Check for admin permissions using Set operations
        const adminPrefixes = ['admin', 'admin:', 'admin_'];
        for (const perm of permissionSet) {
            if (adminPrefixes.some(prefix => perm.startsWith(prefix))) {
                roles.add('admin');
                break;
            }
        }
    }

    if (roles.size === 0) {
        roles.add('user');
    }

    return Array.from(roles);
}

/**
 * Get token cache statistics (for monitoring)
 */
function getTokenCacheStats() {
    return tokenCache.getStats();
}

module.exports = {
    verifyAuth0Token,
    extractUserInfo,
    extractRoles,
    getTokenCacheStats,
};

