/**
 * ConFuse Auth Middleware - Auth0 Service
 * 
 * Handles Auth0 token verification with JWKS caching
 * 
 * DSA Patterns Implemented:
 * - LRU Cache for token verification results (O(1) operations)
 * - TTL-based cache invalidation
 * - Optimized role extraction with Set operations
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { config } from '../config.js';
import type { Auth0Claims, Auth0UserInfo, CacheStats, CacheEntry } from '../types/index.js';

// =============================================================================
// DSA: LRU Cache for Token Verification - O(1) get/set operations
// =============================================================================

/**
 * Simple LRU Cache implementation using Map (which maintains insertion order)
 * Time Complexity: O(1) for get/set operations
 * Space Complexity: O(n) where n = capacity
 */
class TokenCache {
    private capacity: number;
    private ttlMs: number;
    private cache: Map<string, CacheEntry<JWTPayload>>;
    private hits: number = 0;
    private misses: number = 0;

    constructor(capacity: number = 1000, ttlMs: number = 60000) {
        this.capacity = capacity;
        this.ttlMs = ttlMs;
        this.cache = new Map();
    }

    /**
     * Hash token for cache key (avoid storing full tokens)
     * Using simple djb2 hash - O(n) where n = token length
     */
    private hashToken(token: string): string {
        let hash = 5381;
        for (let i = 0; i < token.length; i++) {
            hash = ((hash << 5) + hash) ^ token.charCodeAt(i);
        }
        return hash.toString(36);
    }

    /**
     * Get cached verification result
     */
    get(token: string): JWTPayload | null {
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
     */
    set(token: string, payload: JWTPayload): void {
        const key = this.hashToken(token);

        // Evict LRU entry if at capacity - O(1)
        if (this.cache.size >= this.capacity && !this.cache.has(key)) {
            const firstKey = this.cache.keys().next().value;
            if (firstKey) {
                this.cache.delete(firstKey);
            }
        }

        this.cache.set(key, {
            payload,
            timestamp: Date.now(),
        });
    }

    /**
     * Get cache statistics
     */
    getStats(): CacheStats {
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
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJWKS(): ReturnType<typeof createRemoteJWKSet> {
    if (!jwks) {
        jwks = createRemoteJWKSet(new URL(config.auth0.jwksUri));
    }
    return jwks;
}

/**
 * Verify Auth0 access token with caching
 */
export async function verifyAuth0Token(token: string): Promise<Auth0Claims> {
    // DSA: Check cache first - O(1)
    const cached = tokenCache.get(token);
    if (cached) {
        return cached as Auth0Claims;
    }

    try {
        const { payload } = await jwtVerify(token, getJWKS(), {
            issuer: config.auth0.issuer,
            audience: config.auth0.audience,
        });

        // DSA: Cache successful verification - O(1)
        tokenCache.set(token, payload);

        return payload as Auth0Claims;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Auth0 token verification failed: ${message}`);
    }
}

/**
 * Extract user info from Auth0 claims
 */
export function extractUserInfo(claims: Auth0Claims): Auth0UserInfo {
    // Try to get email from standard claim or namespaced claims
    let email: string | null = claims.email || null;

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
 */
export function extractRoles(claims: Auth0Claims): string[] {
    const roles = new Set<string>();

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
export function getTokenCacheStats(): CacheStats {
    return tokenCache.getStats();
}
// ... existing code ...

/**
 * Auth0 Management API Client
 * Used to fetch user details and IdP tokens
 */
export class Auth0ManagementClient {
    private static instance: Auth0ManagementClient;
    private token: string | null = null;
    private expiresAt: number = 0;

    private constructor() { }

    static getInstance(): Auth0ManagementClient {
        if (!Auth0ManagementClient.instance) {
            Auth0ManagementClient.instance = new Auth0ManagementClient();
        }
        return Auth0ManagementClient.instance;
    }

    /**
     * Get M2M Access Token for Management API
     */
    private async getAccessToken(): Promise<string> {
        if (this.token && Date.now() < this.expiresAt) {
            return this.token;
        }

        if (!config.auth0.clientId || !config.auth0.clientSecret) {
            throw new Error('Auth0 Client ID/Secret not configured for Management API');
        }

        const response = await fetch(`https://${config.auth0.domain}/oauth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: config.auth0.clientId,
                client_secret: config.auth0.clientSecret,
                audience: `https://${config.auth0.managementDomain}/api/v2/`,
                grant_type: 'client_credentials',
            }),
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Failed to get Auth0 Management token: ${response.status} ${text}`);
        }

        const data: any = await response.json();
        this.token = data.access_token;
        // Cache for slightly less than expires_in to be safe
        this.expiresAt = Date.now() + (data.expires_in * 1000) - 60000;

        return this.token!;
    }

    /**
     * Get User Identities (including IdP tokens)
     * Requires the M2M app to have `read:user_idp_tokens` scope
     */
    async getUserIdentities(userId: string): Promise<any[]> {
        const token = await this.getAccessToken();
        // safe userId encoding
        const encodedUserId = encodeURIComponent(userId);

        const response = await fetch(`https://${config.auth0.managementDomain}/api/v2/users/${encodedUserId}`, {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });

        if (!response.ok) {
            throw new Error(`Failed to fetch user details: ${response.status}`);
        }

        const user: any = await response.json();
        return user.identities || [];
    }
}
