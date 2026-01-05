/**
 * ConFuse Auth Middleware - Feature Toggle Service
 * 
 * Communicates with the feature-context-toggle service to check bypass status
 */

import { config } from '../config.js';
import type { DemoUser, FeatureToggleResponse } from '../types/index.js';

// Cache for toggle state (TTL: 5 seconds)
let bypassCache: { enabled: boolean; demoUser?: DemoUser; timestamp: number } | null = null;
const CACHE_TTL_MS = 5000;

/**
 * Check if auth bypass is enabled
 */
export async function isAuthBypassEnabled(): Promise<boolean> {
    const cached = getFromCache();
    if (cached !== null) {
        return cached.enabled;
    }

    try {
        const response = await fetch(`${config.featureToggleServiceUrl}/api/toggles/authBypass`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
            signal: AbortSignal.timeout(2000), // 2 second timeout
        });

        if (!response.ok) {
            console.warn('Feature toggle service returned non-OK status:', response.status);
            return false;
        }

        const data = await response.json() as FeatureToggleResponse;

        if (data.success && data.data) {
            bypassCache = {
                enabled: data.data.enabled,
                demoUser: data.data.demoUser,
                timestamp: Date.now(),
            };
            return data.data.enabled;
        }

        return false;
    } catch (error) {
        // Log but don't fail - if toggle service is down, auth works normally
        console.warn('Failed to check auth bypass status:', error instanceof Error ? error.message : 'Unknown error');
        return false;
    }
}

/**
 * Get the demo user for bypass mode
 */
export async function getBypassUser(): Promise<DemoUser | null> {
    // First check cache
    const cached = getFromCache();
    if (cached !== null && cached.demoUser) {
        return cached.demoUser;
    }

    try {
        const response = await fetch(`${config.featureToggleServiceUrl}/api/toggles/auth-bypass/user`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
            signal: AbortSignal.timeout(2000),
        });

        if (!response.ok) {
            return null;
        }

        const data = await response.json() as { success: boolean; data?: DemoUser };

        if (data.success && data.data) {
            // Update cache with demo user
            if (bypassCache) {
                bypassCache.demoUser = data.data;
            }
            return data.data;
        }

        return null;
    } catch (error) {
        console.warn('Failed to get bypass user:', error instanceof Error ? error.message : 'Unknown error');
        return null;
    }
}

/**
 * Get cached toggle state if still valid
 */
function getFromCache(): typeof bypassCache {
    if (!bypassCache) return null;

    if (Date.now() - bypassCache.timestamp > CACHE_TTL_MS) {
        bypassCache = null;
        return null;
    }

    return bypassCache;
}

/**
 * Clear the toggle cache (useful for testing)
 */
export function clearToggleCache(): void {
    bypassCache = null;
}
