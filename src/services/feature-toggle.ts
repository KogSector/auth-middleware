/**
 * ConFuse Auth Middleware - Feature Toggle Service
 * 
 * HTTP client for feature toggle service with caching.
 * Note: This is an inline implementation for Docker builds.
 * For local development, use @confuse/feature-toggle-sdk.
 */

import { config } from '../config.js';

// Re-export DemoUser type
export interface DemoUser {
    id: string;
    email: string;
    name: string;
    roles: string[];
    sessionId: string;
}

interface Toggle {
    enabled: boolean;
    description: string;
    category: string;
    categoryType?: string;
    demoUser?: DemoUser;
}

interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
}

// Cache configuration
const CACHE_TTL_MS = 5000;
let toggleCache: { data: Record<string, Toggle>; expiresAt: number } | null = null;
let demoUserCache: { data: DemoUser; expiresAt: number } | null = null;

/**
 * Initialize the toggle client (no-op for Docker build compatibility)
 */
export function initFeatureToggle(): void {
    console.log('[AuthMiddleware] Feature toggle client initialized (inline mode)');
}

/**
 * Check if auth bypass is enabled
 */
export async function isAuthBypassEnabled(): Promise<boolean> {
    try {
        const toggle = await getToggle('authBypass');
        return toggle?.enabled ?? false;
    } catch (error) {
        console.warn('Failed to check auth bypass status:',
            error instanceof Error ? error.message : 'Unknown error');
        return false;
    }
}

/**
 * Get the demo user for bypass mode
 */
export async function getBypassUser(): Promise<DemoUser | null> {
    // Check cache
    if (demoUserCache && Date.now() < demoUserCache.expiresAt) {
        return demoUserCache.data;
    }

    try {
        const response = await fetch(
            `${config.featureToggleServiceUrl}/api/toggles/auth-bypass/user`,
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Service-Name': 'auth-middleware',
                },
                signal: AbortSignal.timeout(2000),
            }
        );

        if (!response.ok) {
            return null;
        }

        const data = await response.json() as ApiResponse<DemoUser>;

        if (data.success && data.data) {
            demoUserCache = {
                data: data.data,
                expiresAt: Date.now() + CACHE_TTL_MS,
            };
            return data.data;
        }

        return null;
    } catch (error) {
        console.warn('Failed to get bypass user:',
            error instanceof Error ? error.message : 'Unknown error');
        return null;
    }
}

/**
 * Get a specific toggle
 */
async function getToggle(name: string): Promise<Toggle | null> {
    // Check cache
    if (toggleCache && Date.now() < toggleCache.expiresAt) {
        return toggleCache.data[name] || null;
    }

    try {
        const response = await fetch(
            `${config.featureToggleServiceUrl}/api/toggles`,
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Service-Name': 'auth-middleware',
                },
                signal: AbortSignal.timeout(2000),
            }
        );

        if (!response.ok) {
            return null;
        }

        const data = await response.json() as ApiResponse<Record<string, Toggle>>;

        if (data.success && data.data) {
            toggleCache = {
                data: data.data,
                expiresAt: Date.now() + CACHE_TTL_MS,
            };
            return data.data[name] || null;
        }

        return null;
    } catch (error) {
        console.warn('Failed to get toggle:',
            error instanceof Error ? error.message : 'Unknown error');
        return null;
    }
}

/**
 * Check if a specific toggle is enabled
 */
export async function isToggleEnabled(toggleName: string): Promise<boolean> {
    try {
        const toggle = await getToggle(toggleName);
        return toggle?.enabled ?? false;
    } catch (error) {
        console.warn(`Failed to check toggle '${toggleName}':`,
            error instanceof Error ? error.message : 'Unknown error');
        return false;
    }
}

/**
 * Clear the toggle cache (useful for testing)
 */
export function clearToggleCache(): void {
    toggleCache = null;
    demoUserCache = null;
}
