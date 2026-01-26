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
    console.log('[FEATURE-TOGGLE] Feature toggle client initialized (inline mode)');
    console.log(`[FEATURE-TOGGLE] Service URL: ${config.featureToggleServiceUrl}`);
}

/**
 * Check if auth bypass is enabled
 */
export async function isAuthBypassEnabled(): Promise<boolean> {
    console.log('[FEATURE-TOGGLE] Checking if auth bypass is enabled...');
    try {
        const toggle = await getToggle('authBypass');
        const enabled = toggle?.enabled ?? false;
        console.log(`[FEATURE-TOGGLE] Auth bypass enabled: ${enabled}`);
        return enabled;
    } catch (error) {
        console.warn('[FEATURE-TOGGLE] Failed to check auth bypass status:',
            error instanceof Error ? error.message : 'Unknown error');
        return false;
    }
}

/**
 * Get the demo user for bypass mode
 */
export async function getBypassUser(): Promise<DemoUser | null> {
    console.log('[FEATURE-TOGGLE] Getting bypass demo user...');
    // Check cache
    if (demoUserCache && Date.now() < demoUserCache.expiresAt) {
        console.log('[FEATURE-TOGGLE] Demo user found in cache');
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
            console.log('[FEATURE-TOGGLE] Demo user fetched and cached');
            demoUserCache = {
                data: data.data,
                expiresAt: Date.now() + CACHE_TTL_MS,
            };
            return data.data;
        }

        console.log('[FEATURE-TOGGLE] No demo user found in response');
        return null;
    } catch (error) {
        console.warn('[FEATURE-TOGGLE] Failed to get bypass user:',
            error instanceof Error ? error.message : 'Unknown error');
        return null;
    }
}

/**
 * Get a specific toggle
 */
async function getToggle(name: string): Promise<Toggle | null> {
    console.log(`[FEATURE-TOGGLE] Getting toggle: ${name}`);
    // Check cache
    if (toggleCache && Date.now() < toggleCache.expiresAt) {
        console.log(`[FEATURE-TOGGLE] Toggle '${name}' found in cache`);
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
            console.log(`[FEATURE-TOGGLE] Toggles fetched and cached (${Object.keys(data.data).length} toggles)`);
            toggleCache = {
                data: data.data,
                expiresAt: Date.now() + CACHE_TTL_MS,
            };
            return data.data[name] || null;
        }

        console.log('[FEATURE-TOGGLE] No toggle data in response');
        return null;
    } catch (error) {
        console.warn(`[FEATURE-TOGGLE] Failed to get toggle '${name}':`,
            error instanceof Error ? error.message : 'Unknown error');
        return null;
    }
}

/**
 * Check if a specific toggle is enabled
 */
export async function isToggleEnabled(toggleName: string): Promise<boolean> {
    console.log(`[FEATURE-TOGGLE] Checking if toggle '${toggleName}' is enabled...`);
    try {
        const toggle = await getToggle(toggleName);
        const enabled = toggle?.enabled ?? false;
        console.log(`[FEATURE-TOGGLE] Toggle '${toggleName}' enabled: ${enabled}`);
        return enabled;
    } catch (error) {
        console.warn(`[FEATURE-TOGGLE] Failed to check toggle '${toggleName}':`,
            error instanceof Error ? error.message : 'Unknown error');
        return false;
    }
}

/**
 * Clear the toggle cache (useful for testing)
 */
export function clearToggleCache(): void {
    console.log('[FEATURE-TOGGLE] Clearing toggle cache');
    toggleCache = null;
    demoUserCache = null;
}
