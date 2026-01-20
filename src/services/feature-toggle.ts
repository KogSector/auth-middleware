/**
 * ConFuse Auth Middleware - Feature Toggle Service
 * 
 * Uses the @confuse/feature-toggle-sdk for toggle management.
 */

import {
    initToggleClient,
    getToggleClient,
    type DemoUser
} from '@confuse/feature-toggle-sdk';
import { config } from '../config.js';

// Re-export DemoUser type for backwards compatibility
export type { DemoUser } from '@confuse/feature-toggle-sdk';

// Track if client is initialized
let initialized = false;

/**
 * Initialize the toggle client (call once at startup)
 */
export function initFeatureToggle(): void {
    if (initialized) return;

    initToggleClient({
        serviceUrl: config.featureToggleServiceUrl,
        serviceName: 'auth-middleware',
        cacheTtlMs: 5000,
        timeoutMs: 2000,
        retryAttempts: 2,
        defaultEnabled: false, // Fail-safe: disable features when service unavailable
        onServiceUnavailable: (error) => {
            console.warn('[AuthMiddleware] Feature toggle service unavailable:', error.message);
        },
    });

    initialized = true;
    console.log('[AuthMiddleware] Feature toggle client initialized');
}

/**
 * Check if auth bypass is enabled
 */
export async function isAuthBypassEnabled(): Promise<boolean> {
    try {
        const client = getToggleClient();
        return await client.isEnabled('authBypass');
    } catch (error) {
        // Client not initialized or other error
        console.warn('Failed to check auth bypass status:',
            error instanceof Error ? error.message : 'Unknown error');
        return false;
    }
}

/**
 * Get the demo user for bypass mode
 */
export async function getBypassUser(): Promise<DemoUser | null> {
    try {
        const client = getToggleClient();
        const demoUser = await client.getDemoUser();
        return demoUser;
    } catch (error) {
        console.warn('Failed to get bypass user:',
            error instanceof Error ? error.message : 'Unknown error');
        return null;
    }
}

/**
 * Check if a specific toggle is enabled
 */
export async function isToggleEnabled(toggleName: string): Promise<boolean> {
    try {
        const client = getToggleClient();
        return await client.isEnabled(toggleName);
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
    try {
        const client = getToggleClient();
        client.invalidateCache();
    } catch {
        // Client not initialized, ignore
    }
}
