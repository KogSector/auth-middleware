/**
 * @confuse/feature-toggle-sdk - Toggle Client
 * 
 * Main client for interacting with the Feature Toggle service.
 * Includes automatic caching, retry logic, and graceful fallbacks.
 */

import type {
    ToggleClientConfig,
    FeatureToggle,
    ToggleState,
    ApiResponse,
    DemoUser,
} from './types.js';

// =============================================================================
// Cache Entry
// =============================================================================

interface CacheEntry<T> {
    data: T;
    expiresAt: number;
}

// =============================================================================
// Toggle Client
// =============================================================================

export class ToggleClient {
    private config: Required<Omit<ToggleClientConfig, 'onServiceUnavailable'>> & {
        onServiceUnavailable?: (error: Error) => void;
    };
    private cache: Map<string, CacheEntry<unknown>> = new Map();
    private allTogglesCache: CacheEntry<ToggleState> | null = null;

    constructor(config: ToggleClientConfig) {
        this.config = {
            serviceUrl: config.serviceUrl,
            cacheTtlMs: config.cacheTtlMs ?? 5000,
            timeoutMs: config.timeoutMs ?? 2000,
            retryAttempts: config.retryAttempts ?? 2,
            retryDelayMs: config.retryDelayMs ?? 500,
            serviceName: config.serviceName ?? 'unknown-service',
            defaultEnabled: config.defaultEnabled ?? false,
            onServiceUnavailable: config.onServiceUnavailable,
        };
    }

    // =========================================================================
    // Core Methods
    // =========================================================================

    /**
     * Check if a toggle is enabled
     */
    async isEnabled(toggleName: string): Promise<boolean> {
        const toggle = await this.getToggle(toggleName);
        return toggle?.enabled ?? this.config.defaultEnabled;
    }

    /**
     * Get a specific toggle by name
     */
    async getToggle(toggleName: string): Promise<FeatureToggle | null> {
        // Check cache first
        const cached = this.getCached<FeatureToggle>(`toggle:${toggleName}`);
        if (cached !== null) {
            return cached;
        }

        try {
            const response = await this.fetchWithRetry<ApiResponse<FeatureToggle>>(
                `/api/toggles/${encodeURIComponent(toggleName)}`
            );

            if (response.success && response.data) {
                this.setCache(`toggle:${toggleName}`, response.data);
                return response.data;
            }

            return null;
        } catch (error) {
            this.handleError(error as Error);
            return null;
        }
    }

    /**
     * Get all toggles
     */
    async getAllToggles(): Promise<ToggleState> {
        // Check cache first
        if (this.allTogglesCache && Date.now() < this.allTogglesCache.expiresAt) {
            return this.allTogglesCache.data;
        }

        try {
            const response = await this.fetchWithRetry<ApiResponse<ToggleState>>(
                '/api/toggles'
            );

            if (response.success && response.data) {
                this.allTogglesCache = {
                    data: response.data,
                    expiresAt: Date.now() + this.config.cacheTtlMs,
                };
                return response.data;
            }

            return {};
        } catch (error) {
            this.handleError(error as Error);
            return {};
        }
    }

    /**
     * Get toggles by category
     */
    async getTogglesByCategory(category: string): Promise<ToggleState> {
        const cacheKey = `category:${category}`;
        const cached = this.getCached<ToggleState>(cacheKey);
        if (cached !== null) {
            return cached;
        }

        try {
            const response = await this.fetchWithRetry<ApiResponse<ToggleState>>(
                `/api/toggles?category=${encodeURIComponent(category)}`
            );

            if (response.success && response.data) {
                this.setCache(cacheKey, response.data);
                return response.data;
            }

            return {};
        } catch (error) {
            this.handleError(error as Error);
            return {};
        }
    }

    /**
     * Get demo user for auth bypass (development only)
     */
    async getDemoUser(): Promise<DemoUser | null> {
        const cached = this.getCached<DemoUser>('demoUser');
        if (cached !== null) {
            return cached;
        }

        try {
            const response = await this.fetchWithRetry<ApiResponse<DemoUser>>(
                '/api/toggles/auth-bypass/user'
            );

            if (response.success && response.data) {
                this.setCache('demoUser', response.data);
                return response.data;
            }

            return null;
        } catch (error) {
            this.handleError(error as Error);
            return null;
        }
    }

    /**
     * Check multiple toggles at once
     */
    async areEnabled(toggleNames: string[]): Promise<Record<string, boolean>> {
        const result: Record<string, boolean> = {};
        const toggles = await this.getAllToggles();

        for (const name of toggleNames) {
            result[name] = toggles[name]?.enabled ?? this.config.defaultEnabled;
        }

        return result;
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /**
     * Invalidate all cached data
     */
    invalidateCache(): void {
        this.cache.clear();
        this.allTogglesCache = null;
    }

    /**
     * Invalidate a specific toggle's cache
     */
    invalidateToggle(toggleName: string): void {
        this.cache.delete(`toggle:${toggleName}`);
        this.allTogglesCache = null;
    }

    // =========================================================================
    // Private Methods
    // =========================================================================

    private getCached<T>(key: string): T | null {
        const entry = this.cache.get(key) as CacheEntry<T> | undefined;
        if (entry && Date.now() < entry.expiresAt) {
            return entry.data;
        }
        this.cache.delete(key);
        return null;
    }

    private setCache<T>(key: string, data: T): void {
        this.cache.set(key, {
            data,
            expiresAt: Date.now() + this.config.cacheTtlMs,
        });
    }

    private async fetchWithRetry<T>(path: string, attempt: number = 1): Promise<T> {
        const url = `${this.config.serviceUrl}${path}`;

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Service-Name': this.config.serviceName,
                },
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json() as T;
        } catch (error) {
            if (attempt < this.config.retryAttempts) {
                await this.delay(this.config.retryDelayMs * attempt);
                return this.fetchWithRetry(path, attempt + 1);
            }
            throw error;
        }
    }

    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private handleError(error: Error): void {
        console.warn(`[FeatureToggle] Service unavailable: ${error.message}`);
        if (this.config.onServiceUnavailable) {
            this.config.onServiceUnavailable(error);
        }
    }
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create a new ToggleClient instance
 */
export function createToggleClient(config: ToggleClientConfig): ToggleClient {
    return new ToggleClient(config);
}

// =============================================================================
// Singleton Pattern (Optional)
// =============================================================================

let defaultClient: ToggleClient | null = null;

/**
 * Initialize the default toggle client
 */
export function initToggleClient(config: ToggleClientConfig): ToggleClient {
    defaultClient = new ToggleClient(config);
    return defaultClient;
}

/**
 * Get the default toggle client (must be initialized first)
 */
export function getToggleClient(): ToggleClient {
    if (!defaultClient) {
        throw new Error('Toggle client not initialized. Call initToggleClient() first.');
    }
    return defaultClient;
}

/**
 * Check if a toggle is enabled using the default client
 */
export async function isToggleEnabled(toggleName: string): Promise<boolean> {
    return getToggleClient().isEnabled(toggleName);
}
