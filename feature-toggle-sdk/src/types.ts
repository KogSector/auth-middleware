/**
 * @confuse/feature-toggle-sdk - Type Definitions
 */

// =============================================================================
// Core Types
// =============================================================================

export type CategoryType = 'devOnly' | 'userFacing' | 'ops';

export interface FeatureToggle {
    name: string;
    enabled: boolean;
    description: string;
    category: string;
    categoryType?: CategoryType;
    metadata?: Record<string, unknown>;
}

export interface DemoUser {
    id: string;
    email: string;
    name: string;
    roles: string[];
    sessionId: string;
}

export interface ToggleState {
    [key: string]: Omit<FeatureToggle, 'name'>;
}

// =============================================================================
// API Response Types
// =============================================================================

export interface ApiResponse<T = unknown> {
    success: boolean;
    data?: T;
    error?: string;
    errors?: string[];
    timestamp: string;
    cached?: boolean;
}

// =============================================================================
// Client Configuration
// =============================================================================

export interface ToggleClientConfig {
    /**
     * Base URL of the feature toggle service
     * @default 'http://localhost:3099'
     */
    serviceUrl: string;

    /**
     * Cache TTL in milliseconds
     * @default 5000 (5 seconds)
     */
    cacheTtlMs?: number;

    /**
     * Request timeout in milliseconds
     * @default 2000 (2 seconds)
     */
    timeoutMs?: number;

    /**
     * Number of retry attempts on failure
     * @default 2
     */
    retryAttempts?: number;

    /**
     * Delay between retries in milliseconds
     * @default 500
     */
    retryDelayMs?: number;

    /**
     * Service name for audit logging (sent as X-Service-Name header)
     */
    serviceName?: string;

    /**
     * Default value when toggle is not found or service is unavailable
     * @default false
     */
    defaultEnabled?: boolean;

    /**
     * Callback when toggle service is unavailable
     */
    onServiceUnavailable?: (error: Error) => void;
}

// =============================================================================
// Middleware Types
// =============================================================================

export interface ToggleMiddlewareOptions {
    /**
     * Toggle name to check
     */
    toggle: string;

    /**
     * Action when toggle is disabled
     * @default 'block' - Returns 404
     */
    onDisabled?: 'block' | 'skip' | ((req: unknown, res: unknown, next: unknown) => void);

    /**
     * HTTP status code when blocked
     * @default 404
     */
    blockedStatus?: number;

    /**
     * Error message when blocked
     */
    blockedMessage?: string;
}
