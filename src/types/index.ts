/**
 * ConFuse Auth Middleware - Type Definitions
 */

import type { Request } from 'express';

// ============================================================================
// User Types
// ============================================================================

export interface User {
    id: string;
    auth0Sub: string;
    email: string;
    name: string | null;
    picture: string | null;
    roles: string[];
    createdAt: Date;
    updatedAt: Date;
    lastLoginAt: Date | null;
    onboardingCompleted: boolean;
    userIntent: string | null;
    dashboardPreset: string | null;
}

export interface UserProfile {
    id: string;
    email: string;
    name: string | null;
    picture: string | null;
    roles: string[];
    createdAt: string;
    onboardingCompleted: boolean;
    userIntent: string | null;
    dashboardPreset: string | null;
}

export interface CreateUserInput {
    auth0Sub: string;
    email: string;
    name?: string | null;
    picture?: string | null;
    roles?: string[];
}

// ============================================================================
// Auth0 Types
// ============================================================================

export interface Auth0Claims {
    sub: string;
    email?: string;
    name?: string;
    picture?: string;
    permissions?: string[];
    roles?: string[]; // Augmented by middleware
    [key: string]: unknown;
}

export interface Auth0UserInfo {
    auth0Sub: string;
    email: string;
    name: string | null;
    picture: string | null;
}

// Session types removed as session management is handled by Auth0

// Feature Toggle Types
// ============================================================================

export interface DemoUser {
    id: string;
    sub: string; // Alias for id to match Auth0Claims
    email: string;
    name: string;
    roles: string[];
    sessionId: string;
}

export interface FeatureToggleResponse {
    success: boolean;
    data?: {
        enabled: boolean;
        demoUser?: DemoUser;
    };
    error?: string;
}

// ============================================================================
// Express Extensions
// ============================================================================

export interface AuthenticatedRequest extends Request {
    user?: Auth0Claims | DemoUser;
}

// ============================================================================
// API Response Types
// ============================================================================

export interface ApiError {
    error: string;
    message?: string;
}

export interface AuthExchangeResponse {
    user: UserProfile;
}

// TokenRefreshResponse removed as we use Auth0 refresh tokens on client side

export interface TokenVerifyResponse {
    valid: boolean;
    claims?: Auth0Claims | DemoUser;
    error?: string;
}

// ============================================================================
// Cache Types
// ============================================================================

export interface CacheStats {
    hits: number;
    misses: number;
    hitRate: number;
    size: number;
    capacity: number;
}


// ============================================================================
// User Context (for propagation across services)
// ============================================================================

export interface UserContext {
    userId: string;
    email: string;
    workspaceId: string;
    roles: string[];
}

