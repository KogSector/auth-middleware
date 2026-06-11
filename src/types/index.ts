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


// Session types removed as session management is handled by Auth0


// ============================================================================
// Express Extensions
// ============================================================================

export interface AuthenticatedRequest extends Request {
    user?: Auth0Claims;
}

// ============================================================================
// API Response Types
// ============================================================================


export interface AuthExchangeResponse {
    user: UserProfile;
}

// TokenRefreshResponse removed as we use Auth0 refresh tokens on client side

export interface TokenVerifyResponse {
    valid: boolean;
    claims?: Auth0Claims;
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


