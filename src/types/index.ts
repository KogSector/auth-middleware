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
}

export interface UserProfile {
    id: string;
    email: string;
    name: string | null;
    picture: string | null;
    roles: string[];
    createdAt: string;
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
    [key: string]: unknown;
}

export interface Auth0UserInfo {
    auth0Sub: string;
    email: string;
    name: string | null;
    picture: string | null;
}

// ============================================================================
// JWT Types
// ============================================================================

export interface JwtPayload {
    sub: string;
    email: string;
    roles: string[];
    sessionId: string;
    jti: string;
}

export interface RefreshPayload {
    sub: string;
    sessionId: string;
    type: 'refresh';
}

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
    expiresAt: Date;
    refreshExpiresAt: Date;
}

// ============================================================================
// Session Types
// ============================================================================

export interface Session {
    id: string;
    userId: string;
    refreshToken: string;
    expiresAt: Date;
    createdAt: Date;
    revokedAt: Date | null;
    userAgent: string | null;
    ipAddress: string | null;
    user?: User;
}

// ============================================================================
// Feature Toggle Types
// ============================================================================

export interface DemoUser {
    id: string;
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
    user?: JwtPayload | DemoUser;
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
    token: string;
    refreshToken: string;
    expiresAt: string;
    sessionId: string;
}

export interface TokenRefreshResponse {
    token: string;
    refreshToken: string;
    expiresAt: string;
}

export interface TokenVerifyResponse {
    valid: boolean;
    claims?: JwtPayload;
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

export interface CacheEntry<T> {
    payload: T;
    timestamp: number;
}
