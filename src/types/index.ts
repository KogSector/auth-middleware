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
    roles?: string[]; // Augmented by middleware
    [key: string]: unknown;
}

export interface Auth0UserInfo {
    auth0Sub: string;
    email: string;
    name: string | null;
    picture: string | null;
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

export interface CacheEntry<T> {
    payload: T;
    timestamp: number;
}

// ============================================================================
// Workspace Types
// ============================================================================

export interface Workspace {
    id: string;
    name: string;
    slug: string;
    description: string | null;
    ownerId: string;
    isDefault: boolean;
    settings: Record<string, unknown>;
    createdAt: Date;
    updatedAt: Date;
}

export interface WorkspaceMember {
    id: string;
    workspaceId: string;
    userId: string;
    role: 'owner' | 'admin' | 'member' | 'viewer';
    joinedAt: Date;
}

export interface KnowledgeBase {
    id: string;
    workspaceId: string;
    name: string;
    description: string | null;
    type: 'general' | 'code' | 'docs' | 'chat';
    status: 'active' | 'archived' | 'processing';
    embeddingModel: string;
    milvusCollection: string | null;
    neo4jNamespace: string | null;
    mongoCollection: string | null;
    documentCount: number;
    embeddingCount: number;
    createdAt: Date;
    updatedAt: Date;
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

