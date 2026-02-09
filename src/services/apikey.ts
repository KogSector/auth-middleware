/**
 * ConFuse Auth Middleware - API Key Service
 * 
 * Manages API keys for programmatic access with scopes and rate limiting.
 */

import { ApiKey } from '@prisma/client';
import crypto from 'crypto';
import { logger } from '../utils/logger.js';
import prisma from '../db/client.js';

// Types
export interface CreateApiKeyInput {
    userId: string;
    name: string;
    scopes?: string[];
    expiresAt?: Date;
    rateLimit?: number;
}

export interface ApiKeyResponse {
    id: string;
    name: string;
    keyPrefix: string;
    scopes: string[];
    expiresAt: string | null;
    createdAt: string;
    lastUsedAt: string | null;
    rateLimit: number;
}

export interface ApiKeyWithSecret extends ApiKeyResponse {
    key: string; // Only returned on creation
}

/**
 * Generate secure API key
 */
function generateApiKey(): { key: string; hash: string; prefix: string } {
    const key = `confuse_${crypto.randomBytes(24).toString('base64url')}`;
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    const prefix = key.slice(0, 16);

    return { key, hash, prefix };
}

/**
 * Hash an API key for lookup
 */
export function hashApiKey(key: string): string {
    return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * Create a new API key
 */
export async function createApiKey(input: CreateApiKeyInput): Promise<ApiKeyWithSecret> {
    const { key, hash, prefix } = generateApiKey();

    const apiKey = await prisma.apiKey.create({
        data: {
            userId: input.userId,
            name: input.name,
            keyHash: hash,
            keyPrefix: prefix,
            scopes: input.scopes || ['read'],
            expiresAt: input.expiresAt,
            rateLimit: input.rateLimit || 1000,
        },
    });

    logger.info(`[APIKEY] Created API key ${apiKey.id} for user ${input.userId}`);

    return {
        ...toResponse(apiKey),
        key, // Return the actual key only on creation
    };
}

/**
 * Validate API key and return user info
 */
export async function validateApiKey(key: string): Promise<{
    valid: boolean;
    apiKey?: ApiKey;
    error?: string;
}> {
    const hash = hashApiKey(key);

    const apiKey = await prisma.apiKey.findUnique({
        where: { keyHash: hash },
    });

    if (!apiKey) {
        return { valid: false, error: 'Invalid API key' };
    }

    if (apiKey.revokedAt) {
        return { valid: false, error: 'API key has been revoked' };
    }

    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
        return { valid: false, error: 'API key has expired' };
    }

    // Update last used timestamp
    await prisma.apiKey.update({
        where: { id: apiKey.id },
        data: { lastUsedAt: new Date() },
    }).catch(() => { }); // Non-blocking update

    return { valid: true, apiKey };
}

/**
 * Get all API keys for a user
 */
export async function getUserApiKeys(userId: string): Promise<ApiKeyResponse[]> {
    const keys = await prisma.apiKey.findMany({
        where: {
            userId,
            revokedAt: null,
        },
        orderBy: { createdAt: 'desc' },
    });

    return keys.map(toResponse);
}

/**
 * Get API key by ID
 */
export async function getApiKeyById(keyId: string): Promise<ApiKey | null> {
    return prisma.apiKey.findUnique({
        where: { id: keyId },
    });
}

/**
 * Revoke API key
 */
export async function revokeApiKey(keyId: string): Promise<void> {
    await prisma.apiKey.update({
        where: { id: keyId },
        data: { revokedAt: new Date() },
    });

    logger.info(`[APIKEY] Revoked API key ${keyId}`);
}

/**
 * Update API key
 */
export async function updateApiKey(
    keyId: string,
    input: { name?: string; scopes?: string[]; rateLimit?: number }
): Promise<ApiKey> {
    return prisma.apiKey.update({
        where: { id: keyId },
        data: {
            name: input.name,
            scopes: input.scopes,
            rateLimit: input.rateLimit,
        },
    });
}

/**
 * Check if API key has required scope
 */
export function hasScope(apiKey: ApiKey, requiredScope: string): boolean {
    return apiKey.scopes.includes(requiredScope) || apiKey.scopes.includes('admin');
}

/**
 * Convert to response format (hides sensitive data)
 */
export function toResponse(apiKey: ApiKey): ApiKeyResponse {
    return {
        id: apiKey.id,
        name: apiKey.name,
        keyPrefix: apiKey.keyPrefix,
        scopes: apiKey.scopes,
        expiresAt: apiKey.expiresAt?.toISOString() ?? null,
        createdAt: apiKey.createdAt.toISOString(),
        lastUsedAt: apiKey.lastUsedAt?.toISOString() ?? null,
        rateLimit: apiKey.rateLimit,
    };
}
