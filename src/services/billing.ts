/**
 * ConFuse Billing & Subscription Service
 */

import prisma from '../infra/db.js';
import { config } from '../config.js';
import { logger } from '../utils/logger.js';

export interface TierLimits {
    maxRepos: number | null; // null = unlimited
    maxDocs: number | null;  // null = unlimited
    maxStorageBytes: bigint;
    maxMonthlyRequests: number;
    maxConnectedUsers: number;
    securityLevel: 'Standard' | 'Advanced' | 'Enterprise';
    readOnlyConnectionsOnly: boolean;
}

export const TIER_CONFIGS: Record<string, TierLimits> = {
    free: {
        maxRepos: 2,
        maxDocs: 4,
        maxStorageBytes: BigInt(256 * 1024 * 1024), // 256 MB
        maxMonthlyRequests: 80_000,
        maxConnectedUsers: 0,
        securityLevel: 'Standard',
        readOnlyConnectionsOnly: true,
    },
    pro: {
        maxRepos: 5,
        maxDocs: 10,
        maxStorageBytes: BigInt(512 * 1024 * 1024), // 512 MB
        maxMonthlyRequests: 160_000,
        maxConnectedUsers: 0,
        securityLevel: 'Standard',
        readOnlyConnectionsOnly: true,
    },
    team: {
        maxRepos: 10,
        maxDocs: 16,
        maxStorageBytes: BigInt(1024 * 1024 * 1024), // 1024 MB (1 GB)
        maxMonthlyRequests: 320_000,
        maxConnectedUsers: 3,
        securityLevel: 'Advanced',
        readOnlyConnectionsOnly: true,
    },
    enterprise: {
        maxRepos: null,
        maxDocs: null,
        maxStorageBytes: BigInt(5 * 1024 * 1024 * 1024), // 5 GB+ default
        maxMonthlyRequests: 1_000_000,
        maxConnectedUsers: 99999,
        securityLevel: 'Enterprise',
        readOnlyConnectionsOnly: false,
    },
};

/**
 * Fetch current user subscription state and quota usage
 */
export async function getUserSubscriptionDetails(userId: string) {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
            id: true,
            email: true,
            name: true,
            subscriptionTier: true,
            subscriptionStatus: true,
            subscriptionEndsAt: true,
            monthlyRequestCount: true,
            monthlyRequestResetAt: true,
            storageUsedBytes: true,
        },
    });

    if (!user) throw new Error('User not found');

    const tier = user.subscriptionTier || 'free';
    const tierConfig = TIER_CONFIGS[tier] || TIER_CONFIGS.free;

    // Count repositories owned by user
    const repoCount = await prisma.repositories.count({
        where: { user_id: userId },
    });

    // Count documents / sources owned by user
    const docCount = await prisma.sources.count({
        where: { user_id: userId },
    });

    // Count connected database users (for Team Tier)
    const connectedUsersCount = await prisma.databaseConnection.count({
        where: { ownerId: userId },
    });

    return {
        user: {
            id: user.id,
            email: user.email,
            name: user.name,
        },
        subscription: {
            tier,
            status: user.subscriptionStatus || 'active',
            endsAt: user.subscriptionEndsAt,
        },
        limits: {
            maxRepos: tierConfig.maxRepos,
            maxDocs: tierConfig.maxDocs,
            maxStorageBytes: tierConfig.maxStorageBytes.toString(),
            maxStorageMb: Number(tierConfig.maxStorageBytes / BigInt(1024 * 1024)),
            maxMonthlyRequests: tierConfig.maxMonthlyRequests,
            maxConnectedUsers: tierConfig.maxConnectedUsers,
            securityLevel: tierConfig.securityLevel,
            readOnlyConnectionsOnly: tierConfig.readOnlyConnectionsOnly,
        },
        usage: {
            repoCount,
            docCount,
            storageUsedBytes: user.storageUsedBytes.toString(),
            storageUsedMb: Number(user.storageUsedBytes / BigInt(1024 * 1024)),
            monthlyRequestCount: user.monthlyRequestCount,
            connectedUsersCount,
        },
    };
}

/**
 * Create a Checkout Session
 */
export async function createCheckoutSession(userId: string, targetTier: string): Promise<{ checkoutUrl: string }> {
    return { checkoutUrl: '/billing' };
}

/**
 * Get Customer Portal URL
 */
export async function getCustomerPortalUrl(userId: string): Promise<{ portalUrl: string }> {
    return { portalUrl: '/billing' };
}

/**
 * Storage Limit Check (Processing stops when max size reached)
 */
export async function checkStorageLimit(userId: string, additionalBytes: number = 0): Promise<{ allowed: boolean; currentBytes: bigint; maxBytes: bigint }> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { subscriptionTier: true, storageUsedBytes: true },
    });

    const tier = user?.subscriptionTier || 'free';
    const tierConfig = TIER_CONFIGS[tier] || TIER_CONFIGS.free;
    const currentBytes = user?.storageUsedBytes || BigInt(0);
    const newTotalBytes = currentBytes + BigInt(additionalBytes);

    const allowed = newTotalBytes <= tierConfig.maxStorageBytes;
    return {
        allowed,
        currentBytes,
        maxBytes: tierConfig.maxStorageBytes,
    };
}

/**
 * Repository Count Limit Check
 */
export async function checkRepoLimit(userId: string): Promise<{ allowed: boolean; currentCount: number; maxRepos: number | null }> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { subscriptionTier: true },
    });

    const tier = user?.subscriptionTier || 'free';
    const tierConfig = TIER_CONFIGS[tier] || TIER_CONFIGS.free;

    if (tierConfig.maxRepos === null) {
        return { allowed: true, currentCount: 0, maxRepos: null };
    }

    const currentCount = await prisma.repositories.count({
        where: { user_id: userId },
    });

    return {
        allowed: currentCount < tierConfig.maxRepos,
        currentCount,
        maxRepos: tierConfig.maxRepos,
    };
}

/**
 * Document Count Limit Check
 */
export async function checkDocLimit(userId: string): Promise<{ allowed: boolean; currentCount: number; maxDocs: number | null }> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { subscriptionTier: true },
    });

    const tier = user?.subscriptionTier || 'free';
    const tierConfig = TIER_CONFIGS[tier] || TIER_CONFIGS.free;

    if (tierConfig.maxDocs === null) {
        return { allowed: true, currentCount: 0, maxDocs: null };
    }

    const currentCount = await prisma.sources.count({
        where: { user_id: userId },
    });

    return {
        allowed: currentCount < tierConfig.maxDocs,
        currentCount,
        maxDocs: tierConfig.maxDocs,
    };
}

/**
 * Team Database User Connection Check (Max 3 users for Team tier, Read-Only ONLY)
 */
export async function connectTeamUserToDatabase(ownerUserId: string, targetUserId: string): Promise<{ success: boolean; message: string }> {
    const owner = await prisma.user.findUnique({
        where: { id: ownerUserId },
        select: { subscriptionTier: true },
    });

    const tier = owner?.subscriptionTier || 'free';
    const tierConfig = TIER_CONFIGS[tier] || TIER_CONFIGS.free;

    if (tierConfig.maxConnectedUsers <= 0) {
        return { success: false, message: 'Your subscription tier does not support multi-user database connections. Please upgrade to Team or Enterprise tier.' };
    }

    const currentConnectedCount = await prisma.databaseConnection.count({
        where: { ownerId: ownerUserId },
    });

    if (currentConnectedCount >= tierConfig.maxConnectedUsers) {
        return { success: false, message: `Maximum connected database users limit reached (${tierConfig.maxConnectedUsers} users max).` };
    }

    // Connect user with strictly READ_ONLY permission
    await prisma.databaseConnection.upsert({
        where: {
            ownerId_connectedUserId: {
                ownerId: ownerUserId,
                connectedUserId: targetUserId,
            },
        },
        create: {
            ownerId: ownerUserId,
            connectedUserId: targetUserId,
            permission: 'READ_ONLY',
        },
        update: {
            permission: 'READ_ONLY',
        },
    });

    return { success: true, message: 'User successfully connected to database in READ_ONLY mode.' };
}
