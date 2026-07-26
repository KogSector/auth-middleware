/**
 * ConFuse Billing & Subscription Service (LemonSqueezy Integration)
 */

import crypto from 'crypto';
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

export const VARIANT_TO_TIER_MAP: Record<string, string> = {
    '1950940': 'pro',
    '1950955': 'team',
    '1950957': 'enterprise',
};

export const TIER_TO_VARIANT_MAP: Record<string, string> = {
    pro: '1950940',
    team: '1950955',
    enterprise: '1950957',
};

export const BUY_URL_MAP: Record<string, string> = {
    pro: 'https://tryconfuse.lemonsqueezy.com/checkout/buy/dc2fe0c0-8fc8-4b14-8bc8-42b1b93d6610',
    team: 'https://tryconfuse.lemonsqueezy.com/checkout/buy/fc9e1c35-1284-4e66-90c5-b8fd06e24fb5',
    enterprise: 'https://tryconfuse.lemonsqueezy.com/checkout/buy/85924e78-5dae-40b2-bc55-9d7dac547e1d',
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
            lemonSqueezyCustomerId: true,
            lemonSqueezySubscriptionId: true,
            lemonSqueezyVariantId: true,
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
            customerId: user.lemonSqueezyCustomerId,
            subscriptionId: user.lemonSqueezySubscriptionId,
            variantId: user.lemonSqueezyVariantId,
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
 * Create a LemonSqueezy Checkout Session
 */
export async function createCheckoutSession(userId: string, targetTier: string): Promise<{ checkoutUrl: string }> {
    const variantId = TIER_TO_VARIANT_MAP[targetTier];
    if (!variantId) {
        throw new Error(`Invalid subscription tier: ${targetTier}`);
    }

    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { email: true, name: true },
    });

    if (!user) throw new Error('User not found');

    const apiKey = config.lemonSqueezy.apiKey;
    const storeId = config.lemonSqueezy.storeId;

    try {
        const response = await fetch('https://api.lemonsqueezy.com/v1/checkouts', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/vnd.api+json',
                'Accept': 'application/vnd.api+json',
            },
            body: JSON.stringify({
                data: {
                    type: 'checkouts',
                    attributes: {
                        checkout_data: {
                            email: user.email,
                            name: user.name || undefined,
                            custom: {
                                user_id: userId,
                                tier: targetTier,
                            },
                        },
                    },
                    relationships: {
                        store: {
                            data: {
                                type: 'stores',
                                id: storeId,
                            },
                        },
                        variant: {
                            data: {
                                type: 'variants',
                                id: variantId,
                            },
                        },
                    },
                },
            }),
        });

        if (!response.ok) {
            const errText = await response.text();
            logger.warn(`[LEMONSQUEEZY] API checkout failed (${response.status}): ${errText}. Falling back to buy URL.`);
            const fallbackUrl = BUY_URL_MAP[targetTier];
            return { checkoutUrl: `${fallbackUrl}?checkout[custom][user_id]=${userId}` };
        }

        const data = await response.json();
        const checkoutUrl = data?.data?.attributes?.url;
        if (!checkoutUrl) {
            const fallbackUrl = BUY_URL_MAP[targetTier];
            return { checkoutUrl: `${fallbackUrl}?checkout[custom][user_id]=${userId}` };
        }

        return { checkoutUrl };
    } catch (err) {
        logger.error('[LEMONSQUEEZY] Error creating checkout session:', err);
        const fallbackUrl = BUY_URL_MAP[targetTier];
        return { checkoutUrl: `${fallbackUrl}?checkout[custom][user_id]=${userId}` };
    }
}

/**
 * Get Customer Portal URL or fallback portal
 */
export async function getCustomerPortalUrl(userId: string): Promise<{ portalUrl: string }> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { lemonSqueezyCustomerId: true },
    });

    if (user?.lemonSqueezyCustomerId) {
        try {
            const response = await fetch(`https://api.lemonsqueezy.com/v1/customers/${user.lemonSqueezyCustomerId}`, {
                headers: {
                    'Authorization': `Bearer ${config.lemonSqueezy.apiKey}`,
                    'Accept': 'application/vnd.api+json',
                },
            });
            if (response.ok) {
                const data = await response.json();
                const portalUrl = data?.data?.attributes?.urls?.customer_portal;
                if (portalUrl) return { portalUrl };
            }
        } catch (err) {
            logger.warn('[LEMONSQUEEZY] Failed to fetch customer portal:', err);
        }
    }

    return { portalUrl: 'https://tryconfuse.lemonsqueezy.com/billing' };
}

/**
 * Verify Webhook Signature HMAC SHA-256
 */
export function verifyWebhookSignature(rawBody: string | Buffer, signatureHeader: string): boolean {
    const secret = config.lemonSqueezy.webhookSecret;
    if (!secret || !signatureHeader) return false;

    const hmac = crypto.createHmac('sha256', secret);
    const digest = Buffer.from(hmac.update(rawBody).digest('hex'), 'utf8');
    const signature = Buffer.from(signatureHeader, 'utf8');

    if (digest.length !== signature.length) return false;
    return crypto.timingSafeEqual(digest, signature);
}

/**
 * Process LemonSqueezy Webhook Payload
 */
export async function processLemonSqueezyWebhook(payload: any): Promise<void> {
    const eventName = payload?.meta?.event_name;
    const customData = payload?.meta?.custom_data;
    const attributes = payload?.data?.attributes;

    logger.info(`[LEMONSQUEEZY-WEBHOOK] Received event: ${eventName}`, { customData });

    const userId = customData?.user_id;
    const customerId = attributes?.customer_id ? String(attributes.customer_id) : null;
    const subscriptionId = payload?.data?.id ? String(payload.data.id) : null;
    const variantId = attributes?.variant_id ? String(attributes.variant_id) : null;
    const status = attributes?.status || 'active';
    const endsAt = attributes?.ends_at ? new Date(attributes.ends_at) : null;

    // Determine target tier from variant ID or custom data
    let targetTier = customData?.tier;
    if (!targetTier && variantId && VARIANT_TO_TIER_MAP[variantId]) {
        targetTier = VARIANT_TO_TIER_MAP[variantId];
    }

    if (eventName === 'subscription_created' || eventName === 'subscription_updated' || eventName === 'subscription_resumed') {
        const finalTier = targetTier || 'pro';
        if (userId) {
            await prisma.user.update({
                where: { id: userId },
                data: {
                    subscriptionTier: finalTier,
                    subscriptionStatus: status,
                    subscriptionEndsAt: endsAt,
                    lemonSqueezyCustomerId: customerId,
                    lemonSqueezySubscriptionId: subscriptionId,
                    lemonSqueezyVariantId: variantId,
                },
            });
            logger.info(`[LEMONSQUEEZY-WEBHOOK] Updated user ${userId} to tier ${finalTier}`);
        } else if (customerId) {
            // Find by customerId
            await prisma.user.updateMany({
                where: { lemonSqueezyCustomerId: customerId },
                data: {
                    subscriptionTier: finalTier,
                    subscriptionStatus: status,
                    subscriptionEndsAt: endsAt,
                    lemonSqueezySubscriptionId: subscriptionId,
                    lemonSqueezyVariantId: variantId,
                },
            });
        }
    } else if (eventName === 'subscription_cancelled' || eventName === 'subscription_expired') {
        const newStatus = eventName === 'subscription_cancelled' ? 'cancelled' : 'expired';
        const fallbackTier = eventName === 'subscription_expired' ? 'free' : undefined;

        if (userId) {
            await prisma.user.update({
                where: { id: userId },
                data: {
                    subscriptionStatus: newStatus,
                    subscriptionEndsAt: endsAt,
                    ...(fallbackTier ? { subscriptionTier: fallbackTier } : {}),
                },
            });
        } else if (customerId) {
            await prisma.user.updateMany({
                where: { lemonSqueezyCustomerId: customerId },
                data: {
                    subscriptionStatus: newStatus,
                    subscriptionEndsAt: endsAt,
                    ...(fallbackTier ? { subscriptionTier: fallbackTier } : {}),
                },
            });
        }
    }
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
