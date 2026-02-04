/**
 * ConFuse Auth Middleware - User Preferences Service
 * 
 * Manages user preferences and settings with defaults.
 */

import { PrismaClient, UserPreference } from '@prisma/client';
import { logger } from '../utils/logger.js';

const prisma = new PrismaClient();

// Default preferences template
export const DEFAULT_PREFERENCES = {
    theme: 'system',
    language: 'en',
    timezone: 'UTC',
    defaultModel: 'gpt-4',
    embeddingModel: 'all-MiniLM-L6-v2',
    enableNotifications: true,
    emailDigest: 'weekly',
    customSettings: {},
};

// Types
export interface UpdatePreferencesInput {
    theme?: 'light' | 'dark' | 'system';
    language?: string;
    timezone?: string;
    defaultModel?: string;
    embeddingModel?: string;
    enableNotifications?: boolean;
    emailDigest?: 'daily' | 'weekly' | 'never';
    defaultWorkspaceId?: string;
    customSettings?: Record<string, unknown>;
}

export interface PreferencesResponse {
    id: string;
    userId: string;
    theme: string;
    language: string;
    timezone: string;
    defaultModel: string;
    embeddingModel: string;
    enableNotifications: boolean;
    emailDigest: string;
    defaultWorkspaceId: string | null;
    customSettings: Record<string, unknown>;
}

/**
 * Get user preferences (create with defaults if not exists)
 */
export async function getOrCreatePreferences(userId: string): Promise<UserPreference> {
    let preferences = await prisma.userPreference.findUnique({
        where: { userId },
    });

    if (!preferences) {
        preferences = await prisma.userPreference.create({
            data: {
                userId,
                ...DEFAULT_PREFERENCES,
            },
        });

        logger.info(`[PREFERENCES] Created default preferences for user ${userId}`);
    }

    return preferences;
}

/**
 * Get user preferences (returns null if not exists)
 */
export async function getPreferences(userId: string): Promise<UserPreference | null> {
    return prisma.userPreference.findUnique({
        where: { userId },
    });
}

/**
 * Update user preferences
 */
export async function updatePreferences(
    userId: string,
    input: UpdatePreferencesInput
): Promise<UserPreference> {
    // Ensure preferences exist
    await getOrCreatePreferences(userId);

    const updateData: any = {};

    if (input.theme !== undefined) updateData.theme = input.theme;
    if (input.language !== undefined) updateData.language = input.language;
    if (input.timezone !== undefined) updateData.timezone = input.timezone;
    if (input.defaultModel !== undefined) updateData.defaultModel = input.defaultModel;
    if (input.embeddingModel !== undefined) updateData.embeddingModel = input.embeddingModel;
    if (input.enableNotifications !== undefined) updateData.enableNotifications = input.enableNotifications;
    if (input.emailDigest !== undefined) updateData.emailDigest = input.emailDigest;
    if (input.defaultWorkspaceId !== undefined) updateData.defaultWorkspaceId = input.defaultWorkspaceId;
    if (input.customSettings !== undefined) updateData.customSettings = input.customSettings;

    const preferences = await prisma.userPreference.update({
        where: { userId },
        data: updateData,
    });

    logger.info(`[PREFERENCES] Updated preferences for user ${userId}`);
    return preferences;
}

/**
 * Set default workspace
 */
export async function setDefaultWorkspace(
    userId: string,
    workspaceId: string
): Promise<UserPreference> {
    return updatePreferences(userId, { defaultWorkspaceId: workspaceId });
}

/**
 * Reset preferences to defaults
 */
export async function resetPreferences(userId: string): Promise<UserPreference> {
    const preferences = await prisma.userPreference.update({
        where: { userId },
        data: {
            ...DEFAULT_PREFERENCES,
            defaultWorkspaceId: null,
        },
    });

    logger.info(`[PREFERENCES] Reset preferences to defaults for user ${userId}`);
    return preferences;
}

/**
 * Delete user preferences (cascade from user delete)
 */
export async function deletePreferences(userId: string): Promise<void> {
    await prisma.userPreference.deleteMany({
        where: { userId },
    });
}

/**
 * Get custom setting value
 */
export async function getCustomSetting(
    userId: string,
    key: string
): Promise<unknown> {
    const preferences = await getPreferences(userId);
    if (!preferences?.customSettings) return undefined;

    const settings = preferences.customSettings as Record<string, unknown>;
    return settings[key];
}

/**
 * Set custom setting value
 */
export async function setCustomSetting(
    userId: string,
    key: string,
    value: unknown
): Promise<void> {
    const preferences = await getOrCreatePreferences(userId);
    const settings = (preferences.customSettings as Record<string, unknown>) || {};

    settings[key] = value;

    await prisma.userPreference.update({
        where: { userId },
        data: { customSettings: settings },
    });
}

/**
 * Convert to response format
 */
export function toResponse(preferences: UserPreference): PreferencesResponse {
    return {
        id: preferences.id,
        userId: preferences.userId,
        theme: preferences.theme,
        language: preferences.language,
        timezone: preferences.timezone,
        defaultModel: preferences.defaultModel,
        embeddingModel: preferences.embeddingModel,
        enableNotifications: preferences.enableNotifications,
        emailDigest: preferences.emailDigest,
        defaultWorkspaceId: preferences.defaultWorkspaceId,
        customSettings: (preferences.customSettings as Record<string, unknown>) || {},
    };
}
