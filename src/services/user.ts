/**
 * ConFuse Auth Middleware - User Service
 * 
 * Handles user CRUD operations with Prisma
 */

import { PrismaClient } from '@prisma/client';
import type { User, UserProfile, CreateUserInput } from '../types/index.js';

export const prisma = new PrismaClient();

/**
 * Find or create user by Auth0 subject
 */
export async function findOrCreateByAuth0(input: CreateUserInput): Promise<User> {
    const { auth0Sub, email, name, picture, roles } = input;

    // Try to find existing user by auth0Sub
    let user = await prisma.user.findUnique({
        where: { auth0Sub },
    });

    if (user) {
        // Update user info if changed
        user = await prisma.user.update({
            where: { id: user.id },
            data: {
                email: email || user.email,
                name: name ?? user.name,
                picture: picture ?? user.picture,
                lastLoginAt: new Date(),
            },
        });
        return user as User;
    }

    // Check if email already exists (different auth0 sub)
    const existingByEmail = await prisma.user.findUnique({
        where: { email },
    });

    if (existingByEmail) {
        // Link auth0Sub to existing user
        user = await prisma.user.update({
            where: { id: existingByEmail.id },
            data: {
                auth0Sub,
                name: name ?? existingByEmail.name,
                picture: picture ?? existingByEmail.picture,
                lastLoginAt: new Date(),
            },
        });
        return user as User;
    }

    // Create new user
    user = await prisma.user.create({
        data: {
            auth0Sub,
            email,
            name,
            picture,
            lastLoginAt: new Date(),
        },
    });

    // Publish USER_CREATED event
    try {
        const { kafkaClient } = await import('./kafka.js');
        await kafkaClient.publishAuthEvent({
            userId: user.id,
            eventType: 'USER_CREATED',
            metadata: {
                email: user.email,
                name: user.name,
                roles: user.roles.join(','),
                provider: 'auth0'
            }
        });
    } catch (error) {
        console.error('[USER] Failed to publish USER_CREATED event:', error);
    }

    // Create default workspace for new user
    try {
        const workspaceName = name ? `${name}'s Workspace` : 'My Workspace';
        await prisma.workspace.create({
            data: {
                name: workspaceName,
                slug: `user-${user.id.slice(0, 8)}-${Date.now().toString(36)}`,
                ownerId: user.id,
                isDefault: true,
                members: {
                    create: {
                        userId: user.id,
                        role: 'owner',
                    },
                },
            },
        });

        // Create default preferences
        await prisma.userPreference.create({
            data: {
                userId: user.id,
            },
        });
    } catch (error) {
        console.warn('[USER] Failed to create default workspace/preferences:', error);
    }

    return user as User;
}

/**
 * Find user by ID
 */
export async function findById(id: string): Promise<User | null> {
    const user = await prisma.user.findUnique({
        where: { id },
    });
    return user as User | null;
}

/**
 * Find user by auth0Sub
 */
export async function findByAuth0Sub(auth0Sub: string): Promise<User | null> {
    const user = await prisma.user.findUnique({
        where: { auth0Sub },
    });
    return user as User | null;
}

/**
 * Update last login timestamp
 */
export async function updateLastLogin(userId: string): Promise<void> {
    await prisma.user.update({
        where: { id: userId },
        data: { lastLoginAt: new Date() },
    });
}

/**
 * Get user profile (safe for client)
 */
export function toProfile(user: User): UserProfile {
    return {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        roles: user.roles,
        createdAt: user.createdAt.toISOString(),
    };
}
