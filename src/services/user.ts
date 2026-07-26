/**
 * ConFuse Auth Middleware - User Service
 * 
 * Handles user CRUD operations with Prisma
 */

import { User, UserProfile, CreateUserInput } from '../types/index.js';
import prisma from '../infra/db.js';

/**
 * Find or create user by Auth0 subject
 */
export async function findOrCreateByAuth0(input: CreateUserInput): Promise<User> {
    const { auth0Sub, email, name, picture } = input;

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

    // Initialize the per-user FalkorDB graph
    import('./user-graph.js').then(({ createUserGraph }) => {
        createUserGraph(user.id).catch((err) => {
            console.error('[USER] Failed to initialize FalkorDB graph asynchronously:', err);
        });
    });

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
 * Find user by email
 */
export async function findByEmail(email: string): Promise<User | null> {
    const user = await prisma.user.findUnique({
        where: { email },
    });
    return user as User | null;
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
        onboardingCompleted: user.onboardingCompleted,
        userIntent: user.userIntent,
        dashboardPreset: user.dashboardPreset,
        subscriptionTier: user.subscriptionTier || 'free',
        subscriptionStatus: user.subscriptionStatus || 'active',
    };
}


/**
 * Deletes a user account, including their FalkorDB graph and all related PostgreSQL data
 * (workspaces, preferences, api keys, sessions, accounts, etc).
 */
export async function deleteUserAccount(userId: string): Promise<void> {
    // First, delete the FalkorDB graph
    try {
        const { deleteUserGraph } = await import('./user-graph.js');
        await deleteUserGraph(userId);
    } catch (error) {
        console.error(`[USER_DELETE] Failed to delete FalkorDB graph for user ${userId}:`, error);
        // We continue with the deletion even if graph deletion fails
        // to avoid putting the account in a stuck state.
    }

    // Second, delete the user from PostgreSQL.
    // Due to the 'onDelete: Cascade' rules in schema.prisma, this will also wipe:
    // Workspaces, Preferences, Sessions, ApiKeys, Accounts, etc.
    try {
        await prisma.user.delete({
            where: { id: userId }
        });
        console.info(`[USER_DELETE] Successfully deleted user record ${userId} and cascaded data`);
    } catch (error) {
        console.error(`[USER_DELETE] Failed to delete PostgreSQL user ${userId}:`, error);
        throw new Error(`Failed to delete user account: ${error instanceof Error ? error.message : String(error)}`);
    }
}
