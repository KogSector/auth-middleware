/**
 * ConFuse Auth Middleware - Workspace Service
 * 
 * Manages workspaces for multi-tenant data isolation.
 * Each user can have multiple workspaces, and workspaces can have multiple members.
 */

import { Workspace, WorkspaceMember } from '@prisma/client';
import { logger } from '../utils/logger.js';
import prisma from '../db/client.js';

// Types
export interface CreateWorkspaceInput {
    name: string;
    description?: string;
    ownerId: string;
}

export interface UpdateWorkspaceInput {
    name?: string;
    description?: string;
    settings?: Record<string, unknown>;
}

export interface WorkspaceWithMembers extends Workspace {
    members: (WorkspaceMember & { user: { id: string; email: string; name: string | null } })[];
}

/**
 * Generate URL-safe slug from name
 */
function generateSlug(name: string, suffix?: string): string {
    let slug = name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');

    if (suffix) {
        slug = `${slug}-${suffix}`;
    }

    return slug;
}

/**
 * Create a new workspace
 */
export async function createWorkspace(input: CreateWorkspaceInput): Promise<Workspace> {
    const { name, description, ownerId } = input;

    // Generate unique slug
    let slug = generateSlug(name);
    let attempts = 0;

    while (attempts < 5) {
        const existing = await prisma.workspace.findUnique({ where: { slug } });
        if (!existing) break;

        slug = generateSlug(name, Date.now().toString(36));
        attempts++;
    }

    // Create workspace and add owner as member
    const workspace = await prisma.workspace.create({
        data: {
            name,
            slug,
            description,
            ownerId,
            members: {
                create: {
                    userId: ownerId,
                    role: 'owner',
                },
            },
        },
    });

    logger.info(`[WORKSPACE] Created workspace: ${workspace.id} (${workspace.slug}) for user ${ownerId}`);
    return workspace;
}

/**
 * Create default workspace for new user
 */
export async function createDefaultWorkspace(userId: string, userName?: string): Promise<Workspace> {
    const workspaceName = userName ? `${userName}'s Workspace` : 'My Workspace';

    const workspace = await prisma.workspace.create({
        data: {
            name: workspaceName,
            slug: generateSlug(`user-${userId.slice(0, 8)}-${Date.now().toString(36)}`),
            ownerId: userId,
            isDefault: true,
            members: {
                create: {
                    userId,
                    role: 'owner',
                },
            },
        },
    });

    logger.info(`[WORKSPACE] Created default workspace: ${workspace.id} for user ${userId}`);
    return workspace;
}

/**
 * Get workspace by ID
 */
export async function getWorkspaceById(workspaceId: string): Promise<Workspace | null> {
    return prisma.workspace.findUnique({
        where: { id: workspaceId },
    });
}

/**
 * Get workspace by slug
 */
export async function getWorkspaceBySlug(slug: string): Promise<Workspace | null> {
    return prisma.workspace.findUnique({
        where: { slug },
    });
}

/**
 * Get workspace with members
 */
export async function getWorkspaceWithMembers(workspaceId: string): Promise<WorkspaceWithMembers | null> {
    return prisma.workspace.findUnique({
        where: { id: workspaceId },
        include: {
            members: {
                include: {
                    user: {
                        select: { id: true, email: true, name: true },
                    },
                },
            },
        },
    }) as Promise<WorkspaceWithMembers | null>;
}

/**
 * Get all workspaces for a user (owned or member of)
 */
export async function getUserWorkspaces(userId: string): Promise<Workspace[]> {
    const memberships = await prisma.workspaceMember.findMany({
        where: { userId },
        include: { workspace: true },
    });

    return memberships.map(m => m.workspace);
}

/**
 * Get user's default workspace
 */
export async function getUserDefaultWorkspace(userId: string): Promise<Workspace | null> {
    // First check user preferences
    const preference = await prisma.userPreference.findUnique({
        where: { userId },
    });

    if (preference?.defaultWorkspaceId) {
        const workspace = await prisma.workspace.findUnique({
            where: { id: preference.defaultWorkspaceId },
        });
        if (workspace) return workspace;
    }

    // Fallback to default workspace
    const defaultWorkspace = await prisma.workspace.findFirst({
        where: {
            ownerId: userId,
            isDefault: true,
        },
    });

    if (defaultWorkspace) return defaultWorkspace;

    // Fallback to first owned workspace
    return prisma.workspace.findFirst({
        where: { ownerId: userId },
        orderBy: { createdAt: 'asc' },
    });
}

/**
 * Update workspace
 */
export async function updateWorkspace(
    workspaceId: string,
    input: UpdateWorkspaceInput
): Promise<Workspace> {
    return prisma.workspace.update({
        where: { id: workspaceId },
        data: {
            name: input.name,
            description: input.description,
            settings: input.settings as any,
        },
    });
}

/**
 * Delete workspace (soft delete by archiving)
 */
export async function deleteWorkspace(workspaceId: string): Promise<void> {
    // For now, hard delete (can change to soft delete later)
    await prisma.workspace.delete({
        where: { id: workspaceId },
    });

    logger.info(`[WORKSPACE] Deleted workspace: ${workspaceId}`);
}

/**
 * Add member to workspace
 */
export async function addWorkspaceMember(
    workspaceId: string,
    userId: string,
    role: 'admin' | 'member' | 'viewer' = 'member'
): Promise<WorkspaceMember> {
    const member = await prisma.workspaceMember.create({
        data: {
            workspaceId,
            userId,
            role,
        },
    });

    logger.info(`[WORKSPACE] Added member ${userId} to workspace ${workspaceId} with role ${role}`);
    return member;
}

/**
 * Remove member from workspace
 */
export async function removeWorkspaceMember(
    workspaceId: string,
    userId: string
): Promise<void> {
    await prisma.workspaceMember.delete({
        where: {
            workspaceId_userId: { workspaceId, userId },
        },
    });

    logger.info(`[WORKSPACE] Removed member ${userId} from workspace ${workspaceId}`);
}

/**
 * Update member role
 */
export async function updateMemberRole(
    workspaceId: string,
    userId: string,
    role: 'admin' | 'member' | 'viewer'
): Promise<WorkspaceMember> {
    return prisma.workspaceMember.update({
        where: {
            workspaceId_userId: { workspaceId, userId },
        },
        data: { role },
    });
}

/**
 * Check if user has access to workspace
 */
export async function hasWorkspaceAccess(
    workspaceId: string,
    userId: string
): Promise<boolean> {
    const member = await prisma.workspaceMember.findUnique({
        where: {
            workspaceId_userId: { workspaceId, userId },
        },
    });

    return member !== null;
}

/**
 * Check if user has specific role in workspace
 */
export async function hasWorkspaceRole(
    workspaceId: string,
    userId: string,
    requiredRoles: string[]
): Promise<boolean> {
    const member = await prisma.workspaceMember.findUnique({
        where: {
            workspaceId_userId: { workspaceId, userId },
        },
    });

    return member !== null && requiredRoles.includes(member.role);
}
