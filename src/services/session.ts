/**
 * ConFuse Auth Middleware - Concurrent Session Management
 *
 * Tracks active sessions per user with device_info, active status,
 * and enforces max-concurrent-session policies.
 */

import prisma from '../db/client.js';
import { logger } from '../utils/logger.js';

// ── Types ──

export interface DeviceInfo {
    userAgent: string;
    platform?: string;
    browser?: string;
    os?: string;
    deviceType?: 'desktop' | 'mobile' | 'tablet' | 'unknown';
}

export interface SessionInfo {
    id: string;
    userId: string;
    deviceInfo: DeviceInfo | null;
    ipAddress: string | null;
    isActive: boolean;
    lastActiveAt: Date | null;
    createdAt: Date;
    expiresAt: Date;
    current?: boolean;
}

export interface CreateSessionInput {
    userId: string;
    refreshToken: string;
    expiresAt: Date;
    userAgent?: string | null;
    ipAddress?: string | null;
    deviceInfo?: DeviceInfo | null;
}

// ── Configuration ──

const MAX_CONCURRENT_SESSIONS = parseInt(process.env.MAX_CONCURRENT_SESSIONS || '5', 10);

// ── Service ──

/**
 * Parse user-agent string into structured DeviceInfo
 */
export function parseDeviceInfo(userAgent?: string | null): DeviceInfo | null {
    if (!userAgent) return null;

    let platform = 'unknown';
    let browser = 'unknown';
    let os = 'unknown';
    let deviceType: DeviceInfo['deviceType'] = 'unknown';

    // OS detection
    if (/windows/i.test(userAgent)) { os = 'Windows'; platform = 'windows'; }
    else if (/macintosh|mac os/i.test(userAgent)) { os = 'macOS'; platform = 'macos'; }
    else if (/linux/i.test(userAgent)) { os = 'Linux'; platform = 'linux'; }
    else if (/android/i.test(userAgent)) { os = 'Android'; platform = 'android'; }
    else if (/iphone|ipad|ipod/i.test(userAgent)) { os = 'iOS'; platform = 'ios'; }

    // Browser detection
    if (/edg\//i.test(userAgent)) browser = 'Edge';
    else if (/chrome|crios/i.test(userAgent)) browser = 'Chrome';
    else if (/firefox|fxios/i.test(userAgent)) browser = 'Firefox';
    else if (/safari/i.test(userAgent) && !/chrome/i.test(userAgent)) browser = 'Safari';

    // Device type
    if (/mobile|android|iphone/i.test(userAgent)) deviceType = 'mobile';
    else if (/ipad|tablet/i.test(userAgent)) deviceType = 'tablet';
    else deviceType = 'desktop';

    return { userAgent, platform, browser, os, deviceType };
}

/**
 * Create a new session, enforcing the concurrent session limit.
 * If the limit is reached, the oldest active session is revoked.
 */
export async function createSession(input: CreateSessionInput): Promise<string> {
    const { userId, refreshToken, expiresAt, userAgent, ipAddress, deviceInfo } = input;

    // Count active sessions for the user
    const activeSessions = await prisma.session.findMany({
        where: {
            userId,
            isActive: true,
            revokedAt: null,
            expiresAt: { gt: new Date() },
        },
        orderBy: { createdAt: 'asc' },
    });

    // If at the limit, revoke oldest session(s)
    if (activeSessions.length >= MAX_CONCURRENT_SESSIONS) {
        const sessionsToRevoke = activeSessions.slice(0, activeSessions.length - MAX_CONCURRENT_SESSIONS + 1);
        for (const old of sessionsToRevoke) {
            await prisma.session.update({
                where: { id: old.id },
                data: { revokedAt: new Date(), isActive: false },
            });
            logger.info(`[SESSION] Revoked oldest session ${old.id} for user ${userId} (limit: ${MAX_CONCURRENT_SESSIONS})`);
        }
    }

    const session = await prisma.session.create({
        data: {
            userId,
            refreshToken,
            expiresAt,
            userAgent: userAgent || null,
            ipAddress: ipAddress || null,
            deviceInfo: deviceInfo ? (deviceInfo as any) : null,
            isActive: true,
            lastActiveAt: new Date(),
        },
    });

    logger.info(`[SESSION] Created session ${session.id} for user ${userId}`);
    return session.id;
}

/**
 * Touch session — update lastActiveAt timestamp
 */
export async function touchSession(sessionId: string): Promise<void> {
    await prisma.session.updateMany({
        where: { id: sessionId, isActive: true, revokedAt: null },
        data: { lastActiveAt: new Date() },
    });
}

/**
 * List all active sessions for a user
 */
export async function listUserSessions(userId: string, currentSessionId?: string): Promise<SessionInfo[]> {
    const sessions = await prisma.session.findMany({
        where: {
            userId,
            isActive: true,
            revokedAt: null,
            expiresAt: { gt: new Date() },
        },
        orderBy: { lastActiveAt: 'desc' },
    });

    return sessions.map(s => ({
        id: s.id,
        userId: s.userId,
        deviceInfo: s.deviceInfo as DeviceInfo | null,
        ipAddress: s.ipAddress,
        isActive: s.isActive,
        lastActiveAt: s.lastActiveAt,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        current: s.id === currentSessionId,
    }));
}

/**
 * Revoke a specific session
 */
export async function revokeSession(sessionId: string, userId: string): Promise<boolean> {
    const result = await prisma.session.updateMany({
        where: { id: sessionId, userId },
        data: { revokedAt: new Date(), isActive: false },
    });
    if (result.count > 0) {
        logger.info(`[SESSION] Revoked session ${sessionId} for user ${userId}`);
    }
    return result.count > 0;
}

/**
 * Revoke all sessions for a user except the current one
 */
export async function revokeAllOtherSessions(userId: string, currentSessionId: string): Promise<number> {
    const result = await prisma.session.updateMany({
        where: {
            userId,
            isActive: true,
            revokedAt: null,
            id: { not: currentSessionId },
        },
        data: { revokedAt: new Date(), isActive: false },
    });
    logger.info(`[SESSION] Revoked ${result.count} other sessions for user ${userId}`);
    return result.count;
}

/**
 * Validate that a session is still active
 */
export async function validateSession(sessionId: string): Promise<boolean> {
    const session = await prisma.session.findFirst({
        where: {
            id: sessionId,
            isActive: true,
            revokedAt: null,
            expiresAt: { gt: new Date() },
        },
    });
    return !!session;
}

/**
 * Cleanup expired sessions (run periodically)
 */
export async function cleanupExpiredSessions(): Promise<number> {
    const result = await prisma.session.updateMany({
        where: {
            isActive: true,
            expiresAt: { lt: new Date() },
        },
        data: { isActive: false },
    });
    if (result.count > 0) {
        logger.info(`[SESSION] Cleaned up ${result.count} expired sessions`);
    }
    return result.count;
}
