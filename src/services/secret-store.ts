/**
 * ConFuse Auth Middleware - Encrypted Secret Store
 *
 * Stores customer secrets (FalkorDB passwords, CA certificates, client
 * certificates and client private keys) AES-256-GCM encrypted. The raw value
 * NEVER touches the normal application database — only ciphertext, IV and
 * auth tag are persisted.
 *
 * Master key: SECRETS_ENCRYPTION_KEY (base64 or hex, 32 bytes). In
 * non-production environments an ephemeral development key is derived when the
 * variable is missing (with a loud warning) so local development works out of
 * the box. Production refuses to store secrets without a real key.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'crypto';
import prisma from '../infra/db.js';
import { logger } from '../utils/logger.js';
import { redactSensitive } from '../utils/redact.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const CURRENT_KEY_VERSION = 1;

let devKeyWarningLogged = false;

export interface EncryptedSecretPayload {
    algorithm: string;
    keyVersion: number;
    ciphertext: string;
    iv: string;
    authTag: string;
}

/**
 * Resolve the AES-256 master key.
 * Accepts base64 or hex encodings of exactly 32 bytes.
 */
function getMasterKey(): Buffer {
    const raw = process.env.SECRETS_ENCRYPTION_KEY;
    if (raw && raw.trim() !== '') {
        const value = raw.trim();
        let key: Buffer | null = null;
        if (/^[0-9a-fA-F]{64}$/.test(value)) {
            key = Buffer.from(value, 'hex');
        } else {
            const decoded = Buffer.from(value, 'base64');
            if (decoded.length === 32) key = decoded;
        }
        if (!key) {
            throw new Error(
                'SECRETS_ENCRYPTION_KEY must be a 32-byte key encoded as base64 or 64-char hex'
            );
        }
        return key;
    }

    if (process.env.NODE_ENV === 'production') {
        throw new Error(
            'SECRETS_ENCRYPTION_KEY is required in production to encrypt customer secrets'
        );
    }

    if (!devKeyWarningLogged) {
        devKeyWarningLogged = true;
        logger.warn(
            '[SECRET-STORE] SECRETS_ENCRYPTION_KEY is not set — using an ephemeral development key. ' +
            'Secrets will NOT survive restarts and must not be trusted outside local development.'
        );
    }
    return createHash('sha256').update('confuse-dev-only-secret-store-key').digest();
}

/** Encrypt a raw secret value. Pure function — safe to unit test. */
export function encryptSecretValue(
    value: string,
    key: Buffer = getMasterKey()
): EncryptedSecretPayload {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, iv);
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return {
        algorithm: ALGORITHM,
        keyVersion: CURRENT_KEY_VERSION,
        ciphertext: ciphertext.toString('base64'),
        iv: iv.toString('base64'),
        authTag: cipher.getAuthTag().toString('base64'),
    };
}

/** Decrypt a stored secret payload. Pure function — safe to unit test. */
export function decryptSecretValue(
    payload: EncryptedSecretPayload,
    key: Buffer = getMasterKey()
): string {
    const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(payload.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(payload.authTag, 'base64'));
    const plaintext = Buffer.concat([
        decipher.update(Buffer.from(payload.ciphertext, 'base64')),
        decipher.final(),
    ]);
    return plaintext.toString('utf8');
}

/**
 * Store (or rotate) a secret value under a stable reference.
 * Example ref: `falkordb/<connectionId>/password`
 */
export async function putSecret(
    secretRef: string,
    ownerId: string,
    value: string,
    purpose = 'falkordb'
): Promise<void> {
    const payload = encryptSecretValue(value);
    await prisma.secret.upsert({
        where: { secretRef },
        create: {
            secretRef,
            ownerId,
            purpose,
            algorithm: payload.algorithm,
            keyVersion: payload.keyVersion,
            ciphertext: payload.ciphertext,
            iv: payload.iv,
            authTag: payload.authTag,
        },
        update: {
            ownerId,
            purpose,
            algorithm: payload.algorithm,
            keyVersion: payload.keyVersion,
            ciphertext: payload.ciphertext,
            iv: payload.iv,
            authTag: payload.authTag,
        },
    });
    logger.info('[SECRET-STORE] Secret stored', { secretRef, purpose });
}

/** Retrieve and decrypt a secret value. Returns null when absent. */
export async function getSecret(secretRef: string): Promise<string | null> {
    const row = await prisma.secret.findUnique({ where: { secretRef } });
    if (!row) return null;
    try {
        return decryptSecretValue({
            algorithm: row.algorithm,
            keyVersion: row.keyVersion,
            ciphertext: row.ciphertext,
            iv: row.iv,
            authTag: row.authTag,
        });
    } catch (error) {
        logger.error('[SECRET-STORE] Failed to decrypt secret', {
            secretRef,
            error: redactSensitive(error instanceof Error ? error.message : String(error)),
        });
        throw new Error('Stored secret could not be decrypted (key mismatch or corrupt payload)');
    }
}

/** Delete a single secret. */
export async function deleteSecret(secretRef: string): Promise<void> {
    await prisma.secret.deleteMany({ where: { secretRef } });
    logger.info('[SECRET-STORE] Secret deleted', { secretRef });
}

/** Delete every secret under a prefix (e.g. all secrets of one connection). */
export async function deleteSecretsByPrefix(prefix: string): Promise<number> {
    const result = await prisma.secret.deleteMany({
        where: { secretRef: { startsWith: prefix } },
    });
    logger.info('[SECRET-STORE] Secrets deleted by prefix', { prefix, count: result.count });
    return result.count;
}

/** Constant-time string comparison helper (for internal API key checks). */
export function safeEquals(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) return false;
    return timingSafeEqual(bufA, bufB);
}