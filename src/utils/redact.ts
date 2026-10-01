/**
 * ConFuse Auth Middleware - Secret Redaction
 *
 * Guarantees that passwords, credential-bearing connection URLs, client
 * private keys and other TLS secrets never reach logs, errors, telemetry or
 * debugging output.
 */

/** Matches `scheme://user:password@host` credential pairs in URLs. */
const URL_CREDENTIALS_REGEX = /([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+:[^\s/@]+@/gi;

/** Matches `password=...`, `pwd: ...`, `secret = ...` inline assignments. */
const SECRET_ASSIGNMENT_REGEX =
    /\b(password|passwd|pwd|secret|token|api[_-]?key|auth)[a-z0-9_-]*\b(\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)/gi;

/** Matches Redis/Falkor `AUTH [username] password` command lines. */
const AUTH_COMMAND_REGEX = /\bAUTH\b\s+(?:\S+\s+)?\S+/gi;

/** Matches HELLO ... AUTH <user> <pass> handshake payloads. */
const HELLO_AUTH_REGEX = /(\bHELLO\b[\s\S]*?\bAUTH\b\s+)\S+(\s+)\S+/gi;

/** Matches PEM encoded material (private keys and certificates). */
const PEM_BLOCK_REGEX =
    /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;

export const REDACTED = '[REDACTED]';

/**
 * Redact secret material from a free-form string (error messages, log lines,
 * stack traces, connection URLs).
 */
export function redactSensitive(input: string): string {
    if (!input) return input;
    return input
        .replace(PEM_BLOCK_REGEX, REDACTED)
        .replace(URL_CREDENTIALS_REGEX, `$1${REDACTED}@`)
        .replace(HELLO_AUTH_REGEX, `$1${REDACTED}$2${REDACTED}`)
        .replace(AUTH_COMMAND_REGEX, `AUTH ${REDACTED}`)
        .replace(SECRET_ASSIGNMENT_REGEX, (_m, key: string, sep: string) => `${key}${sep}${REDACTED}`);
}

/** Keys whose values must always be masked in structured output. */
const SENSITIVE_KEY_REGEX =
    /(password|passwd|pwd|secret|token|credential|private[_-]?key|client[_-]?key|ca[_-]?cert|certificate)/i;

/**
 * Deep-copy a value, masking anything that looks like a secret. Used for
 * telemetry, debug dumps and structured log metadata.
 */
export function redactStructured<T>(value: T): T {
    return redactStructuredInner(value, 0) as T;
}

function redactStructuredInner(value: unknown, depth: number): unknown {
    if (depth > 8) return REDACTED;
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') return redactSensitive(value);
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    if (Array.isArray(value)) {
        return value.map((item) => redactStructuredInner(item, depth + 1));
    }
    if (value instanceof Error) {
        return {
            name: value.name,
            message: redactSensitive(value.message),
            stack: value.stack ? redactSensitive(value.stack) : undefined,
        };
    }
    if (typeof value === 'object') {
        const out: Record<string, unknown> = {};
        for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
            if (SENSITIVE_KEY_REGEX.test(key)) {
                out[key] = val === null || val === undefined || val === '' ? val : REDACTED;
            } else {
                out[key] = redactStructuredInner(val, depth + 1);
            }
        }
        return out;
    }
    return REDACTED;
}

/**
 * Produce a safe, redacted summary of an error for API responses and logs.
 */
export function redactError(error: unknown): { message: string; stack?: string } {
    if (error instanceof Error) {
        return {
            message: redactSensitive(error.message),
            stack: error.stack ? redactSensitive(error.stack) : undefined,
        };
    }
    return { message: redactSensitive(String(error)) };
}