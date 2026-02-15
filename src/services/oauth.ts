
import { Redis } from 'ioredis';
import { randomBytes, createHash } from 'crypto';
import { config } from '../config.js';

export interface OAuthState {
    provider: string;
    userId?: string;
    redirectUri: string;
    codeVerifier?: string;
    createdAt: number;
    expiresAt: number;
}

export class OAuthStateService {
    private redis: any;
    private readonly PREFIX = 'oauth:state:';
    private readonly TTL = 600; // 10 minutes

    constructor() {
        const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
        this.redis = new Redis(redisUrl);

        this.redis.on('error', (err: Error) => {
            console.error('Redis connection error:', err);
        });
    }

    /**
     * Generate secure random state
     */
    generateState(): string {
        return randomBytes(32).toString('hex');
    }

    /**
     * Generate PKCE Code Verifier and Challenge
     */
    generatePKCE(): { codeVerifier: string; codeChallenge: string } {
        const codeVerifier = randomBytes(32).toString('base64url');
        const codeChallenge = createHash('sha256')
            .update(codeVerifier)
            .digest('base64url');
        return { codeVerifier, codeChallenge };
    }

    /**
     * Store OAuth state in Redis
     */
    async storeState(state: string, data: Omit<OAuthState, 'createdAt' | 'expiresAt'>): Promise<void> {
        const key = `${this.PREFIX}${state}`;
        const now = Date.now();
        const stateData: OAuthState = {
            ...data,
            createdAt: now,
            expiresAt: now + (this.TTL * 1000),
        };

        // Redis SET command with EX (expiration) option
        await this.redis.set(key, JSON.stringify(stateData), 'EX', this.TTL);
    }

    /**
     * Validate and retrieve state
     */
    async validateState(state: string): Promise<OAuthState | null> {
        const key = `${this.PREFIX}${state}`;
        const data = await this.redis.get(key);

        if (!data) return null;

        try {
            return JSON.parse(data);
        } catch {
            return null;
        }
    }

    /**
     * Consume state (one-time use)
     */
    async consumeState(state: string): Promise<boolean> {
        const key = `${this.PREFIX}${state}`;
        const result = await this.redis.del(key);
        return result === 1;
    }
}

export const oAuthStateService = new OAuthStateService();


export interface OAuthProfile {
    id: string;
    username: string;
    email?: string;
    name?: string;
    avatar_url?: string;
}

/**
 * Validate OAuth token and fetch user profile
 */
export async function validateOAuthToken(provider: string, accessToken: string): Promise<OAuthProfile> {
    switch (provider.toLowerCase()) {
        case 'github':
            return validateGitHubToken(accessToken);
        case 'gitlab':
            return validateGitLabToken(accessToken);
        case 'bitbucket':
            return validateBitbucketToken(accessToken);
        case 'google':
            return validateGoogleToken(accessToken);
        default:
            throw new Error(`Unsupported provider: ${provider}`);
    }
}

async function validateGitHubToken(token: string): Promise<OAuthProfile> {
    const response = await fetch('https://api.github.com/user', {
        headers: {
            'Authorization': `Bearer ${token}`,
            'User-Agent': 'ConFuse-Auth-Middleware',
            'Accept': 'application/json',
        },
    });

    if (!response.ok) {
        throw new Error(`GitHub token validation failed: ${response.status} ${response.statusText}`);
    }

    const data: any = await response.json();
    return {
        id: data.id.toString(),
        username: data.login,
        email: data.email,
        name: data.name,
        avatar_url: data.avatar_url,
    };
}

async function validateGitLabToken(token: string): Promise<OAuthProfile> {
    const response = await fetch('https://gitlab.com/api/v4/user', {
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });

    if (!response.ok) {
        throw new Error(`GitLab token validation failed: ${response.status} ${response.statusText}`);
    }

    const data: any = await response.json();
    return {
        id: data.id.toString(),
        username: data.username,
        email: data.email,
        name: data.name,
        avatar_url: data.avatar_url,
    };
}

async function validateBitbucketToken(token: string): Promise<OAuthProfile> {
    const response = await fetch('https://api.bitbucket.org/2.0/user', {
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });

    if (!response.ok) {
        throw new Error(`Bitbucket token validation failed: ${response.status} ${response.statusText}`);
    }

    const data: any = await response.json();
    return {
        id: data.account_id,
        username: data.username || data.display_name, // Bitbucket 2.0 uses account_id/uuid
        name: data.display_name,
        avatar_url: data.links?.avatar?.href,
    };
}

async function validateGoogleToken(token: string): Promise<OAuthProfile> {
    const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });

    if (!response.ok) {
        throw new Error(`Google token validation failed: ${response.status} ${response.statusText}`);
    }

    const data: any = await response.json();
    return {
        id: data.sub,
        username: data.email,
        email: data.email,
        name: data.name,
        avatar_url: data.picture,
    };
}
// ... existing validation functions ...
