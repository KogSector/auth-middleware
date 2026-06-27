/**
 * ConFuse Auth Middleware - Configuration
 * 
 * Loads environment variables with validation
 */

import dotenv from 'dotenv';

interface Auth0Config {
    domain: string;
    issuer: string;
    audience: string;
    jwksUri?: string;
    clientId?: string;
    clientSecret?: string;
    managementDomain?: string;
}

import path from 'path';

// Load local .env.map first (non-sensitive defaults)
dotenv.config({ path: path.resolve(process.cwd(), '.env.map') });
// Then load local .env.secret (sensitive values that override defaults)
dotenv.config({ path: path.resolve(process.cwd(), '.env.secret') });

interface OAuthProviderConfig {
    clientId?: string;
    clientSecret?: string;
    redirectUri?: string;
}

interface Config {
    port: number;
    nodeEnv: string;
    auth0: Auth0Config;

    tokenCacheTtlSeconds: number;
    databaseUrl: string;
    corsOrigins: string[];

    frontendUrl: string;
    grpcPort: number;
    internalApiKey: string;
    redisUrl: string;

    // Direct OAuth provider configs (non-Auth0 flows)
    github: OAuthProviderConfig;
    slack: OAuthProviderConfig;
    notion: OAuthProviderConfig;
    atlassian: OAuthProviderConfig; // Jira + Confluence share a single Atlassian OAuth app
    gitlab: OAuthProviderConfig;
    bitbucket: OAuthProviderConfig;
    microsoft: OAuthProviderConfig & { tenantId?: string };
    dropbox: OAuthProviderConfig;
}

function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

export const config: Config = {
    // Server
    port: parseInt(requireEnv('AUTH_MIDDLEWARE_PORT'), 10),
    nodeEnv: requireEnv('NODE_ENV'),

    // Auth0 (required — OAuth via Google or Microsoft)
    auth0: {
        domain: requireEnv('AUTH0_DOMAIN'),
        issuer: requireEnv('AUTH0_ISSUER'),
        audience: requireEnv('AUTH0_AUDIENCE'),
        jwksUri: process.env.AUTH0_JWKS_URI || `https://${requireEnv('AUTH0_DOMAIN')}/.well-known/jwks.json`,
        clientId: process.env.AUTH0_CLIENT_ID,
        clientSecret: process.env.AUTH0_CLIENT_SECRET,
        managementDomain: process.env.AUTH0_MANAGEMENT_DOMAIN || process.env.AUTH0_DOMAIN,
    },

    // Token cache TTL
    tokenCacheTtlSeconds: parseInt(requireEnv('TOKEN_CACHE_TTL_SECONDS'), 10),

    // Database
    databaseUrl: requireEnv('DATABASE_URL'),

    // CORS
    corsOrigins: requireEnv('CORS_ORIGINS')
        .split(',')
        .map(s => s.trim()),


    // Frontend URL for OAuth callbacks
    frontendUrl: requireEnv('FRONTEND_URL'),

    // gRPC Server Port
    grpcPort: parseInt(requireEnv('GRPC_PORT'), 10),

    // Internal API Key
    internalApiKey: requireEnv('INTERNAL_API_KEY'),

    redisUrl: requireEnv('REDIS_URL'),

    // Direct OAuth provider configs
    github: {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        redirectUri: process.env.GITHUB_REDIRECT_URI,
    },
    slack: {
        clientId: process.env.SLACK_CLIENT_ID,
        clientSecret: process.env.SLACK_CLIENT_SECRET,
        redirectUri: process.env.SLACK_REDIRECT_URI,
    },
    notion: {
        clientId: process.env.NOTION_CLIENT_ID,
        clientSecret: process.env.NOTION_CLIENT_SECRET,
        redirectUri: process.env.NOTION_REDIRECT_URI,
    },
    atlassian: {
        clientId: process.env.ATLASSIAN_CLIENT_ID,
        clientSecret: process.env.ATLASSIAN_CLIENT_SECRET,
        redirectUri: process.env.ATLASSIAN_REDIRECT_URI,
    },
    gitlab: {
        clientId: process.env.GITLAB_CLIENT_ID,
        clientSecret: process.env.GITLAB_CLIENT_SECRET,
        redirectUri: process.env.GITLAB_REDIRECT_URI,
    },
    bitbucket: {
        clientId: process.env.BITBUCKET_CLIENT_ID,
        clientSecret: process.env.BITBUCKET_CLIENT_SECRET,
        redirectUri: process.env.BITBUCKET_REDIRECT_URI,
    },
    microsoft: {
        clientId: process.env.MICROSOFT_CLIENT_ID,
        clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
        tenantId: process.env.MICROSOFT_TENANT_ID,
        redirectUri: process.env.MICROSOFT_REDIRECT_URI,
    },
    dropbox: {
        clientId: process.env.DROPBOX_CLIENT_ID,
        clientSecret: process.env.DROPBOX_CLIENT_SECRET,
        redirectUri: process.env.DROPBOX_REDIRECT_URI,
    },
};
