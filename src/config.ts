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

// Load .env.map first, then .env.secret (with override), then .env.local
dotenv.config({ path: path.resolve(process.cwd(), '.env.map') });
// .env.secret overrides defaults (override: true ensures secrets win over .env.map)
dotenv.config({ path: path.resolve(process.cwd(), '.env.secret'), override: true });
// .env.local allows local developer overrides on top of everything
dotenv.config({ path: path.resolve(process.cwd(), '.env.local'), override: true });

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

    // FalkorDB configuration
    falkordbHost: string;
    falkordbPort: number;
    falkordbUsername: string;
    falkordbPassword: string;

    // Direct OAuth provider configs (non-Auth0 flows)
    github: OAuthProviderConfig;
    slack: OAuthProviderConfig;
    notion: OAuthProviderConfig;
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
    port: parseInt(process.env.PORT || process.env.AUTH_MIDDLEWARE_PORT || '3010', 10),
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

    // FalkorDB configuration
    falkordbHost: process.env.FALKORDB_HOST || 'r-6jissuruar.instance-ivah2xvml.hc-7up0crkyn.ap-south-1.aws.f2e0a955bb84.cloud',
    falkordbPort: parseInt(process.env.FALKORDB_PORT || '50860', 10),
    falkordbUsername: process.env.FALKORDB_USERNAME || 'adminconfuse',
    falkordbPassword: process.env.FALKORDB_PASSWORD || 'graph4confuse',

    // Direct OAuth provider configs
    github: {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        redirectUri: process.env.GITHUB_REDIRECT_URI?.trim() || process.env.OAUTH_CALLBACK_URL?.trim(),
    },
    slack: {
        clientId: process.env.SLACK_CLIENT_ID,
        clientSecret: process.env.SLACK_CLIENT_SECRET,
        redirectUri: process.env.SLACK_REDIRECT_URI?.trim() || process.env.OAUTH_CALLBACK_URL?.trim(),
    },
    notion: {
        clientId: process.env.NOTION_CLIENT_ID,
        clientSecret: process.env.NOTION_CLIENT_SECRET,
        redirectUri: process.env.NOTION_REDIRECT_URI?.trim() || process.env.OAUTH_CALLBACK_URL?.trim(),
    },

    gitlab: {
        clientId: process.env.GITLAB_CLIENT_ID,
        clientSecret: process.env.GITLAB_CLIENT_SECRET,
        redirectUri: process.env.GITLAB_REDIRECT_URI?.trim() || process.env.OAUTH_CALLBACK_URL?.trim(),
    },
    bitbucket: {
        clientId: process.env.BITBUCKET_CLIENT_ID,
        clientSecret: process.env.BITBUCKET_CLIENT_SECRET,
        redirectUri: process.env.BITBUCKET_REDIRECT_URI?.trim() || process.env.OAUTH_CALLBACK_URL?.trim(),
    },
    microsoft: {
        clientId: process.env.MICROSOFT_CLIENT_ID,
        clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
        tenantId: process.env.MICROSOFT_TENANT_ID,
        redirectUri: process.env.MICROSOFT_REDIRECT_URI?.trim() || process.env.OAUTH_CALLBACK_URL?.trim(),
    },
    dropbox: {
        clientId: process.env.DROPBOX_CLIENT_ID,
        clientSecret: process.env.DROPBOX_CLIENT_SECRET,
        redirectUri: process.env.DROPBOX_REDIRECT_URI?.trim() || process.env.OAUTH_CALLBACK_URL?.trim(),
    },
};


