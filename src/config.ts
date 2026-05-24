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
    jwksUri: string;
    clientId?: string;
    clientSecret?: string;
    managementDomain?: string;
}

// Load .env.map first (non-sensitive defaults)
dotenv.config({ path: '.env.map' });
// Then load .env.secret (sensitive values that override defaults)
dotenv.config({ path: '.env.secret' });




interface OAuthProviderConfig {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
}

interface Config {
    port: number;
    nodeEnv: string;
    auth0: Auth0Config;

    tokenCacheTtlSeconds: number;
    databaseUrl: string;
    corsOrigins: string[];
    featureToggleServiceUrl: string;
    frontendUrl: string;
    grpcPort: number;
    internalApiKey: string;
    kafka?: {
        bootstrapServers: string;
        clientId: string;
        eventsTopic: string;
        // Optional dead-letter queue topic for failed messages
        dlqTopic?: string;
    };
    redisUrl: string;

    // Direct OAuth provider configs (non-Auth0 flows)
    github: OAuthProviderConfig;
    slack: OAuthProviderConfig;
    notion: OAuthProviderConfig;
    atlassian: OAuthProviderConfig; // Jira + Confluence share a single Atlassian OAuth app
    gitlab: OAuthProviderConfig;
    bitbucket: OAuthProviderConfig;
    microsoft: OAuthProviderConfig & { tenantId: string };
}

function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

// Note: loading key files is not currently used; keep helper removed to avoid lint warnings.

export const config: Config = {
    // Server
    port: parseInt(process.env.PORT || '3010', 10),
    nodeEnv: process.env.NODE_ENV || 'development',

    // Auth0 (required — OAuth via Google or Microsoft)
    auth0: {
        domain: process.env.AUTH0_DOMAIN || 'dev-placeholder.auth0.com',
        issuer: process.env.AUTH0_ISSUER || 'https://dev-placeholder.auth0.com/',
        audience: process.env.AUTH0_AUDIENCE || 'https://api.confuse.dev',
        jwksUri: process.env.AUTH0_JWKS_URI ||
            `https://${process.env.AUTH0_DOMAIN || 'dev-placeholder.auth0.com'}/.well-known/jwks.json`,
        clientId: process.env.AUTH0_CLIENT_ID,
        clientSecret: process.env.AUTH0_CLIENT_SECRET,
        managementDomain: process.env.AUTH0_MANAGEMENT_DOMAIN || process.env.AUTH0_DOMAIN,
    },

    // ConFuse JWT


    // Token cache TTL
    tokenCacheTtlSeconds: parseInt(process.env.TOKEN_CACHE_TTL_SECONDS || '900', 10), // 15 minutes

    // Database
    databaseUrl: requireEnv('DATABASE_URL'),

    // CORS
    corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:3000')
        .split(',')
        .map(s => s.trim()),

    // Feature Toggle Service
    featureToggleServiceUrl: process.env.FEATURE_TOGGLE_SERVICE_URL || 'http://localhost:3099',

    // Frontend URL for OAuth callbacks
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',

    // gRPC Server Port
    grpcPort: parseInt(process.env.GRPC_PORT || '50058', 10),

    // Internal API Key
    internalApiKey: process.env.INTERNAL_API_KEY || 'default-internal-key',

    // Kafka
    kafka: {
        bootstrapServers: process.env.KAFKA_BOOTSTRAP_SERVERS || 'localhost:9092',
        clientId: process.env.KAFKA_CLIENT_ID || 'auth-middleware',
        eventsTopic: process.env.KAFKA_AUTH_EVENTS_TOPIC || 'auth.events',
        dlqTopic: process.env.KAFKA_DLQ_TOPIC || `${process.env.KAFKA_AUTH_EVENTS_TOPIC || 'auth.events'}.dlq`,
    },
    redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',

    // Direct OAuth provider configs
    github: {
        clientId: process.env.GITHUB_CLIENT_ID || 'Ov23liL3MQoIiV6bgA5w',
        clientSecret: process.env.GITHUB_CLIENT_SECRET || '7e1dd12025ee7c7c43e296192cf16975587729e9',
        redirectUri: process.env.GITHUB_REDIRECT_URI || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/oauth/callback`,
    },
    slack: {
        clientId: process.env.SLACK_CLIENT_ID || '',
        clientSecret: process.env.SLACK_CLIENT_SECRET || '',
        redirectUri: process.env.SLACK_REDIRECT_URI || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/oauth/callback?provider=slack`,
    },
    notion: {
        clientId: process.env.NOTION_CLIENT_ID || '',
        clientSecret: process.env.NOTION_CLIENT_SECRET || '',
        redirectUri: process.env.NOTION_REDIRECT_URI || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/oauth/callback?provider=notion`,
    },
    atlassian: {
        clientId: process.env.ATLASSIAN_CLIENT_ID || '',
        clientSecret: process.env.ATLASSIAN_CLIENT_SECRET || '',
        redirectUri: process.env.ATLASSIAN_REDIRECT_URI || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/oauth/callback?provider=atlassian`,
    },
    gitlab: {
        clientId: process.env.GITLAB_CLIENT_ID || '',
        clientSecret: process.env.GITLAB_CLIENT_SECRET || '',
        redirectUri: process.env.GITLAB_REDIRECT_URI || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/oauth/callback`,
    },
    bitbucket: {
        clientId: process.env.BITBUCKET_CLIENT_ID || '',
        clientSecret: process.env.BITBUCKET_CLIENT_SECRET || '',
        redirectUri: process.env.BITBUCKET_REDIRECT_URI || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/oauth/callback`,
    },
    microsoft: {
        clientId: process.env.MICROSOFT_CLIENT_ID || '',
        clientSecret: process.env.MICROSOFT_CLIENT_SECRET || '',
        tenantId: process.env.MICROSOFT_TENANT_ID || 'common',
        redirectUri: process.env.MICROSOFT_REDIRECT_URI || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/api/auth/oauth/callback`,
    },
};
