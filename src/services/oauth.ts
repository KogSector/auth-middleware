

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
