/**
 * ConHub Auth Middleware - Auth0 Service
 * 
 * Handles Auth0 token verification with JWKS caching
 */

const { createRemoteJWKSet, jwtVerify } = require('jose');
const { config } = require('../config');

// JWKS remote key set (cached by jose library)
let jwks = null;

function getJWKS() {
    if (!jwks) {
        jwks = createRemoteJWKSet(new URL(config.auth0.jwksUri));
    }
    return jwks;
}

/**
 * Verify Auth0 access token
 * @param {string} token - Auth0 access token
 * @returns {Promise<Object>} - Decoded claims
 */
async function verifyAuth0Token(token) {
    try {
        const { payload } = await jwtVerify(token, getJWKS(), {
            issuer: config.auth0.issuer,
            audience: config.auth0.audience,
        });

        return payload;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Auth0 token verification failed: ${message}`);
    }
}

/**
 * Extract user info from Auth0 claims
 * @param {Object} claims - Auth0 JWT claims
 * @returns {Object} - User info
 */
function extractUserInfo(claims) {
    // Try to get email from standard claim or namespaced claims
    let email = claims.email || null;

    // Check for namespaced email claims (Auth0 custom namespace)
    if (!email) {
        const namespaces = ['https://conhub.dev/', 'https://api.conhub.dev/'];
        for (const ns of namespaces) {
            const nsEmail = claims[`${ns}email`];
            if (typeof nsEmail === 'string') {
                email = nsEmail;
                break;
            }
        }
    }

    // Generate synthetic email if not available
    if (!email) {
        const sanitizedSub = claims.sub.replace(/\|/g, '.');
        email = `${sanitizedSub}@auth0.local`;
    }

    return {
        auth0Sub: claims.sub,
        email,
        name: claims.name || null,
        picture: claims.picture || null,
    };
}

/**
 * Extract roles from permissions
 * @param {Object} claims - Auth0 JWT claims
 * @returns {string[]} - User roles
 */
function extractRoles(claims) {
    const roles = [];

    if (claims.permissions) {
        if (claims.permissions.some(p => p.startsWith('admin'))) {
            roles.push('admin');
        }
    }

    if (roles.length === 0) {
        roles.push('user');
    }

    return roles;
}

module.exports = {
    verifyAuth0Token,
    extractUserInfo,
    extractRoles,
};
