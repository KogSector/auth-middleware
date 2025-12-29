/**
 * ConHub Auth Middleware - User Service
 * 
 * Handles user CRUD operations with Prisma
 */

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

/**
 * Find or create user by Auth0 subject
 * @param {Object} input - User input
 * @returns {Promise<Object>} - User record
 */
async function findOrCreateByAuth0(input) {
    const { auth0Sub, email, name, picture, roles } = input;

    // Try to find existing user by auth0Sub
    let user = await prisma.user.findUnique({
        where: { auth0Sub },
    });

    if (user) {
        // Update user info if changed
        user = await prisma.user.update({
            where: { id: user.id },
            data: {
                email: email || user.email,
                name: name ?? user.name,
                picture: picture ?? user.picture,
                lastLoginAt: new Date(),
            },
        });
        return user;
    }

    // Check if email already exists (different auth0 sub)
    const existingByEmail = await prisma.user.findUnique({
        where: { email },
    });

    if (existingByEmail) {
        // Link auth0Sub to existing user
        user = await prisma.user.update({
            where: { id: existingByEmail.id },
            data: {
                auth0Sub,
                name: name ?? existingByEmail.name,
                picture: picture ?? existingByEmail.picture,
                lastLoginAt: new Date(),
            },
        });
        return user;
    }

    // Create new user
    user = await prisma.user.create({
        data: {
            auth0Sub,
            email,
            name,
            picture,
            roles: roles || ['user'],
            lastLoginAt: new Date(),
        },
    });

    return user;
}

/**
 * Find user by ID
 * @param {string} id - User ID
 * @returns {Promise<Object|null>} - User or null
 */
async function findById(id) {
    return prisma.user.findUnique({
        where: { id },
    });
}

/**
 * Find user by auth0Sub
 * @param {string} auth0Sub - Auth0 subject
 * @returns {Promise<Object|null>} - User or null
 */
async function findByAuth0Sub(auth0Sub) {
    return prisma.user.findUnique({
        where: { auth0Sub },
    });
}

/**
 * Update last login timestamp
 * @param {string} userId - User ID
 */
async function updateLastLogin(userId) {
    await prisma.user.update({
        where: { id: userId },
        data: { lastLoginAt: new Date() },
    });
}

/**
 * Get user profile (safe for client)
 * @param {Object} user - User record
 * @returns {Object} - User profile
 */
function toProfile(user) {
    return {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        roles: user.roles,
        createdAt: user.createdAt.toISOString(),
    };
}

module.exports = {
    prisma,
    findOrCreateByAuth0,
    findById,
    findByAuth0Sub,
    updateLastLogin,
    toProfile,
};
