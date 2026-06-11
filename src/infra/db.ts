import { PrismaClient } from '@prisma/client';

// Prevent multiple instances of Prisma Client in development
/* eslint-disable no-var */
declare global {
    var prisma: PrismaClient | undefined;
}
/* eslint-enable no-var */

export const prisma = global.prisma || new PrismaClient();

if (process.env.NODE_ENV !== 'production') {
    global.prisma = prisma;
}

export default prisma;
