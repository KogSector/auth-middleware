import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
prisma.account.findMany().then(console.log).finally(() => prisma.$disconnect());
