require('dotenv').config({ path: '.env.secret' });
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
prisma.account.findFirst({ where: { provider: 'onedrive' } }).then(console.log).finally(() => prisma.$disconnect());
