require('dotenv').config({ path: '.env.secret' });
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function run() {
  const account = await prisma.account.findFirst({ where: { provider: 'onedrive' } });
  
  const tenantId = process.env.MICROSOFT_TENANT_ID || 'consumers';
  const clientId = process.env.MICROSOFT_CLIENT_ID || '';
  const clientSecret = process.env.MICROSOFT_CLIENT_SECRET || '';
  
  console.log("Tenant:", tenantId);
  console.log("Client:", clientId);
  console.log("Secret length:", clientSecret.length);
  
  const body = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: account.refresh_token,
      grant_type: 'refresh_token'
  }).toString();
  
  const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
  });
  
  const data = await tokenRes.json();
  console.log(data);
  prisma.$disconnect();
}

run();
