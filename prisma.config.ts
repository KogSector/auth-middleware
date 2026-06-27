import { config } from 'dotenv';
import path from 'path';
config({ path: path.resolve(process.cwd(), '.env.map') });
config({ path: path.resolve(process.cwd(), '.env.secret') });
import { defineConfig, env } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: {
    url: env('DATABASE_URL'),
  },
});
