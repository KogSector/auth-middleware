import { config } from 'dotenv';
import path from 'path';
config({ path: path.resolve(process.cwd(), '.map.env') });
config({ path: path.resolve(process.cwd(), '.secret.env') });

import { defineConfig, env } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: {
    url: env('DATABASE_URL'),
  },
});
