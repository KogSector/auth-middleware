# Build stage - compile TypeScript
FROM node:24-slim AS builder

WORKDIR /app

# Install OpenSSL for Prisma
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Copy shared library first
COPY confuse-common/typescript ./confuse-common/typescript

# Set workdir to auth-middleware
WORKDIR /app/auth-middleware

# Copy package files
COPY auth-middleware/package*.json ./
COPY auth-middleware/tsconfig.json ./

# Install ALL dependencies (npm will install local paths correctly now)
RUN npm install

# Copy source files and proto
COPY auth-middleware/src ./src/
COPY proto ../proto/

# Copy prisma schema and generate client
COPY auth-middleware/prisma ./prisma/
RUN npx prisma generate

# Build TypeScript
RUN npm run build

# Prune dev dependencies after building
RUN npm prune --omit=dev 2>/dev/null || true

# Production stage
FROM node:24-slim

# Install OpenSSL (for Prisma), dumb-init (proper signal handling), and wget (health checks)
RUN apt-get update && apt-get install -y openssl dumb-init wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app/auth-middleware

# Set correct ownership for the non-root user
RUN chown -R node:node /app

# Switch to the non-root user
USER node

# Copy shared library (node_modules might symlink to it)
COPY --chown=node:node --from=builder /app/confuse-common /app/confuse-common

# Copy pruned node_modules
COPY --chown=node:node --from=builder /app/auth-middleware/node_modules ./node_modules

# Copy Prisma schema and generated client
COPY --chown=node:node --from=builder /app/auth-middleware/prisma ./prisma/

# Copy package.json for runtime
COPY --chown=node:node --from=builder /app/auth-middleware/package.json ./

# Copy built JavaScript from builder
COPY --chown=node:node --from=builder /app/auth-middleware/dist ./dist

# Copy proto files
COPY --chown=node:node --from=builder /app/proto /app/proto

# Create keys directory
RUN mkdir -p keys

# Set environment
ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080

# Health check optimized for Cloud Run
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1

# Use dumb-init to pass signals correctly (crucial for Cloud Run graceful shutdowns)
ENTRYPOINT ["dumb-init", "--"]

CMD ["node", "dist/index.js"]