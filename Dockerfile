# Build stage - compile TypeScript (Node.js 22 LTS)
# Using slim (Debian) instead of Alpine for Prisma OpenSSL compatibility
FROM node:22-slim AS builder

WORKDIR /app

# Install OpenSSL for Prisma
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY auth-middleware/package*.json ./
COPY auth-middleware/tsconfig.json ./

# Copy source files
COPY auth-middleware/src ./src/
COPY auth-middleware/proto ./proto/

# Copy shared library
COPY shared-middleware/typescript/confuse-events ./shared-middleware/confuse-events

# Install and build shared library
WORKDIR /app/shared-middleware/confuse-events
RUN rm -rf package-lock.json && npm install && npm run build
WORKDIR /app

# Install ALL dependencies (including dev for building)
# Patch @confuse/events path for Docker layout (./shared-middleware instead of ../../shared-middleware)
RUN rm -rf package-lock.json && \
    sed -i 's|file:../shared-middleware|file:./shared-middleware|g' package.json && \
    npm install

# Copy source files
COPY auth-middleware/prisma ./prisma/
COPY auth-middleware/src ./src/

# Generate Prisma client
RUN npx prisma generate

# Build TypeScript
RUN npm run build

# Prune dev dependencies after building
RUN npm prune --omit=dev 2>/dev/null; exit 0

# Production stage
FROM node:22-slim

WORKDIR /app

# Install OpenSSL and wget for health checks
RUN apt-get update && apt-get install -y openssl wget && rm -rf /var/lib/apt/lists/*

# Copy node_modules from builder (already pruned to production deps)
COPY --from=builder /app/node_modules ./node_modules

# Copy shared-middleware built artifacts (needed for @confuse/events runtime)
COPY --from=builder /app/shared-middleware ./shared-middleware

# Copy Prisma schema and generated client
COPY auth-middleware/prisma ./prisma/

# Copy package.json for runtime
COPY --from=builder /app/package.json ./

# Copy built JavaScript from builder
COPY --from=builder /app/dist ./dist

# Copy proto files
COPY --from=builder /app/proto ./proto

# Create keys directory
RUN mkdir -p keys

# Set environment
ENV NODE_ENV=production
ENV PORT=3010

EXPOSE 3010

# Health check optimized for Azure Container Apps
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3010/health || exit 1

CMD ["node", "dist/index.js"]
