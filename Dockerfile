# Build stage - compile TypeScript (Node.js 24 LTS)
# Using slim (Debian) instead of Alpine for Prisma OpenSSL compatibility
FROM node:24-slim AS builder

WORKDIR /app

# Install OpenSSL for Prisma
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY auth-middleware/package*.json ./
COPY auth-middleware/tsconfig.json ./

# Copy source code
COPY auth-middleware/src ./src

# Copy shared library
COPY shared-middleware ./shared-middleware


# Install and build shared library
WORKDIR /app/shared/typescript/confuse-events
RUN npm install && npm run build
WORKDIR /app

# Install ALL dependencies (including dev for building)
RUN npm install

# Copy source files
COPY auth-middleware/prisma ./prisma/
COPY auth-middleware/src ./src/

# Generate Prisma client
RUN npx prisma generate

# Build TypeScript
RUN npm run build

# Production stage
FROM node:24-slim

WORKDIR /app

# Install OpenSSL and wget for health checks
RUN apt-get update && apt-get install -y openssl wget && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY auth-middleware/package*.json ./

# Install production dependencies only
RUN npm install --only=production

# Copy Prisma schema and generate client
COPY auth-middleware/prisma ./prisma/
RUN npx prisma generate

# Copy built JavaScript from builder
COPY --from=builder /app/dist ./dist

# Create keys directory
RUN mkdir -p keys

# Set environment
# Set environment
ENV NODE_ENV=production
ENV PORT=3001

EXPOSE 3001

# Health check optimized for Azure Container Apps
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1

CMD ["node", "dist/index.js"]
