# Build and run
FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY prisma ./prisma/
COPY src ./src/

# Generate Prisma client
RUN npx prisma generate

# Create keys directory
RUN mkdir -p keys

# Set environment
ENV NODE_ENV=production
ENV PORT=3010

EXPOSE 3010

CMD ["node", "src/index.js"]
