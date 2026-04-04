#!/bin/bash
# =============================================================================
# Auth-Middleware Local Development Script
# =============================================================================
# This script runs the auth-middleware service locally with SaaS endpoints
# Usage: ./scripts/local-run.sh [--port PORT] [--env ENV_FILE]
# =============================================================================

set -e

# Default values
PORT="3010"
ENV_FILE=".env.local"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            PORT="$2"
            shift 2
            ;;
        --env)
            ENV_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--port PORT] [--env ENV_FILE]"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Running Auth-Middleware Locally ==="
echo "Port: $PORT"
echo "Environment File: $ENV_FILE"
echo "Service Directory: $SERVICE_DIR"

# ============================================================================
# Step 1: Check Environment File
# ============================================================================
if [ ! -f "$SERVICE_DIR/$ENV_FILE" ]; then
    echo "Creating local environment file..."
    cat > "$SERVICE_DIR/$ENV_FILE" << EOF
# Auth-Middleware Local Development Configuration
PORT=$PORT
HOST=0.0.0.0
ENVIRONMENT=development

# Shared SaaS Infrastructure
POSTGRES_HOST=confuse-postgres.postgres.database.azure.com
POSTGRES_PORT=5432
POSTGRES_DATABASE=confuse-db
POSTGRES_USER=RishabhCF
POSTGRES_PASSWORD=PostAz26confuse
POSTGRES_SSL_MODE=require

REDIS_HOST=redis-cloud.example.com
REDIS_PORT=6380
REDIS_PASSWORD=your_redis_password

# Auth0 (replace with your values)
AUTH0_CLIENT_ID=your_auth0_client_id
AUTH0_CLIENT_SECRET=your_auth0_client_secret
AUTH0_DOMAIN=confuse.auth0.com

# Security
JWT_SECRET=local-dev-secret-change-in-production
ENCRYPTION_KEY=local-dev-encryption-key-32-chars

# Logging
LOG_LEVEL=debug
LOG_FORMAT=pretty

# CORS (for local development)
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# gRPC
GRPC_PORT=50058
GRPC_HOST=0.0.0.0
EOF
    echo "✅ Created $ENV_FILE - please update Auth0 credentials"
fi

# ============================================================================
# Step 2: Install Dependencies
# ============================================================================
echo "Installing dependencies..."
cd "$SERVICE_DIR"
npm install

# ============================================================================
# Step 3: Run Database Migrations (if needed)
# ============================================================================
echo "Running database migrations..."
npx prisma migrate deploy || echo "⚠️  Migration failed - continuing anyway"

# ============================================================================
# Step 4: Start Service
# ============================================================================
echo "Starting auth-middleware service..."
export NODE_ENV=development
export PORT=$PORT

if command -v nodemon &> /dev/null; then
    echo "Using nodemon for auto-reload..."
    nodemon --exec "npm run dev"
else
    echo "Starting with npm run dev..."
    npm run dev
fi
