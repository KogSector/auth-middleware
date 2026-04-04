#!/bin/bash
# =============================================================================
# Auth-Middleware Service Build Script
# =============================================================================
# This script builds the auth-middleware Docker image
# Usage: ./scripts/build.sh [--registry REGISTRY] [--version VERSION]
# =============================================================================

set -e

# Default values
REGISTRY="confuseimgr.azurecr.io"
VERSION="v1.0.0"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --registry)
            REGISTRY="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--registry REGISTRY] [--version VERSION]"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Building Auth-Middleware Docker Image ==="
echo "Registry: $REGISTRY"
echo "Version: $VERSION"
echo "Service Directory: $SERVICE_DIR"

# ============================================================================
# Step 1: Build Docker Image
# ============================================================================
echo "Building Docker image..."
docker build \
    --tag "${REGISTRY}/auth-middleware:${VERSION}" \
    --tag "${REGISTRY}/auth-middleware:latest" \
    "$SERVICE_DIR"

echo "✅ Docker image built successfully!"
echo ""
echo "Built images:"
echo "  ${REGISTRY}/auth-middleware:${VERSION}"
echo "  ${REGISTRY}/auth-middleware:latest"
echo ""
echo "To push to registry:"
echo "  docker push ${REGISTRY}/auth-middleware:${VERSION}"
echo "  docker push ${REGISTRY}/auth-middleware:latest"
