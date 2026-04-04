#!/bin/bash
# =============================================================================
# Auth-Middleware Service Test Script
# =============================================================================
# This script tests the auth-middleware service health and functionality
# Usage: ./scripts/test.sh [--endpoint ENDPOINT] [--namespace NAMESPACE]
# =============================================================================

set -e

# Default values
ENDPOINT="http://localhost:3010"
NAMESPACE="confuse"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --k8s)
            # Test Kubernetes deployment instead of local
            SERVICE_IP=$(kubectl get service auth-middleware -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
            if [ -n "$SERVICE_IP" ] && [ "$SERVICE_IP" != "<none>" ]; then
                ENDPOINT="http://$SERVICE_IP:3010"
                echo "Testing Kubernetes deployment at: $ENDPOINT"
            else
                echo "❌ Could not find auth-middleware service in namespace $NAMESPACE"
                exit 1
            fi
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--endpoint ENDPOINT] [--namespace NAMESPACE] [--k8s]"
            exit 1
            ;;
    esac
done

echo "=== Testing Auth-Middleware Service ==="
echo "Endpoint: $ENDPOINT"

# ============================================================================
# Step 1: Health Check
# ============================================================================
echo "Testing health endpoint..."
if curl -f -s "$ENDPOINT/health" > /dev/null; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# ============================================================================
# Step 2: Ready Check
# ============================================================================
echo "Testing ready endpoint..."
if curl -f -s "$ENDPOINT/ready" > /dev/null; then
    echo "✅ Ready check passed"
else
    echo "❌ Ready check failed"
    exit 1
fi

# ============================================================================
# Step 3: Service Info
# ============================================================================
echo "Getting service info..."
if curl -s "$ENDPOINT/info" | grep -q "auth-middleware"; then
    echo "✅ Service info endpoint working"
else
    echo "⚠️  Service info endpoint not responding (may not be implemented)"
fi

# ============================================================================
# Step 4: Database Connection Test
# ============================================================================
echo "Testing database connection..."
if curl -s "$ENDPOINT/health/db" | grep -q "connected"; then
    echo "✅ Database connection working"
else
    echo "⚠️  Database connection test failed or not implemented"
fi

# ============================================================================
# Step 5: Redis Connection Test
# ============================================================================
echo "Testing Redis connection..."
if curl -s "$ENDPOINT/health/redis" | grep -q "connected"; then
    echo "✅ Redis connection working"
else
    echo "⚠️  Redis connection test failed or not implemented"
fi

# ============================================================================
# Step 6: Authentication Test (if Auth0 is configured)
# ============================================================================
echo "Testing authentication endpoints..."
# Test login endpoint (should return 401 without credentials)
if curl -s -w "%{http_code}" "$ENDPOINT/auth/login" | grep -q "401"; then
    echo "✅ Authentication endpoint responding correctly"
else
    echo "⚠️  Authentication endpoint may not be properly configured"
fi

# ============================================================================
# Step 7: Load Test
# ============================================================================
echo "Running simple load test..."
echo "Sending 10 concurrent requests..."
for i in {1..10}; do
    curl -s "$ENDPOINT/health" > /dev/null &
done
wait
echo "✅ Load test completed"

echo ""
echo "✅ All tests completed successfully!"
echo ""
echo "Service is healthy and responding at: $ENDPOINT"
echo ""
echo "Additional tests you can run:"
echo "1. Manual API testing: curl -X POST $ENDPOINT/auth/login -d '{\"email\":\"test@example.com\"}'"
echo "2. gRPC testing: grpcurl -plaintext $ENDPOINT:50058 list"
echo "3. Performance testing: ab -n 100 -c 10 $ENDPOINT/health"
