#!/bin/bash
# scripts/deploy.sh - Production deployment script for Krittika-Splunk Nexus
# RADHIKATMOSPHERE / Krittika-Splunk Nexus

set -e

echo "=========================================="
echo "Krittika-Splunk Nexus Production Deploy"
echo "=========================================="

# 1. Verify environment
if [ ! -f .env ]; then
    echo "ERROR: .env file not found. Copy .env.example and configure."
    exit 1
fi

source .env

if [ -z "$HEC_TOKEN" ] || [ -z "$MCP_TOKEN" ]; then
    echo "ERROR: HEC_TOKEN and MCP_TOKEN must be set in .env"
    exit 1
fi

# 2. Deploy Splunk Universal Forwarder
echo "[1/4] Deploying Splunk Universal Forwarder..."
docker-compose up -d splunk-universal-forwarder

# Wait for forwarder to be healthy
echo "Waiting for forwarder to be healthy..."
for i in $(seq 1 30); do
    if docker inspect krittika-forwarder --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; then
        echo "Forwarder is healthy."
        break
    fi
    sleep 2
done

# 3. Deploy Krittika AI Agent
echo "[2/4] Deploying Krittika AI Agent..."
docker-compose up -d krittika-agent

# 4. Verify connectivity
echo "[3/4] Verifying Splunk connectivity..."
sleep 5

# Check if we can reach Splunk HEC
if curl -s -k -o /dev/null -w "%{http_code}" \
    -H "Authorization: Splunk $HEC_TOKEN" \
    "${SPLUNK_HOST}:8088/services/collector/health" | grep -q "200"; then
    echo "✓ HEC endpoint reachable"
else
    echo "⚠ HEC endpoint check failed (may still be configuring)"
fi

# 5. Print status
echo "[4/4] Deployment complete!"
echo ""
echo "Services running:"
docker-compose ps
echo ""
echo "Next steps:"
echo "1. Verify logs: docker-compose logs -f krittika-agent"
echo "2. Check dashboard: ${SPLUNK_HOST}/en-US/app/krittika_splunk_nexus_ta"
echo "3. Monitor audit trail: index=krittika_audit sourcetype=krittika:audit"
echo ""
echo "=========================================="
