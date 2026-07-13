#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[1/4] Stopping any old EndpointTrust containers..."
docker rm -f endpointtrust_nginx_gateway endpointtrust_server endpointtrust_internal_hr >/dev/null 2>&1 || true

echo "[2/4] Removing this version's old demo volumes for a clean PKI state..."
docker compose down -v --remove-orphans >/dev/null 2>&1 || true

echo "[3/4] Building and starting EndpointTrust PKI v5..."
docker compose up --build -d

echo "[4/4] Waiting for services..."
for _ in $(seq 1 30); do
  if curl -fsS http://localhost:8080/api/status >/dev/null 2>&1; then
    echo
    echo "EndpointTrust is ready."
    echo "Device Portal: http://localhost:8080/endpointtrust/device-portal"
    echo "Protected HR:  http://localhost:8080/internal/"
    echo "Tkinter admin:  ./scripts/run_admin.sh"
    exit 0
  fi
  sleep 1
done

echo "EndpointTrust did not become ready within 30 seconds. Showing container status:"
docker compose ps
echo "Check logs with: docker compose logs --tail=100"
exit 1
