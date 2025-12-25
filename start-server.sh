#!/usr/bin/env bash
# Hugo Development Server Launcher
# Dynamically determines IP and starts server for LAN browsing

set -euo pipefail

# Get the VM's IP address (best-route IP, not just "first one")
VM_IP="$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')"

# Validate we got an IP
if [[ -z "${VM_IP}" ]]; then
  echo "❌ ERROR: Could not determine VM IP address"
  exit 1
fi

BASEURL="http://${VM_IP}:1313/"

# Display startup info
echo "🚀 Starting Hugo development server..."
echo "📍 Server IP: ${VM_IP}"
echo "🔗 Access at: ${BASEURL}"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Kill any existing Hugo processes (prevent conflicts)
pkill hugo 2>/dev/null || true

# Wait for cleanup
sleep 1

# Start Hugo server with optimal development settings
exec hugo server \
  -D \
  --bind 0.0.0.0 \
  --port 1313 \
  --baseURL "${BASEURL}" \
  --appendPort=false \
  --environment development \
  --disableFastRender \
  --noHTTPCache \
  --buildFuture \
  --cleanDestinationDir
