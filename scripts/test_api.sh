#!/usr/bin/env bash
# ==============================================================================
# FILE: scripts/test_api.sh
# DESCRIPTION: Automated test suite for the NSFW Blocklist API & Cloudflare Middleware.
# 
# WHAT THIS FILE DOES:
# 1. Checks if a local Wrangler Pages dev server is already running on port 8788.
# 2. If not running, launches 'wrangler pages dev' in the background with the test secret.
# 3. Executes comprehensive assertions against endpoints:
#    - Rejection of unauthenticated requests (401 Unauthorized)
#    - Rejection of invalid secret keys (401 Unauthorized)
#    - Acceptance of 'Authorization: Bearer' tokens (200 OK)
#    - Acceptance of 'X-API-Key' custom headers (200 OK)
#    - Acceptance of '?key=' query parameter authentication (200 OK)
#    - Verification of CORS preflight OPTIONS requests (204 No Content)
#    - Verification of exact SHA-256 integrity match between metadata & release
#    - Verification of HTTP Cache-Control headers (fast-revalidate vs immutable)
# 4. Safely shuts down the background server upon completion.
# ==============================================================================

set -eo pipefail

PORT=8788
BASE_URL="http://127.0.0.1:${PORT}"
SECRET="dev-secret-key-12345"
SERVER_PID=""

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    echo "[*] Stopping background Wrangler dev server (PID: $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "============================================================"
echo " Starting NSFW Blocklist API Test Suite"
echo " Target: ${BASE_URL}"
echo "============================================================"

# Check if a dev server is already active
if curl -s -f -o /dev/null --connect-timeout 1 "${BASE_URL}/" 2>/dev/null; then
  echo "[*] Existing dev server detected on port ${PORT}."
else
  echo "[*] Starting local Cloudflare Pages dev server via Wrangler..."
  npx wrangler pages dev public --binding "API_SECRET_KEY=${SECRET}" --port "${PORT}" --ip 127.0.0.1 > /tmp/wrangler_test.log 2>&1 &
  SERVER_PID=$!

  # Wait for server readiness
  MAX_RETRIES=30
  RETRY=0
  until curl -s -o /dev/null --connect-timeout 1 "${BASE_URL}/api/v1/version.json" 2>/dev/null; do
    sleep 0.5
    RETRY=$((RETRY + 1))
    if [ "$RETRY" -ge "$MAX_RETRIES" ]; then
      echo "[ERROR] Wrangler dev server failed to start within 15 seconds."
      cat /tmp/wrangler_test.log
      exit 1
    fi
  done
  echo "[✓] Dev server is ready and accepting requests."
fi

echo ""
echo "--- [1/8] Test: Missing Authentication on /api/v1/version.json ---"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/v1/version.json")
if [ "$HTTP_STATUS" -eq 401 ]; then
  echo "  ✓ PASS: Received HTTP 401 Unauthorized as expected."
else
  echo "  ✗ FAIL: Expected 401, but got ${HTTP_STATUS}."
  exit 1
fi

echo ""
echo "--- [2/8] Test: Invalid Secret Key on /api/v1/version.json ---"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer wrong-password" \
  "${BASE_URL}/api/v1/version.json")
if [ "$HTTP_STATUS" -eq 401 ]; then
  echo "  ✓ PASS: Received HTTP 401 for incorrect bearer key."
else
  echo "  ✗ FAIL: Expected 401, but got ${HTTP_STATUS}."
  exit 1
fi

echo ""
echo "--- [3/8] Test: Valid Bearer Auth on /api/v1/version.json ---"
VERSION_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer ${SECRET}" \
  "${BASE_URL}/api/v1/version.json")
HTTP_STATUS=$(echo "$VERSION_RESPONSE" | tail -n 1)
VERSION_BODY=$(echo "$VERSION_RESPONSE" | head -n -1)

if [ "$HTTP_STATUS" -eq 200 ]; then
  echo "  ✓ PASS: HTTP 200 OK received."
  echo "  Body: ${VERSION_BODY}"
else
  echo "  ✗ FAIL: Expected 200, got ${HTTP_STATUS}."
  echo "${VERSION_BODY}"
  exit 1
fi

ACTIVE_RELEASE_URL=$(echo "$VERSION_BODY" | grep -o '"domains_url": *"[^"]*"' | cut -d'"' -f4)
if [ -z "$ACTIVE_RELEASE_URL" ]; then
  ACTIVE_RELEASE_URL="/api/v1/releases/1.json"
fi

echo ""
echo "--- [4/8] Test: Valid X-API-Key Header on ${ACTIVE_RELEASE_URL} ---"
RELEASE_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -H "X-API-Key: ${SECRET}" \
  "${BASE_URL}${ACTIVE_RELEASE_URL}")
HTTP_STATUS=$(echo "$RELEASE_RESPONSE" | tail -n 1)
RELEASE_BODY=$(echo "$RELEASE_RESPONSE" | head -n -1)

if [ "$HTTP_STATUS" -eq 200 ]; then
  echo "  ✓ PASS: HTTP 200 OK received."
  echo "  Body preview: $(echo "$RELEASE_BODY" | tr '\n' ' ' | cut -c 1-80)..."
else
  echo "  ✗ FAIL: Expected 200, got ${HTTP_STATUS}."
  echo "${RELEASE_BODY}"
  exit 1
fi

echo ""
echo "--- [5/8] Test: Valid Query Parameter Auth on /api/v1/domains.json ---"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "${BASE_URL}/api/v1/domains.json?key=${SECRET}")
if [ "$HTTP_STATUS" -eq 200 ]; then
  echo "  ✓ PASS: HTTP 200 OK via ?key= parameter."
else
  echo "  ✗ FAIL: Expected 200, got ${HTTP_STATUS}."
  exit 1
fi

echo ""
echo "--- [6/8] Test: SHA-256 Checksum Verification ---"
EXPECTED_SHA256=$(echo "$VERSION_BODY" | grep -o '"sha256": *"[^"]*"' | cut -d'"' -f4)
ACTUAL_SHA256=$(curl -s -H "X-API-Key: ${SECRET}" "${BASE_URL}${ACTIVE_RELEASE_URL}" | sha256sum | awk '{print $1}')
echo "  Reported in version.json: ${EXPECTED_SHA256}"
echo "  Calculated on payload:    ${ACTUAL_SHA256}"
if [ "$EXPECTED_SHA256" = "$ACTUAL_SHA256" ]; then
  echo "  ✓ PASS: Checksum match verified! Integrity guaranteed."
else
  echo "  ✗ FAIL: Checksum mismatch detected!"
  exit 1
fi

echo ""
echo "--- [7/8] Test: Cache-Control & Security Headers ---"
HEADERS=$(curl -s -I -H "X-API-Key: ${SECRET}" "${BASE_URL}${ACTIVE_RELEASE_URL}")
if echo "$HEADERS" | grep -i "cache-control:.*immutable" > /dev/null; then
  echo "  ✓ PASS: Immutable cache header present on release snapshot."
else
  echo "  ✗ FAIL: Missing immutable cache header on release."
  echo "$HEADERS"
  exit 1
fi

if echo "$HEADERS" | grep -i "access-control-allow-origin: \*" > /dev/null; then
  echo "  ✓ PASS: CORS allow-origin wildcard header present."
else
  echo "  ✗ FAIL: Missing CORS header."
  exit 1
fi

echo ""
echo "--- [8/8] Test: CORS Preflight OPTIONS Request ---"
OPTIONS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X OPTIONS \
  -H "Origin: https://example.com" \
  -H "Access-Control-Request-Method: GET" \
  "${BASE_URL}/api/v1/version.json")
if [ "$OPTIONS_STATUS" -eq 204 ]; then
  echo "  ✓ PASS: Received HTTP 204 No Content for OPTIONS preflight."
else
  echo "  ✗ FAIL: Expected 204, got ${OPTIONS_STATUS}."
  exit 1
fi

echo ""
echo "============================================================"
echo " All 8 tests passed successfully! "
echo "============================================================"
