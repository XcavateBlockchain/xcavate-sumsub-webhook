#!/usr/bin/env bash
#
# One-time setup: flip `sumsub_sharing_enabled = true` on the tgbp.io client
# account that TGBP_API_KEY belongs to.
#
# Without this flag, the webhook's customer-create call (POST /api/v1/customers
# with a sumsub_share_token) is rejected with 400 sumsub_sharing_not_enabled.
#
# Usage:
#   ./scripts/enable-sumsub-sharing.sh                       # uses $TGBP_API_KEY
#   ./scripts/enable-sumsub-sharing.sh <api-key>             # key as 1st arg
#   TGBP_API_BASE_URL=https://sandbox.tgbp.io ./scripts/enable-sumsub-sharing.sh
#
# The key must be the SAME key the webhook uses (TGBP_API_KEY in .env):
# /api/v1/clients/me operates on the account that key is scoped to.
# Safe to re-run — it just sets the same value again.

set -euo pipefail

# --- config -----------------------------------------------------------------

TGBP_API_KEY="${1:-${TGBP_API_KEY:-}}"
TGBP_API_BASE_URL="${TGBP_API_BASE_URL:-https://sandbox.tgbp.io}"

if [[ -z "$TGBP_API_KEY" ]]; then
  echo "ERROR: no API key provided." >&2
  echo "Set TGBP_API_KEY in the environment (e.g. 'source .env') or pass it as the first argument:" >&2
  echo "  TGBP_API_KEY=... $0" >&2
  echo "  $0 <api-key>" >&2
  exit 1
fi

# strip any trailing slashes from the base URL
TGBP_API_BASE_URL="${TGBP_API_BASE_URL%/}"
ME_PATH="$TGBP_API_BASE_URL/api/v1/clients/me"

# --- call -------------------------------------------------------------------

echo "PATCHing sumsub_sharing_enabled=true on $ME_PATH"
echo

BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

if ! http_status=$(
  curl -sS -X PATCH "$ME_PATH" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $TGBP_API_KEY" \
    -d '{"sumsub_sharing_enabled": true}' \
    -w '%{http_code}' \
    -o "$BODY_FILE"
); then
  echo "ERROR: curl could not reach $ME_PATH (network-level failure — DNS, egress, or a WAF reset)." >&2
  if [ -s "$BODY_FILE" ]; then
    echo "Partial response:" >&2
    cat "$BODY_FILE" >&2
  fi
  exit 1
fi

echo "Response body:"
cat "$BODY_FILE"
echo
echo "HTTP status: $http_status"

# --- exit code + hints ------------------------------------------------------

if grep -qi 'cloudflare' "$BODY_FILE"; then
  echo
  echo "BLOCKED: that is a Cloudflare WAF block page, not an API response." >&2
  echo "Your request never reached the tgbp.io API (the x-api-key was never evaluated)." >&2
  echo "This source IP is blocked by tgbp.io's Cloudflare rules — ask the tgbp.io team" >&2
  echo "to allow this IP for /api/ calls (include the Cloudflare Ray ID from the page)." >&2
  exit 1
fi

case "$http_status" in
  2*)
    echo
    echo "OK: sumsub_sharing_enabled is now enabled on this client account."
    echo "The webhook can now register tgbp.io customers — no webhook changes needed."
    ;;
  401|403)
    echo
    echo "FAILED: 401/403 — the API key is not accepted for this endpoint." >&2
    echo "Check that TGBP_API_KEY is the client-account key (the same key the webhook uses)," >&2
    echo "and that it has not been rotated." >&2
    exit 1
    ;;
  404)
    echo
    echo "FAILED: 404 — the endpoint was not found." >&2
    echo "Check TGBP_API_BASE_URL (currently: $TGBP_API_BASE_URL) — it should be the tgbp.io host" >&2
    echo "with no trailing path." >&2
    exit 1
    ;;
  *)
    echo
    echo "FAILED: unexpected HTTP $http_status. See the response body above for details." >&2
    exit 1
    ;;
esac
