#!/usr/bin/env bash
# =============================================================================
# test-jwt-login.sh - End-to-end JWT login verification for openclaw operator
# =============================================================================
#
# This script tests the complete JWT authentication flow:
#   1. Keycloak ROPC grant → obtain JWT access token
#   2. Decode and display JWT claims (for debugging)
#   3. Matrix login via synapse-token-authenticator
#
# USAGE:
#   ./test-jwt-login.sh [OPTIONS]
#
# OPTIONS:
#   -t, --login-type TYPE   JWT login type (default: com.famedly.login.token.oauth)
#                           Options: com.famedly.login.token.oauth, com.famedly.login.token, org.matrix.login.jwt
#   -m, --auth-method TYPE  Auth method (default: jwt)
#                           Options: password, jwt
#   -s, --skip-decode       Skip JWT decoding step (step 2)
#   -v, --verbose           Show detailed output including full responses
#   -h, --help              Show this help message
#
# REQUIRED ENVIRONMENT VARIABLES:
#   KEYCLOAK_URL          - Keycloak server URL (e.g., https://keycloak.example.com)
#   KEYCLOAK_REALM        - Keycloak realm name (e.g., matrix)
#   KEYCLOAK_CLIENT_ID    - OIDC client ID with ROPC enabled
#   MATRIX_USER           - Bot username (localpart, e.g., clawdbot-operator)
#   MATRIX_PASSWORD       - Bot password (Keycloak user password)
#   MATRIX_HOMESERVER     - Matrix homeserver URL (e.g., https://matrix.example.com)
#   ALLOWED_USERS         - Comma-separated Matrix user IDs (for config validation)
#
# OPTIONAL ENVIRONMENT VARIABLES:
#   KEYCLOAK_CLIENT_SECRET - Client secret (empty for public clients)
#   JWT_LOGIN_TYPE         - Login type (default: com.famedly.login.token.oauth)
#                            Options: com.famedly.login.token.oauth, com.famedly.login.token, org.matrix.login.jwt
#   VERBOSE                - Set to "true" for detailed output
#
# EXIT CODES:
#   0 - All tests passed
#   1 - Configuration error (missing env vars)
#   2 - Keycloak token request failed
#   3 - JWT decode failed
#   4 - Matrix login failed
#
# =============================================================================
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Defaults
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-}"
JWT_LOGIN_TYPE="${JWT_LOGIN_TYPE:-com.famedly.login.token.oauth}"
AUTH_METHOD="${AUTH_METHOD:-jwt}"
VERBOSE="${VERBOSE:-false}"
SKIP_DECODE=false

# =============================================================================
# Helper functions
# =============================================================================

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "\n${BLUE}=== $* ===${NC}"; }

# Base64 URL decode (handles padding correctly)
base64url_decode() {
    local input="$1"
    # Replace URL-safe chars with standard base64 chars
    local std="${input//-/+}"
    std="${std//_/\/}"
    # Add padding based on length mod 4
    local pad=$((4 - ${#std} % 4))
    if [[ $pad -lt 4 ]]; then
        std="${std}$(printf '=%.0s' $(seq 1 $pad))"
    fi
    echo "$std" | base64 -d 2>/dev/null || echo "(decode failed)"
}

# =============================================================================
# Parse command-line arguments
# =============================================================================
show_help() {
    cat << 'HELP'
test-jwt-login.sh - End-to-end JWT login verification

USAGE:
  ./test-jwt-login.sh [OPTIONS]

OPTIONS:
  -t, --login-type TYPE   JWT login type (default: com.famedly.login.token.oauth)
                          Options:
                            com.famedly.login.token.oauth - synapse-token-authenticator oauth: (JWKS)
                            com.famedly.login.token       - synapse-token-authenticator jwt: (symmetric)
                            org.matrix.login.jwt          - native Synapse JWT (public key)
  -m, --auth-method TYPE  Auth method (default: jwt)
                          Options:
                            password - direct Matrix login (skip Keycloak)
                            jwt      - Keycloak ROPC → JWT → Synapse
  -s, --skip-decode       Skip JWT decoding step (step 2)
  -v, --verbose           Show detailed output
  -h, --help              Show this help message

EXAMPLES:
  # Test with default settings (jwt + com.famedly.login.token.oauth for JWKS)
  ./test-jwt-login.sh

  # Test symmetric JWT (synapse-token-authenticator jwt: config)
  ./test-jwt-login.sh --login-type com.famedly.login.token

  # Test native Synapse JWT
  ./test-jwt-login.sh --login-type org.matrix.login.jwt

  # Test password login (no JWT, skip Keycloak)
  ./test-jwt-login.sh --auth-method password

  # Verbose mode with native JWT
  ./test-jwt-login.sh -v -t org.matrix.login.jwt
HELP
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--login-type)
            JWT_LOGIN_TYPE="$2"
            shift 2
            ;;
        -m|--auth-method)
            AUTH_METHOD="$2"
            shift 2
            ;;
        -s|--skip-decode)
            SKIP_DECODE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate login type
if [[ "$AUTH_METHOD" == "jwt" ]]; then
    case "$JWT_LOGIN_TYPE" in
        com.famedly.login.token.oauth|com.famedly.login.token|org.matrix.login.jwt)
            ;;
        *)
            log_error "Invalid login type: $JWT_LOGIN_TYPE"
            echo "Valid options: com.famedly.login.token.oauth, com.famedly.login.token, org.matrix.login.jwt"
            exit 1
            ;;
    esac
fi

# Validate auth method
case "$AUTH_METHOD" in
    password|jwt)
        ;;
    *)
        log_error "Invalid auth method: $AUTH_METHOD"
        echo "Valid options: password, jwt"
        exit 1
        ;;
esac

# =============================================================================
# Step 0: Validate configuration
# =============================================================================
log_step "Step 0: Validating configuration"

MISSING_VARS=()

# Always required
[[ -z "${MATRIX_USER:-}" ]] && MISSING_VARS+=("MATRIX_USER")
[[ -z "${MATRIX_PASSWORD:-}" ]] && MISSING_VARS+=("MATRIX_PASSWORD")
[[ -z "${MATRIX_HOMESERVER:-}" ]] && MISSING_VARS+=("MATRIX_HOMESERVER")
[[ -z "${ALLOWED_USERS:-}" ]] && MISSING_VARS+=("ALLOWED_USERS")

# Required only for JWT auth method
if [[ "$AUTH_METHOD" == "jwt" ]]; then
    [[ -z "${KEYCLOAK_URL:-}" ]] && MISSING_VARS+=("KEYCLOAK_URL")
    [[ -z "${KEYCLOAK_REALM:-}" ]] && MISSING_VARS+=("KEYCLOAK_REALM")
    [[ -z "${KEYCLOAK_CLIENT_ID:-}" ]] && MISSING_VARS+=("KEYCLOAK_CLIENT_ID")
fi

if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
    log_error "Missing required environment variables:"
    for var in "${MISSING_VARS[@]}"; do
        echo "  - $var"
    done
    echo ""
    echo "Example usage:"
    echo "  KEYCLOAK_URL=https://keycloak.example.com \\"
    echo "  KEYCLOAK_REALM=matrix \\"
    echo "  KEYCLOAK_CLIENT_ID=synapse-jwt-client \\"
    echo "  KEYCLOAK_CLIENT_SECRET=your-secret \\"
    echo "  MATRIX_USER=clawdbot-operator \\"
    echo "  MATRIX_PASSWORD=your-password \\"
    echo "  MATRIX_HOMESERVER=https://matrix.example.com \\"
    echo "  ALLOWED_USERS=@admin:matrix.example.com \\"
    echo "  ./test-jwt-login.sh"
    exit 1
fi

log_info "Configuration:"
echo "  AUTH_METHOD:       ${AUTH_METHOD}"
echo "  MATRIX_USER:       ${MATRIX_USER}"
echo "  MATRIX_HOMESERVER: ${MATRIX_HOMESERVER}"
if [[ "$AUTH_METHOD" == "jwt" ]]; then
    echo "  JWT_LOGIN_TYPE:    ${JWT_LOGIN_TYPE}"
    echo "  KEYCLOAK_URL:      ${KEYCLOAK_URL}"
    echo "  KEYCLOAK_REALM:    ${KEYCLOAK_REALM}"
    echo "  KEYCLOAK_CLIENT_ID: ${KEYCLOAK_CLIENT_ID}"
    echo "  KEYCLOAK_CLIENT_SECRET: ${KEYCLOAK_CLIENT_SECRET:+(set)}"
fi
log_ok "Configuration validated"

# =============================================================================
# Step 1: Obtain JWT from Keycloak via ROPC (JWT auth only)
# =============================================================================
if [[ "$AUTH_METHOD" == "jwt" ]]; then
    log_step "Step 1: Obtaining JWT from Keycloak (ROPC grant)"

    TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
    log_info "Token endpoint: ${TOKEN_ENDPOINT}"

    # Build request data
    REQUEST_DATA="grant_type=password&client_id=${KEYCLOAK_CLIENT_ID}&username=${MATRIX_USER}&password=${MATRIX_PASSWORD}"
    if [[ -n "$KEYCLOAK_CLIENT_SECRET" ]]; then
        REQUEST_DATA="${REQUEST_DATA}&client_secret=${KEYCLOAK_CLIENT_SECRET}"
    fi

    # Make the request
    log_info "Requesting access token..."
    HTTP_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${TOKEN_ENDPOINT}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "${REQUEST_DATA}")

    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed '$d')
    HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)

    if [[ "$HTTP_CODE" != "200" ]]; then
        log_error "Keycloak token request failed (HTTP ${HTTP_CODE})"
        if [[ "$VERBOSE" == "true" ]]; then
            echo "Response body:"
            echo "$HTTP_BODY" | jq . 2>/dev/null || echo "$HTTP_BODY"
        else
            ERROR_DESC=$(echo "$HTTP_BODY" | jq -r '.error_description // .error // "Unknown error"' 2>/dev/null)
            echo "  Error: ${ERROR_DESC}"
        fi
        echo ""
        echo "Common issues:"
        echo "  - Invalid credentials (wrong username/password)"
        echo "  - ROPC not enabled (directAccessGrantsEnabled: false)"
        echo "  - Wrong client secret"
        echo "  - User not in realm"
        exit 2
    fi

    ACCESS_TOKEN=$(echo "$HTTP_BODY" | jq -r '.access_token')
    TOKEN_TYPE=$(echo "$HTTP_BODY" | jq -r '.token_type')
    EXPIRES_IN=$(echo "$HTTP_BODY" | jq -r '.expires_in')

    if [[ -z "$ACCESS_TOKEN" || "$ACCESS_TOKEN" == "null" ]]; then
        log_error "No access_token in Keycloak response"
        exit 2
    fi

    log_ok "JWT obtained successfully"
    echo "  Token type: ${TOKEN_TYPE}"
    echo "  Expires in: ${EXPIRES_IN}s"
    echo "  Token length: ${#ACCESS_TOKEN} chars"

    # =========================================================================
    # Step 2: Decode and display JWT claims
    # =========================================================================
    if [[ "$SKIP_DECODE" != "true" ]]; then
        log_step "Step 2: Decoding JWT claims"

        # Split JWT into parts
        IFS='.' read -r JWT_HEADER JWT_PAYLOAD JWT_SIGNATURE <<< "$ACCESS_TOKEN"

        log_info "JWT Header:"
        HEADER_JSON=$(base64url_decode "$JWT_HEADER")
        echo "$HEADER_JSON" | jq . 2>/dev/null || echo "$HEADER_JSON"

        log_info "JWT Payload (claims):"
        PAYLOAD_JSON=$(base64url_decode "$JWT_PAYLOAD")
        echo "$PAYLOAD_JSON" | jq . 2>/dev/null || echo "$PAYLOAD_JSON"

        # Extract key claims for validation
        CLAIM_SUB=$(echo "$PAYLOAD_JSON" | jq -r '.sub // "(missing)"')
        CLAIM_PREFERRED_USERNAME=$(echo "$PAYLOAD_JSON" | jq -r '.preferred_username // "(missing)"')
        CLAIM_ISS=$(echo "$PAYLOAD_JSON" | jq -r '.iss // "(missing)"')
        CLAIM_AUD=$(echo "$PAYLOAD_JSON" | jq -r '.aud // "(missing)"')
        CLAIM_EXP=$(echo "$PAYLOAD_JSON" | jq -r '.exp // 0')

        log_info "Key claims:"
        echo "  sub (subject):          ${CLAIM_SUB}"
        echo "  preferred_username:     ${CLAIM_PREFERRED_USERNAME}"
        echo "  iss (issuer):           ${CLAIM_ISS}"
        echo "  aud (audience):         ${CLAIM_AUD}"

        # Check expiry
        NOW=$(date +%s)
        if [[ "$CLAIM_EXP" -gt 0 ]]; then
            EXP_DATE=$(date -d "@${CLAIM_EXP}" 2>/dev/null || date -r "${CLAIM_EXP}" 2>/dev/null || echo "unknown")
            REMAINING=$((CLAIM_EXP - NOW))
            echo "  exp (expiry):           ${EXP_DATE} (${REMAINING}s remaining)"
            if [[ $REMAINING -lt 0 ]]; then
                log_warn "Token has expired!"
            fi
        fi

        # Validate username matches
        if [[ "$CLAIM_PREFERRED_USERNAME" != "$MATRIX_USER" ]]; then
            log_warn "preferred_username '${CLAIM_PREFERRED_USERNAME}' does not match MATRIX_USER '${MATRIX_USER}'"
            echo "  This may cause login to fail if Synapse uses preferred_username for localpart"
        fi

        log_ok "JWT decoded successfully"
    else
        log_step "Step 2: Skipped (--skip-decode)"
    fi

else
    # Password auth - skip JWT steps
    log_step "Step 1: Skipped (AUTH_METHOD=password, no Keycloak)"
    log_step "Step 2: Skipped (AUTH_METHOD=password, no JWT to decode)"
fi

# =============================================================================
# Step 3: Test Matrix login via connectortest
# =============================================================================
log_step "Step 3: Testing Matrix login via connectortest CLI"

log_info "Running: openclaw-k8s-toggle-operator-conntest"
if [[ "$AUTH_METHOD" == "jwt" ]]; then
    log_info "Auth method: jwt (login_type: ${JWT_LOGIN_TYPE})"
else
    log_info "Auth method: password (direct Matrix login)"
fi

# Export required env vars for connectortest
export AUTH_METHOD
export MATRIX_USER
export MATRIX_PASSWORD
export MATRIX_HOMESERVER
export ALLOWED_USERS
if [[ "$AUTH_METHOD" == "jwt" ]]; then
    export KEYCLOAK_URL
    export KEYCLOAK_REALM
    export KEYCLOAK_CLIENT_ID
    export KEYCLOAK_CLIENT_SECRET
    export JWT_LOGIN_TYPE
fi

# Determine connectortest command (prefer installed script, fall back to python -c)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH:-}"

if [[ -x "${SCRIPT_DIR}/.venv/bin/openclaw-k8s-toggle-operator-conntest" ]]; then
    CONNTEST_CMD="${SCRIPT_DIR}/.venv/bin/openclaw-k8s-toggle-operator-conntest"
elif command -v openclaw-k8s-toggle-operator-conntest &>/dev/null; then
    CONNTEST_CMD="openclaw-k8s-toggle-operator-conntest"
elif [[ -x "${SCRIPT_DIR}/.venv/bin/python" ]]; then
    # Not installed, but venv exists - run via python -c
    CONNTEST_CMD="${SCRIPT_DIR}/.venv/bin/python -c 'from openclaw_k8s_toggle_operator.__main__ import connectortest; connectortest()'"
elif command -v python3 &>/dev/null; then
    CONNTEST_CMD="python3 -c 'from openclaw_k8s_toggle_operator.__main__ import connectortest; connectortest()'"
else
    log_error "Cannot find python or openclaw-k8s-toggle-operator-conntest"
    echo "  Install with: pip install -e . (in virtualenv)"
    echo "  Or ensure python3 is available"
    exit 4
fi

# Run connectortest
echo ""
if eval "$CONNTEST_CMD"; then
    echo ""
    log_ok "Matrix login successful!"
    echo ""
    echo "=========================================="
    echo "  ALL TESTS PASSED"
    echo "=========================================="
    echo ""
    if [[ "$AUTH_METHOD" == "jwt" ]]; then
        echo "The JWT authentication flow is working correctly:"
        echo "  1. ✓ Keycloak ROPC grant succeeded"
        echo "  2. ✓ JWT claims are valid"
        echo "  3. ✓ Matrix login via ${JWT_LOGIN_TYPE} succeeded"
    else
        echo "Password authentication is working correctly:"
        echo "  1. ✓ Direct Matrix login succeeded"
    fi
    exit 0
else
    echo ""
    log_error "Matrix login failed"
    echo ""
    if [[ "$AUTH_METHOD" == "jwt" ]]; then
        echo "Common issues for JWT auth:"
        echo "  - Synapse not configured for JWT login type '${JWT_LOGIN_TYPE}'"
        echo "  - JWKS endpoint unreachable from Synapse"
        echo "  - Username mismatch (preferred_username vs localpart)"
        echo "  - Token signature validation failed"
        echo ""
        echo "For ${JWT_LOGIN_TYPE}, ensure synapse-token-authenticator is configured with:"
        if [[ "$JWT_LOGIN_TYPE" == "com.famedly.login.token" ]]; then
            echo "  oauth:"
            echo "    jwt_validation:"
            echo "      jwks_endpoint: ${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
            echo "      localpart_path: preferred_username"
        else
            echo "  jwt_config:"
            echo "    enabled: true"
            echo "    algorithm: RS256"
            echo "    subject_claim: preferred_username"
            echo "    issuer: ${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}"
        fi
    else
        echo "Common issues for password auth:"
        echo "  - Wrong password"
        echo "  - User doesn't exist on homeserver"
        echo "  - Homeserver unreachable"
    fi
    exit 4
fi
