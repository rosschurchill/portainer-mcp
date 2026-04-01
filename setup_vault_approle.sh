#!/bin/bash
#
# Setup Vault AppRole for Portainer MCP
# Creates a READ-ONLY AppRole for secure secret injection into Portainer stacks.
#
# Usage: VAULT_TOKEN="your-root-token" bash setup_vault_approle.sh
#

set -e

echo "================================================================"
echo "  Vault AppRole Setup for Portainer MCP (Read-Only)"
echo "================================================================"
echo ""

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://10.0.10.200:8200}"
APPROLE_NAME="portainer-mcp"
POLICY_NAME="portainer-mcp-readonly"
CREDS_DIR="/home/ross/.config/portainer-mcp"
CREDS_FILE="${CREDS_DIR}/vault-approle"
CLAUDE_JSON="/home/ross/.claude.json"
export VAULT_ADDR

# Check for token
if [ -z "$VAULT_TOKEN" ]; then
    read -sp "Enter Vault Root/Admin Token: " VAULT_TOKEN
    echo ""
    export VAULT_TOKEN
fi

echo "Vault Address: $VAULT_ADDR"
echo "AppRole Name:  $APPROLE_NAME"
echo "Policy:        $POLICY_NAME (read-only)"
echo ""

# Test connection
echo "[1/7] Testing Vault connection..."
HEALTH=$(curl -sk "$VAULT_ADDR/v1/sys/health" 2>/dev/null)
if [ -z "$HEALTH" ]; then
    echo "FAIL: Cannot connect to Vault at $VAULT_ADDR"
    exit 1
fi
echo "  OK: Vault is accessible"

# Test token
echo "[2/7] Validating token..."
TOKEN_TEST=$(curl -sk -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/auth/token/lookup-self" 2>/dev/null)
if echo "$TOKEN_TEST" | grep -q "errors"; then
    echo "FAIL: Invalid token"
    exit 1
fi
echo "  OK: Token is valid"
echo ""

# Step 1: Create read-only policy
echo "[3/7] Creating read-only policy '$POLICY_NAME'..."
POLICY_HCL='path "secret/data/*" { capabilities = ["read"] } path "secret/metadata/*" { capabilities = ["read", "list"] } path "secret/metadata" { capabilities = ["list"] }'

POLICY_JSON=$(python3 -c "import json; print(json.dumps({'policy': '''$POLICY_HCL'''}))")

POLICY_RESULT=$(curl -sk -X PUT \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$POLICY_JSON" \
    "$VAULT_ADDR/v1/sys/policies/acl/$POLICY_NAME" 2>&1)

if echo "$POLICY_RESULT" | grep -q "errors"; then
    echo "FAIL: Could not create policy: $POLICY_RESULT"
    exit 1
fi

echo "  OK: Policy created (read + list only)"

# Step 2: Enable AppRole auth (ignore error if already enabled)
echo "[4/7] Enabling AppRole auth method..."
curl -sk -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type": "approle"}' \
    "$VAULT_ADDR/v1/sys/auth/approle" 2>/dev/null || true
echo "  OK: AppRole auth enabled (or already exists)"

# Step 3: Create AppRole
echo "[5/7] Creating AppRole '$APPROLE_NAME'..."
ROLE_CONFIG='{
  "token_ttl": "1h",
  "token_max_ttl": "24h",
  "token_policies": ["'"$POLICY_NAME"'"],
  "bind_secret_id": true,
  "secret_id_ttl": "0"
}'

ROLE_RESULT=$(curl -sk -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$ROLE_CONFIG" \
    "$VAULT_ADDR/v1/auth/approle/role/$APPROLE_NAME" 2>&1)

if echo "$ROLE_RESULT" | grep -q "errors"; then
    echo "FAIL: Could not create AppRole: $ROLE_RESULT"
    exit 1
fi
echo "  OK: AppRole created (1h token TTL, renewable to 24h)"

# Step 4: Get Role ID
echo "[6/7] Retrieving credentials..."
ROLE_ID_RESPONSE=$(curl -sk \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/auth/approle/role/$APPROLE_NAME/role-id")

ROLE_ID=$(echo "$ROLE_ID_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])" 2>&1) || true

if [ -z "$ROLE_ID" ] || echo "$ROLE_ID" | grep -q "Traceback\|Error\|error"; then
    echo "FAIL: Could not retrieve Role ID"
    echo "  Response: $ROLE_ID_RESPONSE"
    exit 1
fi
echo "  Role ID: ${ROLE_ID:0:8}..."

# Generate Secret ID
SECRET_ID_RESPONSE=$(curl -sk -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/auth/approle/role/$APPROLE_NAME/secret-id")

SECRET_ID=$(echo "$SECRET_ID_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])" 2>&1) || true

if [ -z "$SECRET_ID" ] || echo "$SECRET_ID" | grep -q "Traceback\|Error\|error"; then
    echo "FAIL: Could not generate Secret ID"
    echo "  Response: $SECRET_ID_RESPONSE"
    exit 1
fi
echo "  Secret ID: ${SECRET_ID:0:8}..."
echo "  OK: Credentials retrieved"

# Step 5: Test AppRole login
echo "[7/7] Testing AppRole authentication..."
LOGIN_RESPONSE=$(curl -sk -X POST \
    -H "Content-Type: application/json" \
    -d "{\"role_id\": \"$ROLE_ID\", \"secret_id\": \"$SECRET_ID\"}" \
    "$VAULT_ADDR/v1/auth/approle/login")

APP_TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])" 2>/dev/null)

if [ -z "$APP_TOKEN" ]; then
    echo "FAIL: AppRole login failed"
    exit 1
fi
echo "  OK: AppRole login successful"

# Revoke the test token
curl -sk -X PUT \
    -H "X-Vault-Token: $APP_TOKEN" \
    "$VAULT_ADDR/v1/auth/token/revoke-self" >/dev/null 2>&1 || true

# Save credentials
mkdir -p "$CREDS_DIR"
cat > "$CREDS_FILE" << EOF
# Vault AppRole Credentials for Portainer MCP
# Generated: $(date -Iseconds)
# Policy: $POLICY_NAME (read-only)
# DO NOT COMMIT THIS FILE
VAULT_ADDR=$VAULT_ADDR
VAULT_APPROLE_ROLE_ID=$ROLE_ID
VAULT_APPROLE_SECRET_ID=$SECRET_ID
EOF
chmod 600 "$CREDS_FILE"

# Update ~/.claude.json with vault flags
echo ""
echo "Updating Claude Code MCP config..."
python3 << PYEOF
import json

with open("$CLAUDE_JSON") as f:
    data = json.load(f)

portainer = data.get("mcpServers", {}).get("portainer", {})
args = portainer.get("args", [])

# Remove any existing vault flags
clean_args = []
skip_next = False
for i, arg in enumerate(args):
    if skip_next:
        skip_next = False
        continue
    if arg.startswith("-vault-"):
        if i + 1 < len(args) and not args[i + 1].startswith("-"):
            skip_next = True
        continue
    clean_args.append(arg)

# Add vault flags
clean_args.extend([
    "-vault-addr", "$VAULT_ADDR",
    "-vault-role-id", "$ROLE_ID",
    "-vault-secret-id", "$SECRET_ID"
])

portainer["args"] = clean_args
data.setdefault("mcpServers", {})["portainer"] = portainer

with open("$CLAUDE_JSON", "w") as f:
    json.dump(data, f, indent=2)

print("  OK: Vault flags added to ~/.claude.json")
PYEOF

echo ""
echo "================================================================"
echo "  Setup Complete"
echo "================================================================"
echo ""
echo "Credentials saved to: $CREDS_FILE"
echo ""
echo "AppRole Details:"
echo "  Role ID:   $ROLE_ID"
echo "  Secret ID: $SECRET_ID"
echo "  Policy:    $POLICY_NAME (read-only: secret/data/*, secret/metadata/*)"
echo "  Token TTL: 1h (max 24h)"
echo ""
echo "Portainer MCP vault integration is now configured globally."
echo "Restart Claude Code for changes to take effect."
echo ""
echo "Available commands in new sessions:"
echo "  /secure-deploy          - Deploy stacks with Vault secrets"
echo "  listVaultSecrets        - List key names at a Vault path"
echo ""
