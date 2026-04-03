---
description: Deploy or update a Portainer stack with secrets from HashiCorp Vault — values never appear in the conversation
argument-hint: "[stack-name or 'new'] [vault-path]"
allowed-tools: ["mcp__portainer__listLocalStacks", "mcp__portainer__getLocalStackFile", "mcp__portainer__listEnvironments", "mcp__portainer__listVaultSecrets", "mcp__portainer__createLocalStackWithVaultSecrets", "mcp__portainer__updateLocalStackWithVaultSecrets"]
---

# Secure Stack Deployment via Vault

Deploy or update a Docker Compose stack on Portainer with secrets injected from HashiCorp Vault. **Secret values must NEVER appear in this conversation — only key names and vault paths.**

**Arguments:** $ARGUMENTS

## Core Principles

- **Zero secret exposure**: Never display, request, or log secret values. Only key names and vault paths are safe to show.
- **Vault-first**: Always use `*WithVaultSecrets` tool variants. Never fall back to `createLocalStack` or `updateLocalStack` with inline secrets.
- **Confirm before deploying**: Show the user the full mapping and compose file before executing.
- **Fail safe**: If Vault is unavailable or a key is missing, stop and guide the user — never accept inline secrets as a workaround.

---

## Phase 1: Pre-flight

**Goal**: Verify Vault integration is available and understand the request

**Actions**:
1. Check if `listVaultSecrets` is available in your MCP tools
   - **If NOT available**, STOP and tell the user:
     > "Vault integration is not configured. Add `-vault-addr`, `-vault-role-id`, and `-vault-secret-id` to the portainer MCP config in `~/.claude.json`. See the portainer-mcp README for AppRole setup."
   - If available, proceed
2. List environments using `listEnvironments` to show available targets
3. If user provided a stack name in arguments, search for it. Otherwise ask:
   - New stack or updating existing?
   - Stack name (or ID for updates)?
   - Target environment?

---

## Phase 2: Discovery

**Goal**: Identify the stack state and available Vault secrets

**Actions**:
1. **For updates**: Call `listLocalStacks` to find the stack ID and environment ID. Call `getLocalStackFile` to fetch the current compose file.
2. **For new stacks**: Ask user for the compose file content or help them write one.
3. **Discover secrets**: Ask user for the Vault path (e.g., `secret/chimera`, `secret/production/myapp`), or use path from arguments. Call `listVaultSecrets` with that path.
4. Present the available key names to the user (never values).

---

## Phase 3: Mapping

**Goal**: Build the vault-to-env-var mapping with user confirmation

**Actions**:
1. **Analyse the compose file** to identify which `${VAR_NAME}` references need secret values
2. **Match vault keys to env vars**: Propose a mapping table:

   | Vault Key | Env Var | Source |
   |-----------|---------|--------|
   | `db_password` | `POSTGRES_PASSWORD` | Vault |
   | `api_key` | `API_KEY` | Vault |
   | `LOG_LEVEL` | `LOG_LEVEL` | Plain (value: `info`) |

3. **Separate secrets from plain config**: Non-secret env vars (timezone, log level, feature flags) go in the `env` parameter directly
4. **Present mapping to user and wait for confirmation** before proceeding

**CRITICAL**: Do NOT proceed to deployment without explicit user approval of the mapping.

---

## Phase 4: Deployment

**Goal**: Deploy the stack with secrets injected server-side

**Actions**:
1. Build the `vaultSecrets` array:
   ```json
   [
     {"vaultPath": "secret/chimera", "vaultKey": "db_password", "envName": "POSTGRES_PASSWORD"},
     {"vaultPath": "secret/chimera", "vaultKey": "api_key", "envName": "API_KEY"}
   ]
   ```
2. Build the `env` array for non-secret vars:
   ```json
   [{"name": "LOG_LEVEL", "value": "info"}]
   ```
3. Call the appropriate tool:
   - **New**: `createLocalStackWithVaultSecrets(environmentId, name, file, vaultSecrets, env)`
   - **Update**: `updateLocalStackWithVaultSecrets(id, environmentId, file, vaultSecrets, env, prune, pullImage)`
4. Report result: "Stack deployed/updated. X secrets injected from Vault."

---

## Phase 5: Verification

**Goal**: Confirm the deployment succeeded

**Actions**:
1. Call `listLocalStacks` to verify the stack appears with correct status
2. Summarize to the user:
   - Stack name and ID
   - Environment deployed to
   - Number of secrets injected
   - Number of plain env vars set
   - Stack status (active/inactive)

---

## Error Handling

| Scenario | Action |
|----------|--------|
| Vault tools not available | Stop. Guide user to configure vault flags. |
| Vault key not found | Stop. Tell user to add the key to Vault first. Do NOT accept inline value. |
| User pastes a secret value | **Immediately stop.** Say: "I can see you've pasted a secret value. Please add this to Vault instead and I'll reference it by key name." |
| Vault connection fails | Report the failure. Suggest checking vault-addr and AppRole credentials. |
| Stack creation fails | Report the Portainer error. Do NOT retry with inline secrets. |
| Multiple vault paths needed | Support it — group mappings by path, the tool handles multiple paths efficiently. |

---

## Usage Examples

**Update existing stack with secrets from vault:**
```
/secure-deploy chimera secret/chimera
```

**New stack deployment:**
```
/secure-deploy new secret/production/myapp
```

**Interactive (no arguments):**
```
/secure-deploy
```

---

## Security Reminders

- The `listVaultSecrets` tool returns **only key names** — it is always safe to display
- The `*WithVaultSecrets` tools return "X secrets injected" — **never the values**
- Error messages from Vault are sanitized — raw errors go to server logs only
- If you are unsure whether something is a secret, **treat it as one**
- Common secrets: anything with PASSWORD, TOKEN, KEY, SECRET, CREDENTIAL in the name
