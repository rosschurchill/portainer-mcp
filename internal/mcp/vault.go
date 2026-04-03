package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/portainer/portainer-mcp/pkg/portainer/models"
	"github.com/portainer/portainer-mcp/pkg/toolgen"
	"github.com/rs/zerolog/log"
)

// vaultSecretMapping represents a single mapping from a Vault path/key to a
// Portainer environment variable name. Secret values never appear in this struct.
type vaultSecretMapping struct {
	VaultPath string
	VaultKey  string
	EnvName   string
}

// AddVaultFeatures registers vault-related tools with the MCP server.
// Tools are only registered if a secrets provider is configured.
func (s *PortainerMCPServer) AddVaultFeatures() {
	if s.secrets == nil {
		return
	}

	s.addToolIfExists(ToolListVaultSecrets, s.HandleListVaultSecrets())

	if !s.readOnly {
		s.addToolIfExists(ToolCreateLocalStackWithVaultSecrets, s.HandleCreateLocalStackWithVaultSecrets())
		s.addToolIfExists(ToolUpdateLocalStackWithVaultSecrets, s.HandleUpdateLocalStackWithVaultSecrets())
	}
}

// HandleListVaultSecrets returns key names at a Vault path. No values are exposed.
func (s *PortainerMCPServer) HandleListVaultSecrets() server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		parser := toolgen.NewParameterParser(request)

		path, err := parser.GetString("path", true)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid path parameter", err), nil
		}

		keys, err := s.secrets.ListSecrets(path)
		if err != nil {
			return sanitizeVaultError("list secrets", err), nil
		}

		data, err := json.Marshal(keys)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("failed to marshal key list", err), nil
		}

		return mcp.NewToolResultText(string(data)), nil
	}
}

// HandleCreateLocalStackWithVaultSecrets creates a local stack with secrets
// sourced from Vault. Secret values are fetched server-side and never appear
// in the MCP conversation.
func (s *PortainerMCPServer) HandleCreateLocalStackWithVaultSecrets() server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		parser := toolgen.NewParameterParser(request)

		endpointId, err := parser.GetInt("environmentId", true)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid environmentId parameter", err), nil
		}

		name, err := parser.GetString("name", true)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid name parameter", err), nil
		}

		file, err := parser.GetString("file", true)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid file parameter", err), nil
		}

		// Parse non-secret env vars
		plainEnv, err := parseEnvVars(parser)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid env parameter", err), nil
		}

		// Parse vault secret mappings
		mappings, err := parseVaultSecretMappings(parser)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid vaultSecrets parameter", err), nil
		}

		// Resolve secrets from Vault (values stay server-side)
		secretEnv, err := s.resolveVaultSecrets(mappings)
		if err != nil {
			return sanitizeVaultError("resolve secrets", err), nil
		}

		// Combine plain + secret env vars
		allEnv := append(plainEnv, secretEnv...)

		id, err := s.cli.CreateLocalStack(endpointId, name, file, allEnv)

		// Zero secret values in memory immediately after use
		for i := range secretEnv {
			secretEnv[i].Value = ""
		}

		if err != nil {
			return mcp.NewToolResultErrorFromErr("error creating local stack", err), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf(
			"Local stack created successfully with ID: %d. %d secrets injected from Vault.",
			id, len(mappings))), nil
	}
}

// HandleUpdateLocalStackWithVaultSecrets updates a local stack with secrets
// sourced from Vault.
func (s *PortainerMCPServer) HandleUpdateLocalStackWithVaultSecrets() server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		parser := toolgen.NewParameterParser(request)

		id, err := parser.GetInt("id", true)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid id parameter", err), nil
		}

		endpointId, err := parser.GetInt("environmentId", true)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid environmentId parameter", err), nil
		}

		file, err := parser.GetString("file", true)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid file parameter", err), nil
		}

		plainEnv, err := parseEnvVars(parser)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid env parameter", err), nil
		}

		mappings, err := parseVaultSecretMappings(parser)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid vaultSecrets parameter", err), nil
		}

		prune, err := parser.GetBoolean("prune", false)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid prune parameter", err), nil
		}

		pullImage, err := parser.GetBoolean("pullImage", false)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("invalid pullImage parameter", err), nil
		}

		secretEnv, err := s.resolveVaultSecrets(mappings)
		if err != nil {
			return sanitizeVaultError("resolve secrets", err), nil
		}

		allEnv := append(plainEnv, secretEnv...)

		updateErr := s.cli.UpdateLocalStack(id, endpointId, file, allEnv, prune, pullImage)

		// Zero secret values immediately after use
		for i := range secretEnv {
			secretEnv[i].Value = ""
		}

		if updateErr != nil {
			return mcp.NewToolResultErrorFromErr("failed to update local stack", updateErr), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf(
			"Local stack updated successfully. %d secrets injected from Vault.",
			len(mappings))), nil
	}
}

// resolveVaultSecrets fetches secrets from the provider and builds env vars.
// It groups by path to minimize Vault API calls.
func (s *PortainerMCPServer) resolveVaultSecrets(mappings []vaultSecretMapping) ([]models.LocalStackEnvVar, error) {
	if len(mappings) == 0 {
		return nil, nil
	}

	// Group by vault path to minimize API calls
	pathGroups := make(map[string][]vaultSecretMapping)
	for _, m := range mappings {
		pathGroups[m.VaultPath] = append(pathGroups[m.VaultPath], m)
	}

	var envVars []models.LocalStackEnvVar

	for path, entries := range pathGroups {
		result, err := s.secrets.GetSecrets(path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch secrets from vault path %s: %w", path, err)
		}

		for _, entry := range entries {
			sv, ok := result.Secrets[entry.VaultKey]
			if !ok {
				result.Clear()
				return nil, fmt.Errorf("key %q not found at vault path %s", entry.VaultKey, path)
			}
			envVars = append(envVars, models.LocalStackEnvVar{
				Name:  entry.EnvName,
				Value: string(sv.Value),
			})
		}

		result.Clear()
	}

	return envVars, nil
}

// parseVaultSecretMappings extracts vault secret mappings from the request.
// Accepts both camelCase (vaultSecrets) and snake_case (vault_secrets) parameter
// names, since LLMs frequently use snake_case despite the schema specifying camelCase.
func parseVaultSecretMappings(parser *toolgen.ParameterParser) ([]vaultSecretMapping, error) {
	rawMappings, err := parser.GetArrayOfObjects("vaultSecrets", false)
	if err != nil {
		return nil, err
	}
	if len(rawMappings) == 0 {
		// Try snake_case fallback
		rawMappings, err = parser.GetArrayOfObjects("vault_secrets", true)
		if err != nil {
			return nil, fmt.Errorf("vaultSecrets is required")
		}
	}

	mappings := make([]vaultSecretMapping, 0, len(rawMappings))
	for _, item := range rawMappings {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid vaultSecrets entry: expected object")
		}

		vaultPath := stringFromMap(obj, "vaultPath", "vault_path")
		vaultKey := stringFromMap(obj, "vaultKey", "vault_key")
		envName := stringFromMap(obj, "envName", "env_name", "name")

		if vaultPath == "" || vaultKey == "" || envName == "" {
			return nil, fmt.Errorf("vaultSecrets entries require 'vaultPath', 'vaultKey', and 'envName' fields")
		}

		mappings = append(mappings, vaultSecretMapping{
			VaultPath: vaultPath,
			VaultKey:  vaultKey,
			EnvName:   envName,
		})
	}

	return mappings, nil
}

// stringFromMap tries multiple keys in order and returns the first non-empty string value.
func stringFromMap(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := obj[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// sanitizeVaultError returns a safe error message for MCP responses.
// The original error is logged but not exposed to the LLM.
func sanitizeVaultError(operation string, err error) *mcp.CallToolResult {
	log.Error().Err(err).Str("operation", operation).Msg("vault operation failed")
	return mcp.NewToolResultError(
		fmt.Sprintf("Vault %s failed - check server logs for details", operation))
}
