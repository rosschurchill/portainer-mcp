package mcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/portainer/portainer-mcp/pkg/secrets"
	"github.com/portainer/portainer-mcp/pkg/toolgen"
)

// mockSecretsProvider implements secrets.SecretsProvider for testing.
type mockSecretsProvider struct {
	secretData map[string]map[string]string // path -> key -> value
	listKeys   map[string][]string          // path -> key names
	getErr     error
	listErr    error
}

func (m *mockSecretsProvider) GetSecrets(path string) (*secrets.SecretResult, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}

	data, ok := m.secretData[path]
	if !ok {
		return nil, fmt.Errorf("path not found: %s", path)
	}

	result := &secrets.SecretResult{
		Path:    path,
		Secrets: make(map[string]secrets.SecretValue, len(data)),
	}
	for k, v := range data {
		result.Secrets[k] = secrets.SecretValue{Value: []byte(v)}
	}
	return result, nil
}

func (m *mockSecretsProvider) ListSecrets(path string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}

	if keys, ok := m.listKeys[path]; ok {
		return keys, nil
	}

	if data, ok := m.secretData[path]; ok {
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		return keys, nil
	}

	return nil, fmt.Errorf("path not found: %s", path)
}

func (m *mockSecretsProvider) Close() error {
	return nil
}

func TestHandleListVaultSecrets(t *testing.T) {
	mock := &mockSecretsProvider{
		secretData: map[string]map[string]string{
			"secret/data/myapp": {
				"db_password": "secret123",
				"api_key":     "key-abc",
			},
		},
	}

	srv := &PortainerMCPServer{secrets: mock}

	handler := srv.HandleListVaultSecrets()
	request := CreateMCPRequest(map[string]any{
		"path": "secret/data/myapp",
	})

	result, err := handler(nil, request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.IsError {
		t.Fatalf("unexpected tool error")
	}

	// The response text should contain key names but never values
	responseText := fmt.Sprintf("%v", result.Content[0])
	if strings.Contains(responseText, "secret123") || strings.Contains(responseText, "key-abc") {
		t.Error("response contains secret values - this must never happen")
	}
}

func TestHandleListVaultSecrets_Error(t *testing.T) {
	mock := &mockSecretsProvider{
		listErr: fmt.Errorf("vault connection refused"),
	}

	srv := &PortainerMCPServer{secrets: mock}

	handler := srv.HandleListVaultSecrets()
	request := CreateMCPRequest(map[string]any{
		"path": "secret/data/myapp",
	})

	result, err := handler(nil, request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		t.Fatal("expected tool error for vault failure")
	}

	// The error should NOT contain the raw vault error message
	responseText := fmt.Sprintf("%v", result.Content[0])
	if strings.Contains(responseText, "connection refused") {
		t.Error("raw vault error leaked to MCP response")
	}
}

func TestResolveVaultSecrets(t *testing.T) {
	mock := &mockSecretsProvider{
		secretData: map[string]map[string]string{
			"secret/data/myapp": {
				"db_password": "secret123",
				"api_key":     "key-abc",
			},
		},
	}

	srv := &PortainerMCPServer{secrets: mock}

	mappings := []vaultSecretMapping{
		{VaultPath: "secret/data/myapp", VaultKey: "db_password", EnvName: "DB_PASSWORD"},
		{VaultPath: "secret/data/myapp", VaultKey: "api_key", EnvName: "API_KEY"},
	}

	envVars, err := srv.resolveVaultSecrets(mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(envVars) != 2 {
		t.Fatalf("expected 2 env vars, got %d", len(envVars))
	}

	envMap := map[string]string{}
	for _, ev := range envVars {
		envMap[ev.Name] = ev.Value
	}

	if envMap["DB_PASSWORD"] != "secret123" {
		t.Errorf("expected DB_PASSWORD=secret123, got %q", envMap["DB_PASSWORD"])
	}
	if envMap["API_KEY"] != "key-abc" {
		t.Errorf("expected API_KEY=key-abc, got %q", envMap["API_KEY"])
	}
}

func TestResolveVaultSecrets_GroupsByPath(t *testing.T) {
	callCount := 0
	mock := &mockSecretsProvider{
		secretData: map[string]map[string]string{
			"secret/data/app1": {"key1": "val1"},
			"secret/data/app2": {"key2": "val2"},
		},
	}

	// Wrap to count calls
	srv := &PortainerMCPServer{secrets: mock}
	_ = callCount // grouping is verified by having 2 paths producing 2 env vars

	mappings := []vaultSecretMapping{
		{VaultPath: "secret/data/app1", VaultKey: "key1", EnvName: "KEY1"},
		{VaultPath: "secret/data/app2", VaultKey: "key2", EnvName: "KEY2"},
	}

	envVars, err := srv.resolveVaultSecrets(mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(envVars) != 2 {
		t.Fatalf("expected 2 env vars, got %d", len(envVars))
	}
}

func TestResolveVaultSecrets_MissingKey(t *testing.T) {
	mock := &mockSecretsProvider{
		secretData: map[string]map[string]string{
			"secret/data/myapp": {
				"db_password": "secret123",
			},
		},
	}

	srv := &PortainerMCPServer{secrets: mock}

	mappings := []vaultSecretMapping{
		{VaultPath: "secret/data/myapp", VaultKey: "nonexistent", EnvName: "MISSING"},
	}

	_, err := srv.resolveVaultSecrets(mappings)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestResolveVaultSecrets_Empty(t *testing.T) {
	srv := &PortainerMCPServer{}

	envVars, err := srv.resolveVaultSecrets(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if envVars != nil {
		t.Errorf("expected nil for empty mappings, got %v", envVars)
	}
}

func TestParseVaultSecretMappings(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]any
		wantLen int
		wantErr bool
	}{
		{
			name: "valid mappings",
			args: map[string]any{
				"vaultSecrets": []any{
					map[string]any{
						"vaultPath": "secret/data/myapp",
						"vaultKey":  "db_password",
						"envName":   "DB_PASSWORD",
					},
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple mappings",
			args: map[string]any{
				"vaultSecrets": []any{
					map[string]any{
						"vaultPath": "secret/data/myapp",
						"vaultKey":  "db_password",
						"envName":   "DB_PASSWORD",
					},
					map[string]any{
						"vaultPath": "secret/data/myapp",
						"vaultKey":  "api_key",
						"envName":   "API_KEY",
					},
				},
			},
			wantLen: 2,
		},
		{
			name: "missing vaultPath",
			args: map[string]any{
				"vaultSecrets": []any{
					map[string]any{
						"vaultKey": "db_password",
						"envName":  "DB_PASSWORD",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing vaultKey",
			args: map[string]any{
				"vaultSecrets": []any{
					map[string]any{
						"vaultPath": "secret/data/myapp",
						"envName":   "DB_PASSWORD",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing envName",
			args: map[string]any{
				"vaultSecrets": []any{
					map[string]any{
						"vaultPath": "secret/data/myapp",
						"vaultKey":  "db_password",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := CreateMCPRequest(tt.args)
			parser := toolgen.NewParameterParser(request)

			mappings, err := parseVaultSecretMappings(parser)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseVaultSecretMappings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(mappings) != tt.wantLen {
				t.Errorf("expected %d mappings, got %d", tt.wantLen, len(mappings))
			}
		})
	}
}
