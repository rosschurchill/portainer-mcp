package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewVaultClient_AppRoleLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)

			if body["role_id"] != "test-role" || body["secret_id"] != "test-secret" {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "test-token-abc",
					"lease_duration": 0, // no renewal for test
					"renewable":      false,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewVaultClient(server.URL, "test-role", "test-secret",
		WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer client.Close()

	if client.token != "test-token-abc" {
		t.Errorf("expected token 'test-token-abc', got %q", client.token)
	}
}

func TestNewVaultClient_LoginFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	_, err := NewVaultClient(server.URL, "bad-role", "bad-secret",
		WithHTTPClient(server.Client()))
	if err == nil {
		t.Fatal("expected error for bad credentials")
	}
}

func TestGetSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "test-token",
					"lease_duration": 0,
				},
			})
		case "/v1/secret/data/myapp":
			if r.Header.Get("X-Vault-Token") != "test-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"db_password": "secret123",
						"api_key":     "key-abc-xyz",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewVaultClient(server.URL, "role", "secret",
		WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer client.Close()

	result, err := client.GetSecrets("secret/myapp")
	if err != nil {
		t.Fatalf("GetSecrets failed: %v", err)
	}
	defer result.Clear()

	if len(result.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(result.Secrets))
	}

	if string(result.Secrets["db_password"].Value) != "secret123" {
		t.Errorf("expected 'secret123', got %q", string(result.Secrets["db_password"].Value))
	}

	if string(result.Secrets["api_key"].Value) != "key-abc-xyz" {
		t.Errorf("expected 'key-abc-xyz', got %q", string(result.Secrets["api_key"].Value))
	}
}

func TestGetSecrets_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "test-token",
					"lease_duration": 0,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewVaultClient(server.URL, "role", "secret",
		WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer client.Close()

	_, err = client.GetSecrets("secret/nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestListSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "test-token",
					"lease_duration": 0,
				},
			})
		case "/v1/secret/metadata/myapp":
			w.WriteHeader(http.StatusNotFound) // trigger fallback to data keys
		case "/v1/secret/data/myapp":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"db_password": "secret123",
						"api_key":     "key-abc",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewVaultClient(server.URL, "role", "secret",
		WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer client.Close()

	keys, err := client.ListSecrets("secret/myapp")
	if err != nil {
		t.Fatalf("ListSecrets failed: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	keySet := map[string]bool{}
	for _, k := range keys {
		keySet[k] = true
	}
	if !keySet["db_password"] || !keySet["api_key"] {
		t.Errorf("expected keys 'db_password' and 'api_key', got %v", keys)
	}
}

func TestNormalizeKVPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"secret/myapp", "secret/data/myapp"},
		{"secret/data/myapp", "secret/data/myapp"},
		{"kv/production/db", "kv/data/production/db"},
		{"kv/data/production/db", "kv/data/production/db"},
		{"secret", "secret"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeKVPath(tt.input)
			if got != tt.want {
				t.Errorf("normalizeKVPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestClose_ZerosCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "test-token",
					"lease_duration": 0,
				},
			})
			return
		}
		// Accept revoke-self
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewVaultClient(server.URL, "role", "secret",
		WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	client.Close()

	if client.token != "" {
		t.Error("token was not cleared")
	}
	if client.secretID != "" {
		t.Error("secretID was not cleared")
	}
}

func TestWithMountPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/custom-approle/login" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "test-token",
					"lease_duration": 0,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewVaultClient(server.URL, "role", "secret",
		WithHTTPClient(server.Client()),
		WithMountPath("custom-approle"))
	if err != nil {
		t.Fatalf("login with custom mount path failed: %v", err)
	}
	defer client.Close()
}
