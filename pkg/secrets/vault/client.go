package vault

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/portainer/portainer-mcp/pkg/secrets"
	"github.com/rs/zerolog/log"
)

// VaultClient implements secrets.SecretsProvider using HashiCorp Vault with AppRole auth.
type VaultClient struct {
	address   string
	roleID    string
	secretID  string
	mountPath string

	token    string
	tokenTTL time.Duration
	mu       sync.RWMutex

	httpCli *http.Client
	ctx     context.Context
	cancel  context.CancelFunc
}

// loginResponse represents the Vault AppRole login response.
type loginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// kvResponse represents a Vault KV v2 read response.
type kvResponse struct {
	Data struct {
		Data     map[string]interface{} `json:"data"`
		Metadata struct {
			Version int `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
}

// listResponse represents a Vault list response.
type listResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// NewVaultClient creates a new Vault client with AppRole authentication.
//
// Parameters:
//   - address: The Vault server address (e.g., "https://vault.example.com:8200")
//   - roleID: The AppRole role_id for authentication
//   - secretID: The AppRole secret_id for authentication
//   - opts: Optional configuration (TLS, mount path, HTTP client)
//
// Returns:
//   - A configured VaultClient that implements secrets.SecretsProvider
//   - An error if the initial AppRole login fails
func NewVaultClient(address, roleID, secretID string, opts ...ClientOption) (*VaultClient, error) {
	options := &clientOptions{
		mountPath: "approle",
	}
	for _, opt := range opts {
		opt(options)
	}

	httpCli := options.httpClient
	if httpCli == nil {
		transport := &http.Transport{}
		if options.skipTLSVerify {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		httpCli = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	}

	address = strings.TrimRight(address, "/")

	ctx, cancel := context.WithCancel(context.Background())

	c := &VaultClient{
		address:   address,
		roleID:    roleID,
		secretID:  secretID,
		mountPath: options.mountPath,
		httpCli:   httpCli,
		ctx:       ctx,
		cancel:    cancel,
	}

	if err := c.login(); err != nil {
		cancel()
		return nil, fmt.Errorf("vault AppRole login failed: %w", err)
	}

	if c.tokenTTL > 0 {
		go c.renewalLoop()
	}

	return c, nil
}

// login authenticates with Vault using AppRole and stores the client token.
func (c *VaultClient) login() error {
	payload := fmt.Sprintf(`{"role_id":"%s","secret_id":"%s"}`, c.roleID, c.secretID)

	url := fmt.Sprintf("%s/v1/auth/%s/login", c.address, c.mountPath)
	resp, err := c.httpCli.Post(url, "application/json", strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to connect to Vault: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault login returned status %d", resp.StatusCode)
	}

	var loginResp loginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return fmt.Errorf("failed to parse login response: %w", err)
	}

	if loginResp.Auth.ClientToken == "" {
		return fmt.Errorf("vault returned empty client token")
	}

	c.mu.Lock()
	c.token = loginResp.Auth.ClientToken
	c.tokenTTL = time.Duration(loginResp.Auth.LeaseDuration) * time.Second
	c.mu.Unlock()

	log.Info().Dur("ttl", c.tokenTTL).Msg("vault AppRole login successful")
	return nil
}

// renewalLoop renews the Vault token at 75% of its TTL.
func (c *VaultClient) renewalLoop() {
	for {
		c.mu.RLock()
		ttl := c.tokenTTL
		c.mu.RUnlock()

		if ttl <= 0 {
			return
		}

		renewAt := time.Duration(float64(ttl) * 0.75)

		select {
		case <-time.After(renewAt):
			if err := c.renewToken(); err != nil {
				log.Warn().Err(err).Msg("vault token renewal failed, attempting re-login")
				if err := c.login(); err != nil {
					log.Error().Err(err).Msg("vault re-login failed")
				}
			}
		case <-c.ctx.Done():
			return
		}
	}
}

// renewToken renews the current Vault token.
func (c *VaultClient) renewToken() error {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	url := fmt.Sprintf("%s/v1/auth/token/renew-self", c.address)
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, url, strings.NewReader(`{}`))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpCli.Do(req)
	if err != nil {
		return fmt.Errorf("token renewal request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token renewal returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var loginResp loginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return err
	}

	c.mu.Lock()
	c.token = loginResp.Auth.ClientToken
	c.tokenTTL = time.Duration(loginResp.Auth.LeaseDuration) * time.Second
	c.mu.Unlock()

	log.Debug().Dur("ttl", c.tokenTTL).Msg("vault token renewed")
	return nil
}

// GetSecrets retrieves all key-value pairs at the given Vault KV v2 path.
// The caller must call SecretResult.Clear() when done to zero secret memory.
func (c *VaultClient) GetSecrets(path string) (*secrets.SecretResult, error) {
	path = normalizeKVPath(path)

	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	url := fmt.Sprintf("%s/v1/%s", c.address, path)
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := c.httpCli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault read returned status %d for path %s", resp.StatusCode, path)
	}

	var kvResp kvResponse
	if err := json.Unmarshal(body, &kvResp); err != nil {
		return nil, fmt.Errorf("failed to parse vault response: %w", err)
	}

	result := &secrets.SecretResult{
		Path:    path,
		Secrets: make(map[string]secrets.SecretValue, len(kvResp.Data.Data)),
	}

	for k, v := range kvResp.Data.Data {
		strVal := fmt.Sprintf("%v", v)
		result.Secrets[k] = secrets.SecretValue{Value: []byte(strVal)}
	}

	// Zero the raw body to avoid lingering secrets in memory
	for i := range body {
		body[i] = 0
	}

	return result, nil
}

// ListSecrets returns the list of key names at the given Vault path.
// No secret values are returned.
func (c *VaultClient) ListSecrets(path string) ([]string, error) {
	path = normalizeKVPath(path)

	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	// For KV v2, metadata listing uses the metadata prefix
	metadataPath := strings.Replace(path, "/data/", "/metadata/", 1)

	url := fmt.Sprintf("%s/v1/%s", c.address, metadataPath)
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := c.httpCli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Path has no sub-keys; try reading the secret to list its data keys
		return c.listDataKeys(path, token)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Fall back to listing data keys from the secret itself
		return c.listDataKeys(path, token)
	}

	var listResp listResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		return c.listDataKeys(path, token)
	}

	if len(listResp.Data.Keys) > 0 {
		return listResp.Data.Keys, nil
	}

	return c.listDataKeys(path, token)
}

// listDataKeys reads a secret and returns its key names (without values).
func (c *VaultClient) listDataKeys(path, token string) ([]string, error) {
	url := fmt.Sprintf("%s/v1/%s", c.address, path)
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := c.httpCli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault read returned status %d for path %s", resp.StatusCode, path)
	}

	var kvResp kvResponse
	if err := json.Unmarshal(body, &kvResp); err != nil {
		return nil, fmt.Errorf("failed to parse vault response: %w", err)
	}

	keys := make([]string, 0, len(kvResp.Data.Data))
	for k := range kvResp.Data.Data {
		keys = append(keys, k)
	}

	// Zero the body since it may contain secret values
	for i := range body {
		body[i] = 0
	}

	return keys, nil
}

// Close stops the renewal goroutine and revokes the Vault token.
func (c *VaultClient) Close() error {
	c.cancel()

	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	if token != "" {
		// Best-effort token revocation
		url := fmt.Sprintf("%s/v1/auth/token/revoke-self", c.address)
		req, err := http.NewRequest(http.MethodPut, url, nil)
		if err == nil {
			req.Header.Set("X-Vault-Token", token)
			resp, err := c.httpCli.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
	}

	// Zero sensitive fields
	c.mu.Lock()
	for i := range []byte(c.token) {
		[]byte(c.token)[i] = 0
	}
	for i := range []byte(c.secretID) {
		[]byte(c.secretID)[i] = 0
	}
	c.token = ""
	c.secretID = ""
	c.mu.Unlock()

	return nil
}

// normalizeKVPath ensures a KV v2 path has the /data/ segment.
// "secret/myapp" -> "secret/data/myapp"
// "secret/data/myapp" -> "secret/data/myapp" (unchanged)
func normalizeKVPath(path string) string {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		return path
	}

	engine := parts[0]
	rest := parts[1]

	if strings.HasPrefix(rest, "data/") {
		return path
	}

	return engine + "/data/" + rest
}
