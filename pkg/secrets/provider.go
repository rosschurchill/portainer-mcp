package secrets

// SecretsProvider is the abstraction for any secrets backend.
// Implementations must be safe for concurrent use.
type SecretsProvider interface {
	// GetSecrets retrieves all key-value pairs at the given path.
	// The caller is responsible for calling SecretResult.Clear() when done.
	GetSecrets(path string) (*SecretResult, error)

	// ListSecrets returns the list of key names at the given path.
	// No values are returned.
	ListSecrets(path string) ([]string, error)

	// Close cleans up any resources (e.g., revokes Vault token).
	Close() error
}

// SecretValue holds a secret's value with metadata for secure cleanup.
type SecretValue struct {
	Value []byte
}

// Clear zeroes out the secret value bytes in memory.
func (sv *SecretValue) Clear() {
	for i := range sv.Value {
		sv.Value[i] = 0
	}
}

// SecretResult holds a set of secrets keyed by their name within the path.
type SecretResult struct {
	Path    string
	Secrets map[string]SecretValue
}

// Clear zeroes all secret values in the result.
func (sr *SecretResult) Clear() {
	for k := range sr.Secrets {
		v := sr.Secrets[k]
		v.Clear()
		sr.Secrets[k] = v
	}
}
