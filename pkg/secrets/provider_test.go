package secrets

import (
	"testing"
)

func TestSecretValueClear(t *testing.T) {
	sv := SecretValue{Value: []byte("super-secret-password")}
	original := make([]byte, len(sv.Value))
	copy(original, sv.Value)

	sv.Clear()

	for i, b := range sv.Value {
		if b != 0 {
			t.Errorf("byte at index %d was not zeroed: got %d", i, b)
		}
	}

	if len(sv.Value) != len(original) {
		t.Errorf("length changed after clear: got %d, want %d", len(sv.Value), len(original))
	}
}

func TestSecretResultClear(t *testing.T) {
	sr := &SecretResult{
		Path: "secret/data/myapp",
		Secrets: map[string]SecretValue{
			"db_password": {Value: []byte("password123")},
			"api_key":     {Value: []byte("key-abc-xyz")},
		},
	}

	sr.Clear()

	for name, sv := range sr.Secrets {
		for i, b := range sv.Value {
			if b != 0 {
				t.Errorf("secret %q byte at index %d was not zeroed: got %d", name, i, b)
			}
		}
	}
}

func TestSecretValueClearEmpty(t *testing.T) {
	sv := SecretValue{Value: []byte{}}
	sv.Clear() // should not panic

	sv2 := SecretValue{Value: nil}
	sv2.Clear() // should not panic
}
