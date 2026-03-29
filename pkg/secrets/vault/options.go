package vault

import "net/http"

// ClientOption is a function that configures the Vault client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	skipTLSVerify bool
	mountPath     string
	httpClient    *http.Client
}

// WithSkipTLSVerify disables TLS certificate verification for the Vault connection.
func WithSkipTLSVerify(skip bool) ClientOption {
	return func(opts *clientOptions) {
		opts.skipTLSVerify = skip
	}
}

// WithMountPath sets the AppRole auth mount path (default: "approle").
func WithMountPath(path string) ClientOption {
	return func(opts *clientOptions) {
		opts.mountPath = path
	}
}

// WithHTTPClient sets a custom HTTP client for the Vault connection.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(opts *clientOptions) {
		opts.httpClient = c
	}
}
