package client

import (
	"fmt"
	"net/http"

	"github.com/portainer/portainer-mcp/pkg/portainer/models"
)

// ProxyDockerRequest proxies a Docker API request to a specific Portainer environment.
//
// Parameters:
//   - opts: Options defining the proxied request (environmentID, method, path, query params, headers, body)
//
// Returns:
//   - *http.Response: The response from the Docker API
//   - error: Any error that occurred during the request
func (c *PortainerClient) ProxyDockerRequest(opts models.DockerProxyRequestOptions) (*http.Response, error) {
	path := fmt.Sprintf("/api/endpoints/%d/docker%s", opts.EnvironmentID, opts.Path)
	return c.rawCli.proxyRequest(opts.Method, path, opts.QueryParams, opts.Headers, opts.Body)
}
