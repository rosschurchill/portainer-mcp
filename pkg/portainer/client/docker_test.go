package client

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/portainer/portainer-mcp/pkg/portainer/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyDockerRequest(t *testing.T) {
	tests := []struct {
		name             string
		opts             models.DockerProxyRequestOptions
		serverStatus     int
		serverBody       string
		expectedError    bool
		expectedStatus   int
		expectedRespBody string
		expectedReqBody  string
		checkRequest     func(t *testing.T, r *http.Request)
	}{
		{
			name: "GET request with query parameters",
			opts: models.DockerProxyRequestOptions{
				EnvironmentID: 1,
				Method:        "GET",
				Path:          "/images/json",
				QueryParams:   map[string]string{"all": "true"},
			},
			serverStatus:     http.StatusOK,
			serverBody:       `[{"Id":"img1"}]`,
			expectedError:    false,
			expectedStatus:   http.StatusOK,
			expectedRespBody: `[{"Id":"img1"}]`,
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "/api/endpoints/1/docker/images/json", r.URL.Path)
				assert.Equal(t, "true", r.URL.Query().Get("all"))
				assert.Equal(t, "test-token", r.Header.Get("X-API-Key"))
			},
		},
		{
			name: "POST request with custom headers and body",
			opts: models.DockerProxyRequestOptions{
				EnvironmentID: 2,
				Method:        "POST",
				Path:          "/networks/create",
				Headers:       map[string]string{"X-Custom-Header": "value1"},
				Body:          bytes.NewBufferString(`{"Name": "my-network"}`),
			},
			serverStatus:     http.StatusCreated,
			serverBody:       `{"Id": "net1"}`,
			expectedError:    false,
			expectedStatus:   http.StatusCreated,
			expectedRespBody: `{"Id": "net1"}`,
			expectedReqBody:  `{"Name": "my-network"}`,
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "/api/endpoints/2/docker/networks/create", r.URL.Path)
				assert.Equal(t, "value1", r.Header.Get("X-Custom-Header"))
			},
		},
		{
			name: "GET request with no extras",
			opts: models.DockerProxyRequestOptions{
				EnvironmentID: 3,
				Method:        "GET",
				Path:          "/version",
			},
			serverStatus:     http.StatusOK,
			serverBody:       `{"Version":"24.0"}`,
			expectedError:    false,
			expectedStatus:   http.StatusOK,
			expectedRespBody: `{"Version":"24.0"}`,
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "/api/endpoints/3/docker/version", r.URL.Path)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedReq *http.Request
			var capturedBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedReq = r
				capturedBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			c := NewPortainerClient(server.URL, "test-token")

			resp, err := c.ProxyDockerRequest(tt.opts)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
				defer func() { _ = resp.Body.Close() }()
				bodyBytes, _ := io.ReadAll(resp.Body)
				assert.Equal(t, tt.expectedRespBody, string(bodyBytes))
				if tt.expectedReqBody != "" {
					assert.Equal(t, tt.expectedReqBody, string(capturedBody))
				}
				if tt.checkRequest != nil {
					tt.checkRequest(t, capturedReq)
				}
			}
		})
	}
}

func TestProxyDockerRequestScheme(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Ensure http:// scheme is used (not https://)
	c := NewPortainerClient(server.URL, "test-token")
	resp, err := c.ProxyDockerRequest(models.DockerProxyRequestOptions{
		EnvironmentID: 1,
		Method:        "GET",
		Path:          "/info",
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	if resp != nil {
		_ = resp.Body.Close()
	}

	// Ensure server.URL starts with http:// (validating test itself)
	assert.True(t, strings.HasPrefix(server.URL, "http://"), "test server should use http://")
}
