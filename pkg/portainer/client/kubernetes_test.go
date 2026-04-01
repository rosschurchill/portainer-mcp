package client

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/portainer/portainer-mcp/pkg/portainer/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyKubernetesRequest(t *testing.T) {
	tests := []struct {
		name             string
		opts             models.KubernetesProxyRequestOptions
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
			opts: models.KubernetesProxyRequestOptions{
				EnvironmentID: 1,
				Method:        "GET",
				Path:          "/api/v1/pods",
				QueryParams:   map[string]string{"namespace": "default"},
			},
			serverStatus:     http.StatusOK,
			serverBody:       `{"items": [{"metadata": {"name": "pod1"}}]}`,
			expectedError:    false,
			expectedStatus:   http.StatusOK,
			expectedRespBody: `{"items": [{"metadata": {"name": "pod1"}}]}`,
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "/api/endpoints/1/kubernetes/api/v1/pods", r.URL.Path)
				assert.Equal(t, "default", r.URL.Query().Get("namespace"))
				assert.Equal(t, "test-token", r.Header.Get("X-API-Key"))
			},
		},
		{
			name: "POST request with custom headers and body",
			opts: models.KubernetesProxyRequestOptions{
				EnvironmentID: 2,
				Method:        "POST",
				Path:          "/api/v1/namespaces/default/services",
				Headers:       map[string]string{"Content-Type": "application/json"},
				Body:          bytes.NewBufferString(`{"kind": "Service"}`),
			},
			serverStatus:     http.StatusCreated,
			serverBody:       `{"metadata": {"name": "my-service"}}`,
			expectedError:    false,
			expectedStatus:   http.StatusCreated,
			expectedRespBody: `{"metadata": {"name": "my-service"}}`,
			expectedReqBody:  `{"kind": "Service"}`,
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "/api/endpoints/2/kubernetes/api/v1/namespaces/default/services", r.URL.Path)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			},
		},
		{
			name: "GET request with no extras",
			opts: models.KubernetesProxyRequestOptions{
				EnvironmentID: 4,
				Method:        "GET",
				Path:          "/healthz",
			},
			serverStatus:     http.StatusOK,
			serverBody:       "ok",
			expectedError:    false,
			expectedStatus:   http.StatusOK,
			expectedRespBody: "ok",
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "/api/endpoints/4/kubernetes/healthz", r.URL.Path)
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

			resp, err := c.ProxyKubernetesRequest(tt.opts)
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
