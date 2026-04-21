package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type fakeNetTimeoutError struct{}

func (fakeNetTimeoutError) Error() string   { return "timeout" }
func (fakeNetTimeoutError) Timeout() bool   { return true }
func (fakeNetTimeoutError) Temporary() bool { return true }

func TestIsRetryableVaultError_ResponseCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		expected bool
	}{
		{name: "rate limit is retryable", status: 429, expected: true},
		{name: "request timeout is retryable", status: 408, expected: true},
		{name: "server error is retryable", status: 503, expected: true},
		{name: "forbidden is not retryable", status: 403, expected: false},
		{name: "bad request is not retryable", status: 400, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := &vaultapi.ResponseError{StatusCode: tt.status}
			if got := isRetryableVaultError(err); got != tt.expected {
				t.Fatalf("isRetryableVaultError(%d) = %v, want %v", tt.status, got, tt.expected)
			}
		})
	}
}

func TestIsRetryableVaultError_ContextAndNetwork(t *testing.T) {
	t.Parallel()

	if isRetryableVaultError(context.Canceled) {
		t.Fatalf("context.Canceled should not be retryable")
	}

	if !isRetryableVaultError(fakeNetTimeoutError{}) {
		t.Fatalf("timeout network error should be retryable")
	}
}

func TestWithRetry_DoesNotRetryNonRetryableError(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := withRetry(context.Background(), "test operation", func() error {
		attempts++
		return &vaultapi.ResponseError{StatusCode: 400}
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt for non-retryable error, got %d", attempts)
	}
	if !strings.Contains(err.Error(), "non-retryable") {
		t.Fatalf("expected non-retryable classification in error, got %q", err.Error())
	}
}

func TestVerifyKubernetesEngineMount_ReadsMountFromSysEndpoint(t *testing.T) {
	t.Parallel()

	requests := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.URL.Path
		if r.Method == http.MethodGet && strings.TrimSuffix(r.URL.Path, "/") == "/v1/sys/mounts/kubernetes" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"kubernetes","Type":"kubernetes"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	clientCfg := vaultapi.DefaultConfig()
	clientCfg.Address = server.URL
	vaultClient, err := vaultapi.NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create Vault client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := verifyKubernetesEngineMount(ctx, vaultClient, "kubernetes"); err != nil {
		t.Fatalf("verifyKubernetesEngineMount returned error: %v", err)
	}

	close(requests)
	seen := make([]string, 0, len(requests))
	for request := range requests {
		seen = append(seen, request)
	}

	if len(seen) != 1 {
		t.Fatalf("expected exactly one request, got %d: %v", len(seen), seen)
	}
	if seen[0] != "GET /v1/sys/mounts/kubernetes" {
		t.Fatalf("expected GET on sys mount endpoint, got %q", seen[0])
	}
}

func TestVerifyKubernetesEngineMount_ReturnsNotFoundForMissingMount(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	clientCfg := vaultapi.DefaultConfig()
	clientCfg.Address = server.URL
	vaultClient, err := vaultapi.NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create Vault client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = verifyKubernetesEngineMount(ctx, vaultClient, "missing-mount")
	if err == nil {
		t.Fatal("expected error for missing mount, got nil")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, `failed to find Vault mount "missing-mount"`) &&
		!strings.Contains(errMsg, `Kubernetes secret engine mount "missing-mount" not found`) {
		t.Fatalf("expected not found message, got %q", err.Error())
	}
}
