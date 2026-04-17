package controller

import (
	"context"
	"strings"
	"testing"

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
