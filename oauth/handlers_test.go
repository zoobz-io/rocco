package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zoobzio/rocco"
)

func TestNewLoginHandler_StateGenerationFailure(t *testing.T) {
	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     "https://provider.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "", errors.New("state generation failed")
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewLoginHandler("/auth/login", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestNewLoginHandler_NoScopes(t *testing.T) {
	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     "https://provider.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		Scopes:       nil, // No scopes
		GenerateState: func(ctx context.Context) (string, error) {
			return "state-123", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewLoginHandler("/auth/login", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	status, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, status)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}

	// Should not contain scope parameter
	if contains(location, "scope=") {
		t.Error("expected no scope parameter in URL")
	}
}

func TestNewCallbackHandler_ProviderError(t *testing.T) {
	cfg := Config{
		Name:         "github",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     "https://provider.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(ctx context.Context, tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate provider returning an error (e.g., user denied access)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&error_description=The+user+denied+access", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, status)
	}

	// Check error response contains provider info
	var errResp struct {
		Code    string `json:"code"`
		Details struct {
			Provider string `json:"provider"`
			Reason   string `json:"reason"`
		} `json:"details"`
	}
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Code != "BAD_GATEWAY" {
		t.Errorf("expected code 'BAD_GATEWAY', got %q", errResp.Code)
	}
	if errResp.Details.Provider != "github" {
		t.Errorf("expected provider 'github', got %q", errResp.Details.Provider)
	}
	if errResp.Details.Reason != "The user denied access" {
		t.Errorf("expected reason 'The user denied access', got %q", errResp.Details.Reason)
	}
}

func TestNewCallbackHandler_TokenExchangeFailure(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "The authorization code has expired",
		})
	}))
	defer mockServer.Close()

	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(ctx context.Context, tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=expired-code&state=state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, status)
	}
}

func TestNewCallbackHandler_InvalidJSONResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json"))
	}))
	defer mockServer.Close()

	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(ctx context.Context, tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, status)
	}
}

func TestNewCallbackHandler_OnSuccessFailure(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "token",
			TokenType:   "Bearer",
		})
	}))
	defer mockServer.Close()

	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess: func(ctx context.Context, tokens *TokenResponse) error {
			return errors.New("database error")
		},
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(ctx context.Context, tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestNewCallbackHandler_StateVerificationError(t *testing.T) {
	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     "https://provider.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) {
			return false, errors.New("session expired")
		},
		OnSuccess: func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(ctx context.Context, tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, status)
	}
}

func TestNewCallbackHandler_RespondError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "token",
			TokenType:   "Bearer",
		})
	}))
	defer mockServer.Close()

	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(ctx context.Context, tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{}, rocco.ErrInternalServer.WithMessage("respond failed")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestRefresh_Failure(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Refresh token has been revoked",
		})
	}))
	defer mockServer.Close()

	cfg := Config{
		Name:         "test",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	_, err := Refresh(context.Background(), cfg, "revoked-token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Should be a BadGateway error
	var roccoErr rocco.ErrorDefinition
	if !errors.As(err, &roccoErr) {
		t.Fatalf("expected rocco.ErrorDefinition, got %T", err)
	}
	if roccoErr.Status() != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, roccoErr.Status())
	}
}

func TestBuildAuthURL(t *testing.T) {
	cfg := Config{
		AuthURL:     "https://provider.com/auth",
		ClientID:    "my-client",
		RedirectURI: "https://myapp.com/callback",
		Scopes:      []string{"read", "write", "admin"},
	}

	url, err := buildAuthURL(cfg, "random-state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		"client_id=my-client",
		"redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback",
		"state=random-state",
		"response_type=code",
		"scope=read+write+admin",
	}

	for _, param := range expected {
		if !contains(url, param) {
			t.Errorf("expected URL to contain %q, got %s", param, url)
		}
	}
}

func TestBuildAuthURL_InvalidURL(t *testing.T) {
	cfg := Config{
		AuthURL:     "://invalid",
		ClientID:    "client",
		RedirectURI: "https://myapp.com/callback",
	}

	_, err := buildAuthURL(cfg, "state")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestNewLoginHandler_InvalidAuthURL(t *testing.T) {
	cfg := Config{
		Name:         "test",
		AuthURL:      "://invalid", // Invalid URL
		TokenURL:     "https://provider.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "state-123", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewLoginHandler("/auth/login", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestNewCallbackHandler_ProviderErrorWithoutDescription(t *testing.T) {
	cfg := Config{
		Name:         "github",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     "https://provider.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(ctx context.Context, tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Provider error without error_description - should fall back to error code
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=server_error", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, status)
	}

	var errResp struct {
		Details struct {
			Reason string `json:"reason"`
		} `json:"details"`
	}
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	// Should fall back to error code as reason
	if errResp.Details.Reason != "server_error" {
		t.Errorf("expected reason 'server_error', got %q", errResp.Details.Reason)
	}
}

func TestDoTokenRequest_HTTPClientError(t *testing.T) {
	cfg := Config{
		Name:         "test",
		TokenURL:     "http://localhost:1", // Port that won't be listening
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}
	cfg.defaults()

	_, err := Refresh(context.Background(), cfg, "token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var roccoErr rocco.ErrorDefinition
	if !errors.As(err, &roccoErr) {
		t.Fatalf("expected rocco.ErrorDefinition, got %T", err)
	}
	if roccoErr.Status() != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, roccoErr.Status())
	}
}

func TestDoTokenRequest_ErrorWithoutDescription(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		// Error response with error but no error_description
		json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid_request",
		})
	}))
	defer mockServer.Close()

	cfg := Config{
		Name:         "test",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	_, err := Refresh(context.Background(), cfg, "token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var roccoErr rocco.ErrorDefinition
	if !errors.As(err, &roccoErr) {
		t.Fatalf("expected rocco.ErrorDefinition, got %T", err)
	}
	if roccoErr.Status() != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, roccoErr.Status())
	}
}

func TestDoTokenRequest_NonJSONErrorResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("<html>Service Unavailable</html>"))
	}))
	defer mockServer.Close()

	cfg := Config{
		Name:         "test",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	_, err := Refresh(context.Background(), cfg, "token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var roccoErr rocco.ErrorDefinition
	if !errors.As(err, &roccoErr) {
		t.Fatalf("expected rocco.ErrorDefinition, got %T", err)
	}
	if roccoErr.Status() != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, roccoErr.Status())
	}
}

func TestDoTokenRequest_InvalidURL(t *testing.T) {
	cfg := Config{
		Name:         "test",
		TokenURL:     "://invalid", // Invalid URL scheme
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}
	cfg.defaults()

	_, err := Refresh(context.Background(), cfg, "token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var roccoErr rocco.ErrorDefinition
	if !errors.As(err, &roccoErr) {
		t.Fatalf("expected rocco.ErrorDefinition, got %T", err)
	}
	if roccoErr.Status() != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, roccoErr.Status())
	}
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
