package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zoobzio/rocco"
)

func TestGitHub(t *testing.T) {
	cfg := GitHub()

	if cfg.Name != "github" {
		t.Errorf("expected name 'github', got %q", cfg.Name)
	}
	if cfg.AuthURL != "https://github.com/login/oauth/authorize" {
		t.Errorf("unexpected AuthURL: %s", cfg.AuthURL)
	}
	if cfg.TokenURL != "https://github.com/login/oauth/access_token" {
		t.Errorf("unexpected TokenURL: %s", cfg.TokenURL)
	}
}

func TestGitHubEnterprise(t *testing.T) {
	cfg := GitHubEnterprise("https://github.mycompany.com")

	if cfg.Name != "github-enterprise" {
		t.Errorf("expected name 'github-enterprise', got %q", cfg.Name)
	}
	if cfg.AuthURL != "https://github.mycompany.com/login/oauth/authorize" {
		t.Errorf("unexpected AuthURL: %s", cfg.AuthURL)
	}
	if cfg.TokenURL != "https://github.mycompany.com/login/oauth/access_token" {
		t.Errorf("unexpected TokenURL: %s", cfg.TokenURL)
	}
}

func TestConfig_Validate(t *testing.T) {
	validCfg := func() Config {
		return Config{
			AuthURL:       "https://example.com/auth",
			TokenURL:      "https://example.com/token",
			ClientID:      "client-id",
			ClientSecret:  "client-secret",
			RedirectURI:   "https://myapp.com/callback",
			GenerateState: func(ctx context.Context) (string, error) { return "state", nil },
			VerifyState:   func(ctx context.Context, state string) (bool, error) { return true, nil },
			OnSuccess:     func(ctx context.Context, tokens *TokenResponse) error { return nil },
		}
	}

	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr string
	}{
		{"valid", func(c *Config) {}, ""},
		{"missing AuthURL", func(c *Config) { c.AuthURL = "" }, "AuthURL is required"},
		{"missing TokenURL", func(c *Config) { c.TokenURL = "" }, "TokenURL is required"},
		{"missing ClientID", func(c *Config) { c.ClientID = "" }, "ClientID is required"},
		{"missing ClientSecret", func(c *Config) { c.ClientSecret = "" }, "ClientSecret is required"},
		{"missing RedirectURI", func(c *Config) { c.RedirectURI = "" }, "RedirectURI is required"},
		{"missing GenerateState", func(c *Config) { c.GenerateState = nil }, "GenerateState callback is required"},
		{"missing VerifyState", func(c *Config) { c.VerifyState = nil }, "VerifyState callback is required"},
		{"missing OnSuccess", func(c *Config) { c.OnSuccess = nil }, "OnSuccess callback is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validCfg()
			tc.modify(&cfg)
			err := cfg.validate()

			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestNewLoginHandler(t *testing.T) {
	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     "https://provider.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		Scopes:       []string{"read", "write"},
		GenerateState: func(ctx context.Context) (string, error) {
			return "test-state-123", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	handler, err := NewLoginHandler("/auth/login", cfg)
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
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

	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}

	if u.Host != "provider.com" {
		t.Errorf("expected host 'provider.com', got %q", u.Host)
	}

	q := u.Query()
	if q.Get("client_id") != "client-id" {
		t.Errorf("expected client_id 'client-id', got %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://myapp.com/callback" {
		t.Errorf("unexpected redirect_uri: %s", q.Get("redirect_uri"))
	}
	if q.Get("state") != "test-state-123" {
		t.Errorf("expected state 'test-state-123', got %q", q.Get("state"))
	}
	if q.Get("scope") != "read write" {
		t.Errorf("expected scope 'read write', got %q", q.Get("scope"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("expected response_type 'code', got %q", q.Get("response_type"))
	}
}

func TestNewCallbackHandler_Success(t *testing.T) {
	// Create a mock OAuth server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse form: %v", err)
		}

		if r.Form.Get("code") != "auth-code-123" {
			t.Errorf("expected code 'auth-code-123', got %q", r.Form.Get("code"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "access-token-xyz",
			RefreshToken: "refresh-token-abc",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "read write",
		})
	}))
	defer mockServer.Close()

	var receivedTokens *TokenResponse
	cfg := Config{
		Name:         "test",
		AuthURL:      "https://provider.com/auth",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
		GenerateState: func(ctx context.Context) (string, error) {
			return "test-state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) {
			return state == "valid-state", nil
		},
		OnSuccess: func(ctx context.Context, tokens *TokenResponse) error {
			receivedTokens = tokens
			return nil
		},
	}

	type callbackResponse struct {
		Success bool `json:"success"`
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(tokens *TokenResponse) (callbackResponse, error) {
		return callbackResponse{Success: true}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code-123&state=valid-state", nil)
	w := httptest.NewRecorder()

	status, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, status)
	}

	if receivedTokens == nil {
		t.Fatal("OnSuccess was not called")
	}
	if receivedTokens.AccessToken != "access-token-xyz" {
		t.Errorf("expected access token 'access-token-xyz', got %q", receivedTokens.AccessToken)
	}
	if receivedTokens.RefreshToken != "refresh-token-abc" {
		t.Errorf("expected refresh token 'refresh-token-abc', got %q", receivedTokens.RefreshToken)
	}
}

func TestNewCallbackHandler_InvalidState(t *testing.T) {
	// Need a mock server even though we won't reach it (state check happens first)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach token endpoint with invalid state")
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
			return "test-state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) {
			return false, nil // State is invalid
		},
		OnSuccess: func(ctx context.Context, tokens *TokenResponse) error {
			return nil
		},
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=some-code&state=wrong-state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, status)
	}
}

func TestNewCallbackHandler_MissingCode(t *testing.T) {
	// Use mock server to ensure test is hermetic (no outbound calls)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach token endpoint when code is missing")
		w.WriteHeader(http.StatusBadRequest)
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
			return "test-state", nil
		},
		VerifyState: func(ctx context.Context, state string) (bool, error) {
			return true, nil
		},
		OnSuccess: func(ctx context.Context, tokens *TokenResponse) error {
			return nil
		},
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=valid-state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, status)
	}
}

func TestNewCallbackHandler_WithRedirect(t *testing.T) {
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
		VerifyState: func(ctx context.Context, state string) (bool, error) {
			return true, nil
		},
		OnSuccess: func(ctx context.Context, tokens *TokenResponse) error {
			return nil
		},
	}

	handler, err := NewCallbackHandler("/auth/callback", cfg, func(tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	w := httptest.NewRecorder()

	status, processErr := handler.Process(context.Background(), req, w)
	if processErr != nil {
		t.Fatalf("unexpected error: %v", processErr)
	}

	if status != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, status)
	}

	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected Location '/dashboard', got %q", loc)
	}
}

func TestNewLoginHandler_ValidationError(t *testing.T) {
	// Missing required fields
	cfg := Config{
		Name:    "test",
		AuthURL: "https://provider.com/auth",
		// Missing TokenURL, ClientID, ClientSecret, etc.
	}

	_, err := NewLoginHandler("/auth/login", cfg)
	if err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}

	// Should contain "invalid config" in error message
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("expected error to mention 'invalid config', got %q", err.Error())
	}
}

func TestNewCallbackHandler_ValidationError(t *testing.T) {
	// Missing required fields
	cfg := Config{
		Name:    "test",
		AuthURL: "https://provider.com/auth",
		// Missing TokenURL, ClientID, ClientSecret, etc.
	}

	_, err := NewCallbackHandler("/auth/callback", cfg, func(tokens *TokenResponse) (rocco.Redirect, error) {
		return rocco.Redirect{URL: "/dashboard"}, nil
	})
	if err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}

	// Should contain "invalid config" in error message
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("expected error to mention 'invalid config', got %q", err.Error())
	}
}

func TestNewCallbackHandler_NilRespondFunction(t *testing.T) {
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
		VerifyState: func(ctx context.Context, state string) (bool, error) { return true, nil },
		OnSuccess:   func(ctx context.Context, tokens *TokenResponse) error { return nil },
	}

	_, err := NewCallbackHandler[rocco.Redirect]("/auth/callback", cfg, nil)
	if err == nil {
		t.Fatal("expected error for nil respond function, got nil")
	}

	if !strings.Contains(err.Error(), "respond function is required") {
		t.Errorf("expected error to mention 'respond function is required', got %q", err.Error())
	}
}

func TestRefresh(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse form: %v", err)
		}

		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected grant_type 'refresh_token', got %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "old-refresh-token" {
			t.Errorf("expected refresh_token 'old-refresh-token', got %q", r.Form.Get("refresh_token"))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}))
	defer mockServer.Close()

	cfg := Config{
		Name:         "test",
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	tokens, err := Refresh(context.Background(), cfg, "old-refresh-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens.AccessToken != "new-access-token" {
		t.Errorf("expected access token 'new-access-token', got %q", tokens.AccessToken)
	}
	if tokens.RefreshToken != "new-refresh-token" {
		t.Errorf("expected refresh token 'new-refresh-token', got %q", tokens.RefreshToken)
	}
}
