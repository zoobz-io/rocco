package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
			AuthURL:      "https://example.com/auth",
			TokenURL:     "https://example.com/token",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURI:  "https://myapp.com/callback",
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validCfg()
			tc.modify(&cfg)
			err := cfg.Validate()

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

func TestAuthURL(t *testing.T) {
	cfg := Config{
		AuthURL:     "https://provider.com/auth",
		ClientID:    "my-client",
		RedirectURI: "https://myapp.com/callback",
		Scopes:      []string{"read", "write", "admin"},
	}

	u, err := AuthURL(cfg, "random-state")
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
		if !strings.Contains(u, param) {
			t.Errorf("expected URL to contain %q, got %s", param, u)
		}
	}
}

func TestAuthURL_NoScopes(t *testing.T) {
	cfg := Config{
		AuthURL:     "https://provider.com/auth",
		ClientID:    "client",
		RedirectURI: "https://myapp.com/callback",
	}

	u, err := AuthURL(cfg, "state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(u, "scope=") {
		t.Error("expected no scope parameter in URL")
	}
}

func TestAuthURL_InvalidURL(t *testing.T) {
	cfg := Config{
		AuthURL:     "://invalid",
		ClientID:    "client",
		RedirectURI: "https://myapp.com/callback",
	}

	_, err := AuthURL(cfg, "state")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestExchange(t *testing.T) {
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
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("expected grant_type 'authorization_code', got %q", r.Form.Get("grant_type"))
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

	cfg := Config{
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
	}

	tokens, err := Exchange(context.Background(), cfg, "auth-code-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens.AccessToken != "access-token-xyz" {
		t.Errorf("expected access token 'access-token-xyz', got %q", tokens.AccessToken)
	}
	if tokens.RefreshToken != "refresh-token-abc" {
		t.Errorf("expected refresh token 'refresh-token-abc', got %q", tokens.RefreshToken)
	}
}

func TestExchange_Failure(t *testing.T) {
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
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
	}

	_, err := Exchange(context.Background(), cfg, "expired-code")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "The authorization code has expired") {
		t.Errorf("expected error to contain provider message, got %q", err.Error())
	}
}

func TestExchange_InvalidJSON(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json"))
	}))
	defer mockServer.Close()

	cfg := Config{
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
	}

	_, err := Exchange(context.Background(), cfg, "code")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "invalid token response") {
		t.Errorf("expected error about invalid response, got %q", err.Error())
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
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	_, err := Refresh(context.Background(), cfg, "revoked-token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "Refresh token has been revoked") {
		t.Errorf("expected error about revoked token, got %q", err.Error())
	}
}

func TestDoTokenRequest_ConnectionError(t *testing.T) {
	cfg := Config{
		TokenURL:     "http://localhost:1",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	_, err := Refresh(context.Background(), cfg, "token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to contact provider") {
		t.Errorf("expected connection error, got %q", err.Error())
	}
}

func TestDoTokenRequest_InvalidURL(t *testing.T) {
	cfg := Config{
		TokenURL:     "://invalid",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	_, err := Refresh(context.Background(), cfg, "token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to create request") {
		t.Errorf("expected request creation error, got %q", err.Error())
	}
}

func TestDoTokenRequest_NonJSONError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("<html>Service Unavailable</html>"))
	}))
	defer mockServer.Close()

	cfg := Config{
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	_, err := Refresh(context.Background(), cfg, "token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "token request failed with status 503") {
		t.Errorf("expected status error, got %q", err.Error())
	}
}

func TestDoTokenRequest_ErrorWithoutDescription(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid_request",
		})
	}))
	defer mockServer.Close()

	cfg := Config{
		TokenURL:     mockServer.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	_, err := Refresh(context.Background(), cfg, "token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "invalid_request") {
		t.Errorf("expected error code as reason, got %q", err.Error())
	}
}

func TestDefaults(t *testing.T) {
	cfg := Config{}
	cfg.defaults()

	if cfg.HTTPClient == nil {
		t.Error("expected default HTTPClient")
	}
}
