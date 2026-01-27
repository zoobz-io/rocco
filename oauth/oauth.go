// Package oauth provides OAuth 2.0 authentication handlers for rocco-based APIs.
//
// This package provides login and callback handlers that implement the OAuth 2.0
// authorization code flow. It is provider-agnostic and works with any OAuth 2.0
// compliant provider (GitHub, Google, Auth0, etc.).
//
// # Basic Usage
//
// Configure the OAuth flow and create handlers:
//
//	cfg := oauth.GitHub()
//	cfg.ClientID = os.Getenv("GITHUB_CLIENT_ID")
//	cfg.ClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
//	cfg.RedirectURI = "https://myapp.com/auth/callback"
//	cfg.GenerateState = myapp.GenerateState
//	cfg.VerifyState = myapp.VerifyState
//	cfg.OnSuccess = func(ctx context.Context, tokens *oauth.TokenResponse) error {
//	    return db.StoreTokens(ctx, tokens)
//	}
//
//	login := oauth.NewLoginHandler("/auth/github", cfg)
//	callback := oauth.NewCallbackHandler("/auth/github/callback", cfg,
//	    func(tokens *oauth.TokenResponse) (rocco.Redirect, error) {
//	        return rocco.Redirect{URL: "/dashboard"}, nil
//	    })
//
//	engine.WithHandlers(login, callback)
package oauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Config defines OAuth 2.0 settings and application callbacks.
type Config struct {
	// Provider endpoints
	Name     string // Provider name for errors/logging (e.g., "github")
	AuthURL  string // Authorization endpoint (e.g., "https://github.com/login/oauth/authorize")
	TokenURL string // Token exchange endpoint (e.g., "https://github.com/login/oauth/access_token")

	// Application credentials
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string

	// Application callbacks (required)
	//
	// GenerateState creates a random state parameter for CSRF protection.
	// The state should be stored (e.g., in session) for verification in the callback.
	GenerateState func(ctx context.Context) (string, error)

	// VerifyState checks that the state parameter matches what was generated.
	// Returns true if valid, false if invalid or expired.
	VerifyState func(ctx context.Context, state string) (bool, error)

	// OnSuccess is called after successful token exchange.
	// Use this to store tokens, create sessions, etc.
	OnSuccess func(ctx context.Context, tokens *TokenResponse) error

	// Optional settings
	HTTPClient *http.Client // Default: 10s timeout client
}

// defaults applies default values to the config.
func (c *Config) defaults() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
}

// validate returns an error if required fields are missing.
func (c *Config) validate() error {
	if c.AuthURL == "" {
		return errors.New("oauth: AuthURL is required")
	}
	if c.TokenURL == "" {
		return errors.New("oauth: TokenURL is required")
	}
	if c.ClientID == "" {
		return errors.New("oauth: ClientID is required")
	}
	if c.ClientSecret == "" {
		return errors.New("oauth: ClientSecret is required")
	}
	if c.RedirectURI == "" {
		return errors.New("oauth: RedirectURI is required")
	}
	if c.GenerateState == nil {
		return errors.New("oauth: GenerateState callback is required")
	}
	if c.VerifyState == nil {
		return errors.New("oauth: VerifyState callback is required")
	}
	if c.OnSuccess == nil {
		return errors.New("oauth: OnSuccess callback is required")
	}
	return nil
}

// TokenResponse represents the OAuth 2.0 token response from a provider.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// GitHub returns a Config pre-filled with GitHub's OAuth endpoints.
// You must still set ClientID, ClientSecret, RedirectURI, and the callback functions.
func GitHub() Config {
	return Config{
		Name:     "github",
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	}
}

// GitHubEnterprise returns a Config for GitHub Enterprise Server.
// The baseURL should be the root URL of your GHE instance (e.g., "https://github.mycompany.com").
func GitHubEnterprise(baseURL string) Config {
	return Config{
		Name:     "github-enterprise",
		AuthURL:  baseURL + "/login/oauth/authorize",
		TokenURL: baseURL + "/login/oauth/access_token",
	}
}
