// Package oauth provides OAuth 2.0 protocol functions for the authorization code flow.
//
// This package is provider-agnostic and handles the protocol mechanics:
// building authorization URLs, exchanging codes for tokens, and refreshing tokens.
// It does not handle HTTP handlers, sessions, or cookies — those belong in higher-level packages.
//
// # Basic Usage
//
//	cfg := oauth.GitHub()
//	cfg.ClientID = os.Getenv("GITHUB_CLIENT_ID")
//	cfg.ClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
//	cfg.RedirectURI = "https://myapp.com/auth/callback"
//
//	// Build the authorization URL for redirecting users to the provider.
//	authURL, err := oauth.AuthURL(cfg, state)
//
//	// Exchange the authorization code for tokens after the provider redirects back.
//	tokens, err := oauth.Exchange(ctx, cfg, code)
//
//	// Refresh an expired access token.
//	newTokens, err := oauth.Refresh(ctx, cfg, refreshToken)
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config defines OAuth 2.0 provider configuration and application credentials.
type Config struct {
	// Provider endpoints
	Name     string // Provider name for logging (e.g., "github")
	AuthURL  string // Authorization endpoint (e.g., "https://github.com/login/oauth/authorize")
	TokenURL string // Token exchange endpoint (e.g., "https://github.com/login/oauth/access_token")

	// Application credentials
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string

	// Optional settings
	HTTPClient *http.Client // Default: 10s timeout client
}

// defaults applies default values to the config.
func (c *Config) defaults() {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
}

// Validate returns an error if required fields are missing.
func (c *Config) Validate() error {
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

// AuthURL constructs the OAuth authorization URL with the given state parameter.
func AuthURL(cfg Config, state string) (string, error) {
	u, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return "", fmt.Errorf("oauth: invalid AuthURL: %w", err)
	}

	q := u.Query()
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("state", state)
	q.Set("response_type", "code")

	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange trades an authorization code for access and refresh tokens.
func Exchange(ctx context.Context, cfg Config, code string) (*TokenResponse, error) {
	cfg.defaults()

	data := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	}

	return doTokenRequest(ctx, cfg, data)
}

// Refresh exchanges a refresh token for new access and refresh tokens.
func Refresh(ctx context.Context, cfg Config, refreshToken string) (*TokenResponse, error) {
	cfg.defaults()

	data := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	return doTokenRequest(ctx, cfg, data)
}

// GitHub returns a Config pre-filled with GitHub's OAuth endpoints.
// You must still set ClientID, ClientSecret, and RedirectURI.
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

// doTokenRequest performs a token request to the OAuth provider.
func doTokenRequest(ctx context.Context, cfg Config, data url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to contact provider: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			reason := errResp.ErrorDescription
			if reason == "" {
				reason = errResp.Error
			}
			return nil, fmt.Errorf("oauth: provider error: %s", reason)
		}
		return nil, fmt.Errorf("oauth: token request failed with status %d", resp.StatusCode)
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("oauth: invalid token response: %w", err)
	}

	return &tokens, nil
}
