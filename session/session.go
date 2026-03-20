// Package session provides cookie-based session management for rocco APIs.
//
// This package bridges [rocco/oauth] with [rocco.Identity] by managing the full
// lifecycle: OAuth login, session creation, identity extraction, and logout.
//
// # Basic Usage
//
//	store := session.NewMemoryStore()
//	cfg := session.Config{
//	    OAuth: oauth.GitHub(),
//	    Store: store,
//	    Cookie: session.CookieConfig{
//	        SignKey: []byte(os.Getenv("SESSION_KEY")),
//	    },
//	    Resolve: func(ctx context.Context, tokens *oauth.TokenResponse) (*session.Data, error) {
//	        // Call provider API to get user info, build session data.
//	        return &session.Data{UserID: "123", Email: "user@example.com"}, nil
//	    },
//	    RedirectURL: "/dashboard",
//	}
//	cfg.OAuth.ClientID = os.Getenv("CLIENT_ID")
//	cfg.OAuth.ClientSecret = os.Getenv("CLIENT_SECRET")
//	cfg.OAuth.RedirectURI = "https://myapp.com/auth/callback"
//
//	login, _ := session.NewLoginHandler("/auth/login", cfg)
//	callback, _ := session.NewCallbackHandler("/auth/callback", cfg)
//	logout, _ := session.NewLogoutHandler("/auth/logout", cfg, "/")
//
//	engine := rocco.NewEngine()
//	engine.WithAuthenticator(session.Extractor(store, cfg.Cookie))
//	engine.WithHandlers(login, callback, logout)
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zoobz-io/rocco/oauth"
)

// Config holds all session configuration for an OAuth-backed session flow.
type Config struct {
	// OAuth provider configuration.
	OAuth oauth.Config

	// Store manages session and state persistence.
	Store Store

	// Cookie controls session cookie behavior.
	Cookie CookieConfig

	// Resolve maps OAuth tokens to session data. This is where the application
	// calls the provider's user-info API, looks up roles, etc.
	Resolve func(ctx context.Context, tokens *oauth.TokenResponse) (*Data, error)

	// RedirectURL is where the user is sent after successful login.
	RedirectURL string
}

// validate returns an error if required fields are missing.
func (c *Config) validate() error {
	if err := c.OAuth.Validate(); err != nil {
		return err
	}
	if c.Store == nil {
		return errors.New("session: Store is required")
	}
	if len(c.Cookie.SignKey) == 0 {
		return errors.New("session: Cookie.SignKey is required")
	}
	if c.Resolve == nil {
		return errors.New("session: Resolve is required")
	}
	if c.RedirectURL == "" {
		return errors.New("session: RedirectURL is required")
	}
	return nil
}

// generateID creates a cryptographically random session ID.
func generateID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: failed to generate ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateState returns a function that creates a cryptographic state token
// and stores it via the given [Store]. Compatible with external state management needs.
func GenerateState(store Store) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("session: failed to generate state: %w", err)
		}
		state := hex.EncodeToString(b)
		if err := store.CreateState(ctx, state); err != nil {
			return "", fmt.Errorf("session: failed to store state: %w", err)
		}
		return state, nil
	}
}

// VerifyState returns a function that verifies a state token against the given [Store].
// The state is consumed on verification (single-use).
func VerifyState(store Store) func(context.Context, string) (bool, error) {
	return func(ctx context.Context, state string) (bool, error) {
		return store.VerifyState(ctx, state)
	}
}
