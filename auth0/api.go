// Package auth0 provides Auth0 JWT authentication for rocco-based APIs.
//
// This package provides a drop-in identity extractor for use with rocco.NewEngine
// that validates Auth0-issued JWT tokens and extracts identity information.
//
// # Basic Usage
//
// Create an extractor and pass it to rocco.NewEngine:
//
//	extractor, err := auth0.NewExtractor(auth0.Config{
//	    Domain:   "your-tenant.auth0.com",
//	    Audience: "https://your-api.example.com",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	engine := rocco.NewEngine("", 8080, extractor)
//
// # Advanced Usage
//
// For more control, create a Validator directly:
//
//	validator, err := auth0.NewValidator(auth0.Config{
//	    Domain:      "your-tenant.auth0.com",
//	    Audience:    "https://your-api.example.com",
//	    RolesClaim:  "https://myapp.com/roles",
//	    TenantClaim: "https://myapp.com/tenant_id",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	engine := rocco.NewEngine("", 8080, validator.Extractor())
package auth0

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zoobzio/clockz"
	"github.com/zoobzio/rocco"
)

// Config holds Auth0 integration settings.
type Config struct {
	// Domain is the Auth0 tenant domain (e.g., "your-tenant.auth0.com").
	// Required.
	Domain string

	// Audience is the API identifier configured in Auth0 (e.g., "https://api.example.com").
	// Required.
	Audience string

	// RolesClaim is the claim path for roles. Default: "roles".
	// Auth0 typically uses a namespaced claim like "https://myapp.com/roles".
	RolesClaim string

	// ScopesClaim is the claim path for scopes. Default: "scope".
	ScopesClaim string

	// TenantClaim is the claim path for multi-tenancy. Optional.
	// If set, the value will be extracted to Identity.TenantID().
	TenantClaim string

	// JWKSRefreshInterval controls how often the JWKS is refreshed.
	// Default: 1 hour.
	JWKSRefreshInterval time.Duration

	// Clock provides time for testing. Default: clockz.RealClock.
	Clock clockz.Clock

	// HTTPClient is used for JWKS requests. Default: client with 10s timeout.
	HTTPClient *http.Client

	// jwksURL is used internally for testing to override the JWKS endpoint.
	jwksURL string
}

// defaults applies default values to the config.
func (c *Config) defaults() {
	if c.RolesClaim == "" {
		c.RolesClaim = "roles"
	}
	if c.ScopesClaim == "" {
		c.ScopesClaim = "scope"
	}
	if c.JWKSRefreshInterval == 0 {
		c.JWKSRefreshInterval = time.Hour
	}
	if c.Clock == nil {
		c.Clock = clockz.RealClock
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
}

// validate returns an error if required fields are missing.
func (c *Config) validate() error {
	if c.Domain == "" {
		return errors.New("auth0: Domain is required")
	}
	if c.Audience == "" {
		return errors.New("auth0: Audience is required")
	}
	return nil
}

// Identity implements rocco.Identity from JWT claims.
type Identity struct {
	subject   string
	tenant    string
	email     string
	roles     []string
	scopes    []string
	claims    map[string]any
	expiresAt time.Time
}

// ID returns the subject claim (unique identifier).
func (i *Identity) ID() string {
	return i.subject
}

// TenantID returns the tenant identifier if configured.
func (i *Identity) TenantID() string {
	return i.tenant
}

// HasScope checks if the identity has the given scope.
func (i *Identity) HasScope(scope string) bool {
	for _, s := range i.scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole checks if the identity has the given role.
func (i *Identity) HasRole(role string) bool {
	for _, r := range i.roles {
		if r == role {
			return true
		}
	}
	return false
}

// Stats returns nil as JWT claims don't contain usage metrics.
// Compose with your own stats provider if needed.
func (i *Identity) Stats() map[string]int {
	return nil
}

// Email returns the email claim if present.
func (i *Identity) Email() string {
	return i.email
}

// Scopes returns all scopes.
func (i *Identity) Scopes() []string {
	return i.scopes
}

// Roles returns all roles.
func (i *Identity) Roles() []string {
	return i.roles
}

// ExpiresAt returns the token expiration time.
func (i *Identity) ExpiresAt() time.Time {
	return i.expiresAt
}

// Claim returns a raw claim value by name.
func (i *Identity) Claim(name string) (any, bool) {
	v, ok := i.claims[name]
	return v, ok
}

// Claims returns all claims.
func (i *Identity) Claims() map[string]any {
	return i.claims
}

// Ensure Identity implements rocco.Identity.
var _ rocco.Identity = (*Identity)(nil)

// NewExtractor creates an identity extractor function for use with rocco.NewEngine.
// This is the simplest way to integrate Auth0 authentication.
func NewExtractor(cfg Config) (func(context.Context, *http.Request) (rocco.Identity, error), error) {
	v, err := NewValidator(cfg)
	if err != nil {
		return nil, err
	}
	return v.Extractor(), nil
}

// WithJWKSURL sets a custom JWKS URL, primarily for testing.
func (c Config) WithJWKSURL(url string) Config {
	c.jwksURL = url
	return c
}
