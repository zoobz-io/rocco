// Package github provides GitHub OAuth token authentication for rocco-based APIs.
//
// This package provides a drop-in identity extractor for use with rocco.NewEngine
// that validates GitHub access tokens via the GitHub API and extracts identity information.
//
// # Basic Usage
//
// Create an extractor and pass it to rocco.NewEngine:
//
//	extractor, err := github.NewExtractor(github.Config{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	engine := rocco.NewEngine("", 8080, extractor)
//
// # Restricting Access by Organization
//
// To restrict access to members of specific organizations:
//
//	extractor, err := github.NewExtractor(github.Config{
//	    AllowedOrganizations: []string{"acme-corp", "partner-org"},
//	})
//
// # Restricting Access by Team
//
// To restrict access to members of specific teams:
//
//	extractor, err := github.NewExtractor(github.Config{
//	    AllowedTeams: []string{"acme-corp/developers", "acme-corp/admins"},
//	})
package github

import (
	"context"
	"net/http"
	"time"

	"github.com/zoobzio/clockz"
	"github.com/zoobzio/rocco"
)

// Config holds GitHub integration settings.
type Config struct {
	// AllowedOrganizations restricts access to members of these orgs.
	// If empty, any authenticated GitHub user is allowed.
	AllowedOrganizations []string

	// AllowedTeams restricts access to members of these teams.
	// Format: "org/team-slug" (e.g., "acme-corp/developers").
	// If empty, no team restriction is applied.
	AllowedTeams []string

	// CacheTTL controls how long user data is cached. Default: 5 minutes.
	CacheTTL time.Duration

	// HTTPClient is used for GitHub API requests. Default: client with 10s timeout.
	HTTPClient *http.Client

	// BaseURL is the GitHub API base URL. Default: "https://api.github.com".
	// Set to your GitHub Enterprise API URL if applicable.
	BaseURL string

	// Clock provides time for testing. Default: clockz.RealClock.
	Clock clockz.Clock

	// RequireVerifiedEmail requires the user to have a verified primary email.
	// Default: false.
	RequireVerifiedEmail bool
}

// defaults applies default values to the config.
func (c *Config) defaults() {
	if c.CacheTTL == 0 {
		c.CacheTTL = 5 * time.Minute
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if c.BaseURL == "" {
		c.BaseURL = "https://api.github.com"
	}
	if c.Clock == nil {
		c.Clock = clockz.RealClock
	}
}

// validate returns an error if required fields are missing.
func (c *Config) validate() error {
	// All fields are optional - validation of org/team membership happens at runtime
	return nil
}

// WithBaseURL sets a custom GitHub API base URL (for testing or GitHub Enterprise).
func (c Config) WithBaseURL(url string) Config {
	c.BaseURL = url
	return c
}

// Identity implements rocco.Identity from GitHub user data.
type Identity struct {
	userID    string
	login     string
	email     string
	tenant    string
	scopes    []string
	roles     []string
	orgs      []string
	teams     []string
	avatarURL string
	name      string
	cachedAt  time.Time
	raw       *GitHubUser
}

// ID returns the GitHub user ID.
func (i *Identity) ID() string {
	return i.userID
}

// TenantID returns the primary organization.
func (i *Identity) TenantID() string {
	return i.tenant
}

// Email returns the user's email.
func (i *Identity) Email() string {
	return i.email
}

// Scopes returns the OAuth scopes granted to the token.
func (i *Identity) Scopes() []string {
	return i.scopes
}

// Roles returns derived roles from org/team membership.
// Roles include:
//   - "github:user" for all authenticated users
//   - "org:<org-name>" for each organization
//   - "team:<org>/<team>" for each team
func (i *Identity) Roles() []string {
	return i.roles
}

// HasScope checks if the token has the given OAuth scope.
func (i *Identity) HasScope(scope string) bool {
	for _, s := range i.scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole checks if the user has the given role.
func (i *Identity) HasRole(role string) bool {
	for _, r := range i.roles {
		if r == role {
			return true
		}
	}
	return false
}

// Stats returns nil (GitHub API doesn't provide usage metrics).
func (i *Identity) Stats() map[string]int {
	return nil
}

// Login returns the GitHub username.
func (i *Identity) Login() string {
	return i.login
}

// Name returns the user's display name.
func (i *Identity) Name() string {
	return i.name
}

// AvatarURL returns the user's GitHub avatar URL.
func (i *Identity) AvatarURL() string {
	return i.avatarURL
}

// Organizations returns all organizations the user belongs to.
func (i *Identity) Organizations() []string {
	return i.orgs
}

// Teams returns all teams the user belongs to (org/team format).
func (i *Identity) Teams() []string {
	return i.teams
}

// CachedAt returns when this identity data was fetched.
func (i *Identity) CachedAt() time.Time {
	return i.cachedAt
}

// Raw returns the raw GitHub API user response.
func (i *Identity) Raw() *GitHubUser {
	return i.raw
}

// Ensure Identity implements rocco.Identity.
var _ rocco.Identity = (*Identity)(nil)

// NewExtractor creates an identity extractor function for use with rocco.NewEngine.
// This is the simplest way to integrate GitHub authentication.
func NewExtractor(cfg Config) (func(context.Context, *http.Request) (rocco.Identity, error), error) {
	v, err := NewValidator(cfg)
	if err != nil {
		return nil, err
	}
	return v.Extractor(), nil
}
