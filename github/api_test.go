package github

import (
	"net/http"
	"testing"
	"time"

	"github.com/zoobzio/clockz"
)

func TestConfig_defaults(t *testing.T) {
	cfg := Config{}
	cfg.defaults()

	if cfg.CacheTTL != 5*time.Minute {
		t.Errorf("CacheTTL = %v, want %v", cfg.CacheTTL, 5*time.Minute)
	}
	if cfg.HTTPClient == nil {
		t.Error("HTTPClient should not be nil")
	}
	if cfg.BaseURL != "https://api.github.com" {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, "https://api.github.com")
	}
	if cfg.Clock == nil {
		t.Error("Clock should not be nil")
	}
}

func TestConfig_defaults_preserves_custom_values(t *testing.T) {
	customClient := &http.Client{Timeout: 30 * time.Second}
	customClock := clockz.NewFakeClockAt(time.Now())

	cfg := Config{
		CacheTTL:   10 * time.Minute,
		HTTPClient: customClient,
		BaseURL:    "https://github.example.com/api/v3",
		Clock:      customClock,
	}
	cfg.defaults()

	if cfg.CacheTTL != 10*time.Minute {
		t.Errorf("CacheTTL = %v, want %v", cfg.CacheTTL, 10*time.Minute)
	}
	if cfg.HTTPClient != customClient {
		t.Error("HTTPClient should be preserved")
	}
	if cfg.BaseURL != "https://github.example.com/api/v3" {
		t.Errorf("BaseURL = %q, want custom value", cfg.BaseURL)
	}
	if cfg.Clock != customClock {
		t.Error("Clock should be preserved")
	}
}

func TestConfig_validate(t *testing.T) {
	cfg := Config{}
	if err := cfg.validate(); err != nil {
		t.Errorf("validate() error = %v, want nil", err)
	}
}

func TestConfig_WithBaseURL(t *testing.T) {
	cfg := Config{}
	cfg = cfg.WithBaseURL("https://github.example.com/api/v3")

	if cfg.BaseURL != "https://github.example.com/api/v3" {
		t.Errorf("BaseURL = %q, want custom value", cfg.BaseURL)
	}
}

func TestIdentity_ID(t *testing.T) {
	i := &Identity{userID: "12345"}
	if got := i.ID(); got != "12345" {
		t.Errorf("ID() = %q, want %q", got, "12345")
	}
}

func TestIdentity_TenantID(t *testing.T) {
	i := &Identity{tenant: "acme-corp"}
	if got := i.TenantID(); got != "acme-corp" {
		t.Errorf("TenantID() = %q, want %q", got, "acme-corp")
	}
}

func TestIdentity_Email(t *testing.T) {
	i := &Identity{email: "test@example.com"}
	if got := i.Email(); got != "test@example.com" {
		t.Errorf("Email() = %q, want %q", got, "test@example.com")
	}
}

func TestIdentity_Scopes(t *testing.T) {
	i := &Identity{scopes: []string{"read:user", "read:org"}}
	scopes := i.Scopes()

	if len(scopes) != 2 {
		t.Errorf("Scopes() len = %d, want 2", len(scopes))
	}
	if scopes[0] != "read:user" || scopes[1] != "read:org" {
		t.Errorf("Scopes() = %v, want [read:user read:org]", scopes)
	}
}

func TestIdentity_Roles(t *testing.T) {
	i := &Identity{roles: []string{"github:user", "org:acme-corp"}}
	roles := i.Roles()

	if len(roles) != 2 {
		t.Errorf("Roles() len = %d, want 2", len(roles))
	}
}

func TestIdentity_HasScope(t *testing.T) {
	i := &Identity{scopes: []string{"read:user", "read:org"}}

	if !i.HasScope("read:user") {
		t.Error("HasScope(read:user) = false, want true")
	}
	if !i.HasScope("read:org") {
		t.Error("HasScope(read:org) = false, want true")
	}
	if i.HasScope("write:user") {
		t.Error("HasScope(write:user) = true, want false")
	}
}

func TestIdentity_HasRole(t *testing.T) {
	i := &Identity{roles: []string{"github:user", "org:acme-corp"}}

	if !i.HasRole("github:user") {
		t.Error("HasRole(github:user) = false, want true")
	}
	if !i.HasRole("org:acme-corp") {
		t.Error("HasRole(org:acme-corp) = false, want true")
	}
	if i.HasRole("org:other") {
		t.Error("HasRole(org:other) = true, want false")
	}
}

func TestIdentity_Stats(t *testing.T) {
	i := &Identity{}
	if got := i.Stats(); got != nil {
		t.Errorf("Stats() = %v, want nil", got)
	}
}

func TestIdentity_Login(t *testing.T) {
	i := &Identity{login: "testuser"}
	if got := i.Login(); got != "testuser" {
		t.Errorf("Login() = %q, want %q", got, "testuser")
	}
}

func TestIdentity_Name(t *testing.T) {
	i := &Identity{name: "Test User"}
	if got := i.Name(); got != "Test User" {
		t.Errorf("Name() = %q, want %q", got, "Test User")
	}
}

func TestIdentity_AvatarURL(t *testing.T) {
	i := &Identity{avatarURL: "https://github.com/avatar.png"}
	if got := i.AvatarURL(); got != "https://github.com/avatar.png" {
		t.Errorf("AvatarURL() = %q, want %q", got, "https://github.com/avatar.png")
	}
}

func TestIdentity_Organizations(t *testing.T) {
	i := &Identity{orgs: []string{"acme-corp", "other-org"}}
	orgs := i.Organizations()

	if len(orgs) != 2 {
		t.Errorf("Organizations() len = %d, want 2", len(orgs))
	}
}

func TestIdentity_Teams(t *testing.T) {
	i := &Identity{teams: []string{"acme-corp/developers", "acme-corp/admins"}}
	teams := i.Teams()

	if len(teams) != 2 {
		t.Errorf("Teams() len = %d, want 2", len(teams))
	}
}

func TestIdentity_CachedAt(t *testing.T) {
	now := time.Now()
	i := &Identity{cachedAt: now}
	if got := i.CachedAt(); !got.Equal(now) {
		t.Errorf("CachedAt() = %v, want %v", got, now)
	}
}

func TestIdentity_Raw(t *testing.T) {
	user := &GitHubUser{ID: 12345, Login: "testuser"}
	i := &Identity{raw: user}
	if got := i.Raw(); got != user {
		t.Error("Raw() should return the original user")
	}
}
