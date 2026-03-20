package auth0

import (
	"testing"
	"time"

	"github.com/zoobz-io/clockz"
)

func TestConfig_defaults(t *testing.T) {
	cfg := Config{
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}
	cfg.defaults()

	if cfg.RolesClaim != "roles" {
		t.Errorf("RolesClaim = %q, want %q", cfg.RolesClaim, "roles")
	}
	if cfg.ScopesClaim != "scope" {
		t.Errorf("ScopesClaim = %q, want %q", cfg.ScopesClaim, "scope")
	}
	if cfg.JWKSRefreshInterval != time.Hour {
		t.Errorf("JWKSRefreshInterval = %v, want %v", cfg.JWKSRefreshInterval, time.Hour)
	}
	if cfg.Clock == nil {
		t.Error("Clock should not be nil after defaults")
	}
}

func TestConfig_defaults_preserves_custom_values(t *testing.T) {
	clock := clockz.NewFakeClockAt(time.Now())
	cfg := Config{
		Domain:              "test.auth0.com",
		Audience:            "https://api.test.com",
		RolesClaim:          "custom_roles",
		ScopesClaim:         "custom_scope",
		JWKSRefreshInterval: 30 * time.Minute,
		Clock:               clock,
	}
	cfg.defaults()

	if cfg.RolesClaim != "custom_roles" {
		t.Errorf("RolesClaim = %q, want %q", cfg.RolesClaim, "custom_roles")
	}
	if cfg.ScopesClaim != "custom_scope" {
		t.Errorf("ScopesClaim = %q, want %q", cfg.ScopesClaim, "custom_scope")
	}
	if cfg.JWKSRefreshInterval != 30*time.Minute {
		t.Errorf("JWKSRefreshInterval = %v, want %v", cfg.JWKSRefreshInterval, 30*time.Minute)
	}
	if cfg.Clock != clock {
		t.Error("Clock should be preserved")
	}
}

func TestConfig_validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			cfg: Config{
				Domain:   "test.auth0.com",
				Audience: "https://api.test.com",
			},
			wantErr: false,
		},
		{
			name: "missing domain",
			cfg: Config{
				Audience: "https://api.test.com",
			},
			wantErr: true,
			errMsg:  "auth0: Domain is required",
		},
		{
			name: "missing audience",
			cfg: Config{
				Domain: "test.auth0.com",
			},
			wantErr: true,
			errMsg:  "auth0: Audience is required",
		},
		{
			name:    "both missing",
			cfg:     Config{},
			wantErr: true,
			errMsg:  "auth0: Domain is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("validate() error = nil, want error containing %q", tt.errMsg)
				} else if err.Error() != tt.errMsg {
					t.Errorf("validate() error = %q, want %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("validate() unexpected error = %v", err)
			}
		})
	}
}

func TestConfig_WithJWKSURL(t *testing.T) {
	cfg := Config{
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}

	newCfg := cfg.WithJWKSURL("http://localhost:8080/jwks")

	if newCfg.jwksURL != "http://localhost:8080/jwks" {
		t.Errorf("jwksURL = %q, want %q", newCfg.jwksURL, "http://localhost:8080/jwks")
	}
	// Original should be unchanged
	if cfg.jwksURL != "" {
		t.Errorf("original jwksURL = %q, want empty", cfg.jwksURL)
	}
}

func TestIdentity_methods(t *testing.T) {
	identity := &Identity{
		subject:   "user-123",
		tenant:    "tenant-456",
		email:     "user@example.com",
		roles:     []string{"admin", "user"},
		scopes:    []string{"read:users", "write:users"},
		expiresAt: time.Unix(1234567890, 0),
		claims: map[string]any{
			"sub":   "user-123",
			"email": "user@example.com",
			"custom": "value",
		},
	}

	t.Run("ID", func(t *testing.T) {
		if got := identity.ID(); got != "user-123" {
			t.Errorf("ID() = %q, want %q", got, "user-123")
		}
	})

	t.Run("TenantID", func(t *testing.T) {
		if got := identity.TenantID(); got != "tenant-456" {
			t.Errorf("TenantID() = %q, want %q", got, "tenant-456")
		}
	})

	t.Run("Email", func(t *testing.T) {
		if got := identity.Email(); got != "user@example.com" {
			t.Errorf("Email() = %q, want %q", got, "user@example.com")
		}
	})

	t.Run("HasScope", func(t *testing.T) {
		if !identity.HasScope("read:users") {
			t.Error("HasScope(read:users) = false, want true")
		}
		if identity.HasScope("delete:users") {
			t.Error("HasScope(delete:users) = true, want false")
		}
	})

	t.Run("HasRole", func(t *testing.T) {
		if !identity.HasRole("admin") {
			t.Error("HasRole(admin) = false, want true")
		}
		if identity.HasRole("superadmin") {
			t.Error("HasRole(superadmin) = true, want false")
		}
	})

	t.Run("Stats", func(t *testing.T) {
		if got := identity.Stats(); got != nil {
			t.Errorf("Stats() = %v, want nil", got)
		}
	})

	t.Run("Scopes", func(t *testing.T) {
		scopes := identity.Scopes()
		if len(scopes) != 2 {
			t.Errorf("Scopes() len = %d, want 2", len(scopes))
		}
	})

	t.Run("Roles", func(t *testing.T) {
		roles := identity.Roles()
		if len(roles) != 2 {
			t.Errorf("Roles() len = %d, want 2", len(roles))
		}
	})

	t.Run("ExpiresAt", func(t *testing.T) {
		if got := identity.ExpiresAt(); got.Unix() != 1234567890 {
			t.Errorf("ExpiresAt() = %v, want Unix 1234567890", got)
		}
	})

	t.Run("Claim", func(t *testing.T) {
		v, ok := identity.Claim("custom")
		if !ok {
			t.Error("Claim(custom) not found")
		}
		if v != "value" {
			t.Errorf("Claim(custom) = %v, want %q", v, "value")
		}

		_, ok = identity.Claim("nonexistent")
		if ok {
			t.Error("Claim(nonexistent) should not exist")
		}
	})

	t.Run("Claims", func(t *testing.T) {
		claims := identity.Claims()
		if len(claims) != 3 {
			t.Errorf("Claims() len = %d, want 3", len(claims))
		}
	})
}

func TestIdentity_empty(t *testing.T) {
	identity := &Identity{}

	if identity.ID() != "" {
		t.Errorf("ID() = %q, want empty", identity.ID())
	}
	if identity.HasScope("any") {
		t.Error("HasScope should return false for empty identity")
	}
	if identity.HasRole("any") {
		t.Error("HasRole should return false for empty identity")
	}
}

func TestNewExtractor_validation(t *testing.T) {
	_, err := NewExtractor(Config{})
	if err == nil {
		t.Error("NewExtractor with empty config should fail")
	}

	_, err = NewExtractor(Config{Domain: "test.auth0.com"})
	if err == nil {
		t.Error("NewExtractor without audience should fail")
	}
}
