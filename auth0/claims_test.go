package auth0

import (
	"reflect"
	"testing"
	"time"
)

func TestExtractIdentity(t *testing.T) {
	cfg := &Config{
		RolesClaim:  "roles",
		ScopesClaim: "scope",
		TenantClaim: "tenant_id",
	}

	claims := map[string]any{
		"sub":       "user-123",
		"email":     "user@example.com",
		"exp":       float64(1234567890),
		"roles":     []any{"admin", "user"},
		"scope":     "read:users write:users",
		"tenant_id": "tenant-456",
	}

	identity := extractIdentity(claims, cfg)

	if identity.subject != "user-123" {
		t.Errorf("subject = %q, want %q", identity.subject, "user-123")
	}
	if identity.email != "user@example.com" {
		t.Errorf("email = %q, want %q", identity.email, "user@example.com")
	}
	if identity.tenant != "tenant-456" {
		t.Errorf("tenant = %q, want %q", identity.tenant, "tenant-456")
	}
	if identity.expiresAt.Unix() != 1234567890 {
		t.Errorf("expiresAt = %v, want Unix 1234567890", identity.expiresAt)
	}
	if !reflect.DeepEqual(identity.roles, []string{"admin", "user"}) {
		t.Errorf("roles = %v, want [admin user]", identity.roles)
	}
	if !reflect.DeepEqual(identity.scopes, []string{"read:users", "write:users"}) {
		t.Errorf("scopes = %v, want [read:users write:users]", identity.scopes)
	}
}

func TestExtractIdentity_no_tenant_claim(t *testing.T) {
	cfg := &Config{
		RolesClaim:  "roles",
		ScopesClaim: "scope",
		// TenantClaim not set
	}

	claims := map[string]any{
		"sub":       "user-123",
		"tenant_id": "tenant-456", // Present in claims but not configured
	}

	identity := extractIdentity(claims, cfg)

	if identity.tenant != "" {
		t.Errorf("tenant = %q, want empty (TenantClaim not configured)", identity.tenant)
	}
}

func TestExtractIdentity_custom_claims(t *testing.T) {
	cfg := &Config{
		RolesClaim:  "https://myapp.com/roles",
		ScopesClaim: "permissions",
		TenantClaim: "https://myapp.com/tenant",
	}

	claims := map[string]any{
		"sub":                      "user-123",
		"https://myapp.com/roles":  []any{"superadmin"},
		"permissions":              "admin:all",
		"https://myapp.com/tenant": "acme-corp",
	}

	identity := extractIdentity(claims, cfg)

	if !reflect.DeepEqual(identity.roles, []string{"superadmin"}) {
		t.Errorf("roles = %v, want [superadmin]", identity.roles)
	}
	if !reflect.DeepEqual(identity.scopes, []string{"admin:all"}) {
		t.Errorf("scopes = %v, want [admin:all]", identity.scopes)
	}
	if identity.tenant != "acme-corp" {
		t.Errorf("tenant = %q, want %q", identity.tenant, "acme-corp")
	}
}

func TestExtractString(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		want   string
	}{
		{
			name:   "string value",
			claims: map[string]any{"key": "value"},
			key:    "key",
			want:   "value",
		},
		{
			name:   "missing key",
			claims: map[string]any{},
			key:    "key",
			want:   "",
		},
		{
			name:   "non-string value",
			claims: map[string]any{"key": 123},
			key:    "key",
			want:   "",
		},
		{
			name:   "nil value",
			claims: map[string]any{"key": nil},
			key:    "key",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractString(tt.claims, tt.key)
			if got != tt.want {
				t.Errorf("extractString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractStringSlice(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		want   []string
	}{
		{
			name:   "[]any slice",
			claims: map[string]any{"roles": []any{"admin", "user"}},
			key:    "roles",
			want:   []string{"admin", "user"},
		},
		{
			name:   "[]string slice",
			claims: map[string]any{"roles": []string{"admin", "user"}},
			key:    "roles",
			want:   []string{"admin", "user"},
		},
		{
			name:   "single string",
			claims: map[string]any{"roles": "admin"},
			key:    "roles",
			want:   []string{"admin"},
		},
		{
			name:   "empty string",
			claims: map[string]any{"roles": ""},
			key:    "roles",
			want:   nil,
		},
		{
			name:   "missing key",
			claims: map[string]any{},
			key:    "roles",
			want:   nil,
		},
		{
			name:   "mixed types in slice",
			claims: map[string]any{"roles": []any{"admin", 123, "user"}},
			key:    "roles",
			want:   []string{"admin", "user"}, // Non-strings skipped
		},
		{
			name:   "non-slice non-string value",
			claims: map[string]any{"roles": 123},
			key:    "roles",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStringSlice(tt.claims, tt.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractStringSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractTime(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		want   time.Time
	}{
		{
			name:   "float64 timestamp",
			claims: map[string]any{"exp": float64(1234567890)},
			key:    "exp",
			want:   time.Unix(1234567890, 0),
		},
		{
			name:   "int64 timestamp",
			claims: map[string]any{"exp": int64(1234567890)},
			key:    "exp",
			want:   time.Unix(1234567890, 0),
		},
		{
			name:   "int timestamp",
			claims: map[string]any{"exp": int(1234567890)},
			key:    "exp",
			want:   time.Unix(1234567890, 0),
		},
		{
			name:   "missing key",
			claims: map[string]any{},
			key:    "exp",
			want:   time.Time{},
		},
		{
			name:   "string value",
			claims: map[string]any{"exp": "1234567890"},
			key:    "exp",
			want:   time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTime(tt.claims, tt.key)
			if !got.Equal(tt.want) {
				t.Errorf("extractTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractIdentity_scopes_split(t *testing.T) {
	cfg := &Config{
		ScopesClaim: "scope",
	}

	tests := []struct {
		name  string
		scope string
		want  []string
	}{
		{
			name:  "multiple scopes",
			scope: "read:users write:users delete:users",
			want:  []string{"read:users", "write:users", "delete:users"},
		},
		{
			name:  "single scope",
			scope: "read:users",
			want:  []string{"read:users"},
		},
		{
			name:  "empty scope",
			scope: "",
			want:  nil,
		},
		{
			name:  "extra whitespace",
			scope: "read:users   write:users",
			want:  []string{"read:users", "write:users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]any{"scope": tt.scope}
			identity := extractIdentity(claims, cfg)

			if !reflect.DeepEqual(identity.scopes, tt.want) {
				t.Errorf("scopes = %v, want %v", identity.scopes, tt.want)
			}
		})
	}
}

func TestExtractIdentity_scopes_array(t *testing.T) {
	cfg := &Config{ScopesClaim: "scope"}

	tests := []struct {
		name   string
		scopes any
		want   []string
	}{
		{
			name:   "string array",
			scopes: []string{"read:users", "write:users"},
			want:   []string{"read:users", "write:users"},
		},
		{
			name:   "any array",
			scopes: []any{"read:users", "write:users", "delete:users"},
			want:   []string{"read:users", "write:users", "delete:users"},
		},
		{
			name:   "single element array",
			scopes: []any{"read:users"},
			want:   []string{"read:users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]any{"scope": tt.scopes}
			identity := extractIdentity(claims, cfg)

			if !reflect.DeepEqual(identity.scopes, tt.want) {
				t.Errorf("scopes = %v, want %v", identity.scopes, tt.want)
			}
		})
	}
}

func TestExtractIdentity_preserves_claims(t *testing.T) {
	cfg := &Config{}

	claims := map[string]any{
		"sub":         "user-123",
		"custom_data": map[string]any{"key": "value"},
		"number":      float64(42),
	}

	identity := extractIdentity(claims, cfg)

	if identity.claims["sub"] != "user-123" {
		t.Error("claims should preserve sub")
	}
	if identity.claims["number"] != float64(42) {
		t.Error("claims should preserve number")
	}
	customData, ok := identity.claims["custom_data"].(map[string]any)
	if !ok {
		t.Error("claims should preserve custom_data type")
	}
	if customData["key"] != "value" {
		t.Error("claims should preserve nested values")
	}
}
