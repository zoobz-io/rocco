package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/zoobzio/capitan"
	"github.com/zoobzio/clockz"
	"github.com/zoobzio/rocco"
)

// TestMain sets up capitan in sync mode for all tests.
func TestMain(m *testing.M) {
	capitan.Configure(capitan.WithSyncMode())
	os.Exit(m.Run())
}

// mockGitHubServer creates a test server that mocks GitHub API responses.
func mockGitHubServer(t *testing.T, user *GitHubUser, orgs []GitHubOrg, teams []GitHubTeam, scopes string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", scopes)
			json.NewEncoder(w).Encode(user)
		case "/user/orgs":
			json.NewEncoder(w).Encode(orgs)
		case "/user/teams":
			json.NewEncoder(w).Encode(teams)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	t.Cleanup(server.Close)
	return server
}

func TestNewValidator(t *testing.T) {
	v, err := NewValidator(Config{})
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	if v == nil {
		t.Fatal("NewValidator() returned nil")
	}
}

func TestValidator_Validate_success(t *testing.T) {
	user := &GitHubUser{
		ID:        12345,
		Login:     "testuser",
		Email:     "test@example.com",
		Name:      "Test User",
		AvatarURL: "https://github.com/avatar.png",
	}
	orgs := []GitHubOrg{{ID: 1, Login: "acme-corp"}}

	server := mockGitHubServer(t, user, orgs, nil, "read:user, read:org")

	cfg := Config{}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	identity, err := v.Validate(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if identity.ID() != "12345" {
		t.Errorf("ID() = %q, want %q", identity.ID(), "12345")
	}
	if identity.Login() != "testuser" {
		t.Errorf("Login() = %q, want %q", identity.Login(), "testuser")
	}
	if identity.Email() != "test@example.com" {
		t.Errorf("Email() = %q, want %q", identity.Email(), "test@example.com")
	}
	if identity.Name() != "Test User" {
		t.Errorf("Name() = %q, want %q", identity.Name(), "Test User")
	}
	if !identity.HasScope("read:user") {
		t.Error("HasScope(read:user) = false, want true")
	}
	if !identity.HasScope("read:org") {
		t.Error("HasScope(read:org) = false, want true")
	}
	if !identity.HasRole("github:user") {
		t.Error("HasRole(github:user) = false, want true")
	}
	if !identity.HasRole("org:acme-corp") {
		t.Error("HasRole(org:acme-corp) = false, want true")
	}
	if identity.TenantID() != "acme-corp" {
		t.Errorf("TenantID() = %q, want %q", identity.TenantID(), "acme-corp")
	}
}

func TestValidator_Validate_invalid_token(t *testing.T) {
	user := &GitHubUser{ID: 1, Login: "testuser"}
	server := mockGitHubServer(t, user, nil, nil, "")

	cfg := Config{}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	_, err := v.Validate(context.Background(), "invalid-token")
	if err == nil {
		t.Error("Validate() should fail with invalid token")
	}
}

func TestValidator_Validate_org_restriction_allowed(t *testing.T) {
	user := &GitHubUser{ID: 1, Login: "testuser"}
	orgs := []GitHubOrg{{ID: 1, Login: "acme-corp"}}

	server := mockGitHubServer(t, user, orgs, nil, "")

	cfg := Config{
		AllowedOrganizations: []string{"acme-corp"},
	}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	identity, err := v.Validate(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if identity.TenantID() != "acme-corp" {
		t.Errorf("TenantID() = %q, want %q", identity.TenantID(), "acme-corp")
	}
}

func TestValidator_Validate_org_restriction_denied(t *testing.T) {
	user := &GitHubUser{ID: 1, Login: "testuser"}
	orgs := []GitHubOrg{{ID: 1, Login: "other-org"}}

	server := mockGitHubServer(t, user, orgs, nil, "")

	cfg := Config{
		AllowedOrganizations: []string{"acme-corp"},
	}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	_, err := v.Validate(context.Background(), "valid-token")
	if err == nil {
		t.Error("Validate() should fail when user not in allowed org")
	}
}

func TestValidator_Validate_team_restriction_allowed(t *testing.T) {
	user := &GitHubUser{ID: 1, Login: "testuser"}
	orgs := []GitHubOrg{{ID: 1, Login: "acme-corp"}}
	teams := []GitHubTeam{
		{
			ID:   1,
			Slug: "developers",
			Organization: GitHubTeamOrg{
				ID:    1,
				Login: "acme-corp",
			},
		},
	}

	server := mockGitHubServer(t, user, orgs, teams, "")

	cfg := Config{
		AllowedTeams: []string{"acme-corp/developers"},
	}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	identity, err := v.Validate(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !identity.HasRole("team:acme-corp/developers") {
		t.Error("HasRole(team:acme-corp/developers) = false, want true")
	}
}

func TestValidator_Validate_team_restriction_denied(t *testing.T) {
	user := &GitHubUser{ID: 1, Login: "testuser"}
	orgs := []GitHubOrg{{ID: 1, Login: "acme-corp"}}
	teams := []GitHubTeam{
		{
			ID:   1,
			Slug: "other-team",
			Organization: GitHubTeamOrg{
				ID:    1,
				Login: "acme-corp",
			},
		},
	}

	server := mockGitHubServer(t, user, orgs, teams, "")

	cfg := Config{
		AllowedTeams: []string{"acme-corp/developers"},
	}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	_, err := v.Validate(context.Background(), "valid-token")
	if err == nil {
		t.Error("Validate() should fail when user not in allowed team")
	}
}

func TestValidator_Validate_teams_populated_without_restrictions(t *testing.T) {
	user := &GitHubUser{ID: 1, Login: "testuser"}
	orgs := []GitHubOrg{{ID: 1, Login: "acme-corp"}}
	teams := []GitHubTeam{
		{
			ID:   1,
			Slug: "developers",
			Organization: GitHubTeamOrg{
				ID:    1,
				Login: "acme-corp",
			},
		},
		{
			ID:   2,
			Slug: "backend",
			Organization: GitHubTeamOrg{
				ID:    1,
				Login: "acme-corp",
			},
		},
	}

	server := mockGitHubServer(t, user, orgs, teams, "")

	// No AllowedTeams restriction - teams should still be fetched for roles
	cfg := Config{}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	identity, err := v.Validate(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Verify teams are populated
	gotTeams := identity.Teams()
	if len(gotTeams) != 2 {
		t.Errorf("Teams() len = %d, want 2", len(gotTeams))
	}

	// Verify team roles are emitted
	if !identity.HasRole("team:acme-corp/developers") {
		t.Error("HasRole(team:acme-corp/developers) = false, want true")
	}
	if !identity.HasRole("team:acme-corp/backend") {
		t.Error("HasRole(team:acme-corp/backend) = false, want true")
	}
}

func TestValidator_Validate_require_verified_email(t *testing.T) {
	user := &GitHubUser{ID: 1, Login: "testuser", Email: ""}
	orgs := []GitHubOrg{}

	server := mockGitHubServer(t, user, orgs, nil, "")

	cfg := Config{
		RequireVerifiedEmail: true,
	}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	_, err := v.Validate(context.Background(), "valid-token")
	if err == nil {
		t.Error("Validate() should fail when email is not verified")
	}
}

func TestValidator_caching(t *testing.T) {
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/user":
			fetchCount++
			w.Header().Set("X-OAuth-Scopes", "read:user")
			json.NewEncoder(w).Encode(&GitHubUser{ID: 1, Login: "testuser"})
		case "/user/orgs":
			json.NewEncoder(w).Encode([]GitHubOrg{})
		case "/user/teams":
			json.NewEncoder(w).Encode([]GitHubTeam{})
		}
	}))
	t.Cleanup(server.Close)

	cfg := Config{CacheTTL: time.Hour}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	// First request
	_, _ = v.Validate(context.Background(), "valid-token")
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d after first request, want 1", fetchCount)
	}

	// Second request (should use cache)
	_, _ = v.Validate(context.Background(), "valid-token")
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d after cached request, want 1", fetchCount)
	}
}

func TestValidator_cache_expiry(t *testing.T) {
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/user":
			fetchCount++
			json.NewEncoder(w).Encode(&GitHubUser{ID: 1, Login: "testuser"})
		case "/user/orgs":
			json.NewEncoder(w).Encode([]GitHubOrg{})
		case "/user/teams":
			json.NewEncoder(w).Encode([]GitHubTeam{})
		}
	}))
	t.Cleanup(server.Close)

	clock := clockz.NewFakeClockAt(time.Now())
	cfg := Config{
		CacheTTL: 5 * time.Minute,
		Clock:    clock,
	}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	// First request
	_, _ = v.Validate(context.Background(), "valid-token")
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d after first request, want 1", fetchCount)
	}

	// Advance clock past TTL
	clock.Advance(6 * time.Minute)

	// Should fetch again
	_, _ = v.Validate(context.Background(), "valid-token")
	if fetchCount != 2 {
		t.Errorf("fetchCount = %d after cache expiry, want 2", fetchCount)
	}
}

func TestValidator_ClearCache(t *testing.T) {
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/user":
			fetchCount++
			json.NewEncoder(w).Encode(&GitHubUser{ID: 1, Login: "testuser"})
		case "/user/orgs":
			json.NewEncoder(w).Encode([]GitHubOrg{})
		case "/user/teams":
			json.NewEncoder(w).Encode([]GitHubTeam{})
		}
	}))
	t.Cleanup(server.Close)

	cfg := Config{CacheTTL: time.Hour}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	// First request
	_, _ = v.Validate(context.Background(), "valid-token")
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d after first request, want 1", fetchCount)
	}

	// Clear cache
	v.ClearCache()

	// Should fetch again
	_, _ = v.Validate(context.Background(), "valid-token")
	if fetchCount != 2 {
		t.Errorf("fetchCount = %d after cache clear, want 2", fetchCount)
	}
}

func TestValidator_Extractor(t *testing.T) {
	user := &GitHubUser{ID: 12345, Login: "testuser"}
	orgs := []GitHubOrg{{ID: 1, Login: "acme-corp"}}

	server := mockGitHubServer(t, user, orgs, nil, "read:user")

	cfg := Config{}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	extractor := v.Extractor()

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		identity, err := extractor(context.Background(), req)
		if err != nil {
			t.Fatalf("Extractor() error = %v", err)
		}
		if identity.ID() != "12345" {
			t.Errorf("ID() = %q, want %q", identity.ID(), "12345")
		}
	})

	t.Run("missing header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		_, err := extractor(context.Background(), req)
		if err == nil {
			t.Error("Extractor() should fail with missing header")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")

		_, err := extractor(context.Background(), req)
		if err == nil {
			t.Error("Extractor() should fail with invalid token")
		}
	})
}

func TestNewExtractor(t *testing.T) {
	user := &GitHubUser{ID: 12345, Login: "testuser"}
	orgs := []GitHubOrg{}

	server := mockGitHubServer(t, user, orgs, nil, "")

	cfg := Config{}.WithBaseURL(server.URL)
	extractor, err := NewExtractor(cfg)
	if err != nil {
		t.Fatalf("NewExtractor() error = %v", err)
	}
	if extractor == nil {
		t.Fatal("NewExtractor() returned nil")
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	identity, err := extractor(context.Background(), req)
	if err != nil {
		t.Fatalf("Extractor() error = %v", err)
	}
	if identity.ID() != "12345" {
		t.Errorf("ID() = %q, want %q", identity.ID(), "12345")
	}
}

func Test_extractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{
			name:   "valid bearer token",
			header: "Bearer mytoken123",
			want:   "mytoken123",
		},
		{
			name:   "case insensitive bearer",
			header: "bearer mytoken123",
			want:   "mytoken123",
		},
		{
			name:   "BEARER uppercase",
			header: "BEARER mytoken123",
			want:   "mytoken123",
		},
		{
			name:    "missing header",
			header:  "",
			wantErr: true,
		},
		{
			name:    "basic auth",
			header:  "Basic dXNlcjpwYXNz",
			wantErr: true,
		},
		{
			name:    "empty bearer",
			header:  "Bearer ",
			wantErr: true,
		},
		{
			name:    "no space",
			header:  "Bearertoken",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			got, err := extractBearerToken(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractBearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_parseScopes(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   []string
	}{
		{
			name:   "single scope",
			header: "read:user",
			want:   []string{"read:user"},
		},
		{
			name:   "multiple scopes",
			header: "read:user, read:org, repo",
			want:   []string{"read:user", "read:org", "repo"},
		},
		{
			name:   "with extra whitespace",
			header: "  read:user  ,  read:org  ",
			want:   []string{"read:user", "read:org"},
		},
		{
			name:   "empty header",
			header: "",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseScopes(tt.header)
			if len(got) != len(tt.want) {
				t.Errorf("parseScopes() len = %d, want %d", len(got), len(tt.want))
				return
			}
			for i, scope := range got {
				if scope != tt.want[i] {
					t.Errorf("parseScopes()[%d] = %q, want %q", i, scope, tt.want[i])
				}
			}
		})
	}
}

func TestValidator_Validate_api_error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	cfg := Config{}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	_, err := v.Validate(context.Background(), "valid-token")
	if err == nil {
		t.Error("Validate() should fail on API error")
	}
}

func TestValidator_Validate_orgs_api_error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/user":
			json.NewEncoder(w).Encode(&GitHubUser{ID: 1, Login: "testuser"})
		case "/user/orgs":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)

	cfg := Config{}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	_, err := v.Validate(context.Background(), "valid-token")
	if err == nil {
		t.Error("Validate() should fail on orgs API error")
	}
}

func Test_getNextPageURL(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "empty header",
			header: "",
			want:   "",
		},
		{
			name:   "next link only",
			header: `<https://api.github.com/user/orgs?page=2>; rel="next"`,
			want:   "https://api.github.com/user/orgs?page=2",
		},
		{
			name:   "next and last links",
			header: `<https://api.github.com/user/orgs?page=2>; rel="next", <https://api.github.com/user/orgs?page=5>; rel="last"`,
			want:   "https://api.github.com/user/orgs?page=2",
		},
		{
			name:   "last link only (no next)",
			header: `<https://api.github.com/user/orgs?page=5>; rel="last"`,
			want:   "",
		},
		{
			name:   "prev and next links",
			header: `<https://api.github.com/user/orgs?page=1>; rel="prev", <https://api.github.com/user/orgs?page=3>; rel="next"`,
			want:   "https://api.github.com/user/orgs?page=3",
		},
		{
			name:   "malformed link",
			header: `malformed`,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNextPageURL(tt.header)
			if got != tt.want {
				t.Errorf("getNextPageURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidator_cache_expiry_deletes_entry(t *testing.T) {
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/user":
			fetchCount++
			json.NewEncoder(w).Encode(&GitHubUser{ID: 1, Login: "testuser"})
		case "/user/orgs":
			json.NewEncoder(w).Encode([]GitHubOrg{})
		case "/user/teams":
			json.NewEncoder(w).Encode([]GitHubTeam{})
		}
	}))
	t.Cleanup(server.Close)

	clock := clockz.NewFakeClockAt(time.Now())
	cfg := Config{
		CacheTTL: 5 * time.Minute,
		Clock:    clock,
	}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	// First request - caches the entry
	_, err := v.Validate(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("fetchCount = %d, want 1", fetchCount)
	}

	// Verify entry is in cache
	v.cacheMu.RLock()
	_, exists := v.cache["valid-token"]
	v.cacheMu.RUnlock()
	if !exists {
		t.Fatal("cache entry should exist")
	}

	// Advance clock past TTL
	clock.Advance(6 * time.Minute)

	// Access cache - should delete expired entry
	_ = v.getFromCache("valid-token")

	// Verify entry was deleted
	v.cacheMu.RLock()
	_, exists = v.cache["valid-token"]
	v.cacheMu.RUnlock()
	if exists {
		t.Error("expired cache entry should have been deleted")
	}
}

func TestValidator_pagination_orgs(t *testing.T) {
	page := 0
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/user":
			json.NewEncoder(w).Encode(&GitHubUser{ID: 1, Login: "testuser"})
		case "/user/orgs":
			page++
			if page == 1 {
				w.Header().Set("Link", `<`+serverURL+`/user/orgs?page=2>; rel="next"`)
				json.NewEncoder(w).Encode([]GitHubOrg{
					{ID: 1, Login: "org1"},
					{ID: 2, Login: "org2"},
				})
			} else {
				json.NewEncoder(w).Encode([]GitHubOrg{
					{ID: 3, Login: "org3"},
				})
			}
		case "/user/teams":
			json.NewEncoder(w).Encode([]GitHubTeam{})
		}
	}))
	serverURL = server.URL
	t.Cleanup(server.Close)

	cfg := Config{}.WithBaseURL(server.URL)
	v, _ := NewValidator(cfg)

	identity, err := v.Validate(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	orgs := identity.Organizations()
	if len(orgs) != 3 {
		t.Errorf("Organizations() len = %d, want 3", len(orgs))
	}
	if page != 2 {
		t.Errorf("page = %d, want 2 (pagination should have fetched 2 pages)", page)
	}
}

// errorCloser is an io.ReadCloser that returns an error on Close.
type errorCloser struct {
	io.Reader
}

func (errorCloser) Close() error {
	return errors.New("simulated close error")
}

func Test_closeResponseBody_emitsEvent(t *testing.T) {
	var received bool
	var endpoint, errorMsg string

	listener := capitan.Hook(rocco.ResponseBodyCloseError, func(_ context.Context, e *capitan.Event) {
		received = true
		endpoint, _ = rocco.EndpointKey.From(e)
		errorMsg, _ = rocco.ErrorKey.From(e)
	})
	defer listener.Close()

	resp := &http.Response{
		Body: errorCloser{},
	}

	closeResponseBody(context.Background(), resp, "/user")

	if !received {
		t.Error("ResponseBodyCloseError not emitted")
	}
	if endpoint != "/user" {
		t.Errorf("endpoint = %q, want %q", endpoint, "/user")
	}
	if errorMsg != "simulated close error" {
		t.Errorf("error = %q, want %q", errorMsg, "simulated close error")
	}
}
