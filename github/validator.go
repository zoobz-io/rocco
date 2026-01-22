package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zoobzio/capitan"
	"github.com/zoobzio/clockz"
	"github.com/zoobzio/rocco"
)

// Validator handles GitHub token validation and user data caching.
type Validator struct {
	cfg        Config
	clock      clockz.Clock
	httpClient *http.Client

	cache   map[string]*cacheEntry
	cacheMu sync.RWMutex
}

type cacheEntry struct {
	identity  *Identity
	expiresAt time.Time
}

// NewValidator creates a new Validator with the given configuration.
func NewValidator(cfg Config) (*Validator, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &Validator{
		cfg:        cfg,
		clock:      cfg.Clock,
		httpClient: cfg.HTTPClient,
		cache:      make(map[string]*cacheEntry),
	}, nil
}

// Validate validates a GitHub access token and returns the identity.
func (v *Validator) Validate(ctx context.Context, token string) (*Identity, error) {
	// Check cache first
	if identity := v.getFromCache(token); identity != nil {
		return identity, nil
	}

	// Fetch user data from GitHub API
	identity, err := v.fetchIdentity(ctx, token)
	if err != nil {
		return nil, err
	}

	// Validate organization membership if configured
	if err := v.validateOrgMembership(identity); err != nil {
		return nil, err
	}

	// Validate team membership if configured
	if err := v.validateTeamMembership(ctx, token, identity); err != nil {
		return nil, err
	}

	// Build roles from org/team membership
	identity.roles = v.buildRoles(identity)

	// Set tenant to first allowed org (if any)
	identity.tenant = v.determineTenant(identity)

	// Cache the identity
	v.addToCache(token, identity)

	return identity, nil
}

// getFromCache returns cached identity if valid, nil otherwise.
// Expired entries are removed to prevent unbounded cache growth.
func (v *Validator) getFromCache(token string) *Identity {
	v.cacheMu.RLock()
	entry, ok := v.cache[token]
	if !ok {
		v.cacheMu.RUnlock()
		return nil
	}

	// Fast path: entry is still valid
	if !v.clock.Now().After(entry.expiresAt) {
		identity := entry.identity
		v.cacheMu.RUnlock()
		return identity
	}

	// Entry is expired - release read lock and acquire write lock to delete
	v.cacheMu.RUnlock()

	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()

	// Re-check after acquiring write lock (another goroutine may have deleted it)
	entry, ok = v.cache[token]
	if ok && v.clock.Now().After(entry.expiresAt) {
		delete(v.cache, token)
	}

	return nil
}

// addToCache stores an identity in the cache.
func (v *Validator) addToCache(token string, identity *Identity) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()

	v.cache[token] = &cacheEntry{
		identity:  identity,
		expiresAt: v.clock.Now().Add(v.cfg.CacheTTL),
	}
}

// fetchIdentity fetches user data from GitHub API.
func (v *Validator) fetchIdentity(ctx context.Context, token string) (*Identity, error) {
	// Fetch user profile
	user, scopes, err := v.fetchUser(ctx, token)
	if err != nil {
		return nil, err
	}

	// Validate email if required
	if v.cfg.RequireVerifiedEmail && !user.HasVerifiedEmail() {
		return nil, errors.New("github: user does not have a verified email")
	}

	// Fetch organizations
	orgs, err := v.fetchOrganizations(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("github: failed to fetch organizations: %w", err)
	}

	// Build identity
	identity := &Identity{
		userID:    fmt.Sprintf("%d", user.ID),
		login:     user.Login,
		email:     user.Email,
		scopes:    scopes,
		orgs:      orgs,
		avatarURL: user.AvatarURL,
		name:      user.Name,
		cachedAt:  v.clock.Now(),
		raw:       user,
	}

	return identity, nil
}

// fetchUser calls GET /user and extracts OAuth scopes from response headers.
func (v *Validator) fetchUser(ctx context.Context, token string) (*GitHubUser, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.BaseURL+"/user", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("github: failed to create user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("github: failed to fetch user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, nil, errors.New("github: invalid or expired token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("github: user request failed with status %d", resp.StatusCode)
	}

	// Extract OAuth scopes from response header
	scopeHeader := resp.Header.Get("X-OAuth-Scopes")
	scopes := parseScopes(scopeHeader)

	var user GitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, nil, fmt.Errorf("github: failed to decode user response: %w", err)
	}

	return &user, scopes, nil
}

// fetchOrganizations calls GET /user/orgs with pagination.
func (v *Validator) fetchOrganizations(ctx context.Context, token string) ([]string, error) {
	var result []string
	url := v.cfg.BaseURL + "/user/orgs?per_page=100"

	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("github: failed to create orgs request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := v.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github: failed to fetch orgs: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("github: orgs request failed with status %d", resp.StatusCode)
		}

		var orgs []GitHubOrg
		if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("github: failed to decode orgs response: %w", err)
		}
		resp.Body.Close()

		for _, org := range orgs {
			result = append(result, org.Login)
		}

		url = getNextPageURL(resp.Header.Get("Link"))
	}

	return result, nil
}

// fetchTeams fetches team memberships for the user with pagination.
func (v *Validator) fetchTeams(ctx context.Context, token string) ([]string, error) {
	var result []string
	url := v.cfg.BaseURL + "/user/teams?per_page=100"

	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("github: failed to create teams request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := v.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github: failed to fetch teams: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			// Teams endpoint requires read:org scope - may fail gracefully
			return nil, nil
		}

		var teams []GitHubTeam
		if err := json.NewDecoder(resp.Body).Decode(&teams); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("github: failed to decode teams response: %w", err)
		}
		resp.Body.Close()

		for _, team := range teams {
			result = append(result, fmt.Sprintf("%s/%s", team.Organization.Login, team.Slug))
		}

		url = getNextPageURL(resp.Header.Get("Link"))
	}

	return result, nil
}

// validateOrgMembership checks if user belongs to allowed organizations.
func (v *Validator) validateOrgMembership(identity *Identity) error {
	if len(v.cfg.AllowedOrganizations) == 0 {
		return nil
	}

	for _, allowedOrg := range v.cfg.AllowedOrganizations {
		for _, userOrg := range identity.orgs {
			if strings.EqualFold(allowedOrg, userOrg) {
				return nil
			}
		}
	}

	return errors.New("github: user is not a member of any allowed organization")
}

// validateTeamMembership checks if user belongs to allowed teams.
func (v *Validator) validateTeamMembership(ctx context.Context, token string, identity *Identity) error {
	if len(v.cfg.AllowedTeams) == 0 {
		return nil
	}

	// Fetch teams (lazy - only when needed)
	teams, err := v.fetchTeams(ctx, token)
	if err != nil {
		return fmt.Errorf("github: failed to validate team membership: %w", err)
	}
	identity.teams = teams

	for _, allowedTeam := range v.cfg.AllowedTeams {
		for _, userTeam := range teams {
			if strings.EqualFold(allowedTeam, userTeam) {
				return nil
			}
		}
	}

	return errors.New("github: user is not a member of any allowed team")
}

// buildRoles creates role strings from org/team membership.
func (v *Validator) buildRoles(identity *Identity) []string {
	roles := []string{"github:user"}

	for _, org := range identity.orgs {
		roles = append(roles, "org:"+org)
	}

	for _, team := range identity.teams {
		roles = append(roles, "team:"+team)
	}

	return roles
}

// determineTenant returns the first allowed org the user belongs to.
func (v *Validator) determineTenant(identity *Identity) string {
	if len(v.cfg.AllowedOrganizations) == 0 {
		if len(identity.orgs) > 0 {
			return identity.orgs[0]
		}
		return ""
	}

	for _, allowedOrg := range v.cfg.AllowedOrganizations {
		for _, userOrg := range identity.orgs {
			if strings.EqualFold(allowedOrg, userOrg) {
				return userOrg
			}
		}
	}
	return ""
}

// parseScopes parses the X-OAuth-Scopes header into a slice.
func parseScopes(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		scope := strings.TrimSpace(part)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

// getNextPageURL extracts the "next" page URL from a GitHub Link header.
// Link header format: <url>; rel="next", <url>; rel="last"
func getNextPageURL(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	for _, link := range strings.Split(linkHeader, ",") {
		link = strings.TrimSpace(link)
		parts := strings.Split(link, ";")
		if len(parts) != 2 {
			continue
		}

		url := strings.TrimSpace(parts[0])
		rel := strings.TrimSpace(parts[1])

		if rel == `rel="next"` {
			// Remove angle brackets from URL
			url = strings.TrimPrefix(url, "<")
			url = strings.TrimSuffix(url, ">")
			return url
		}
	}

	return ""
}

// Extractor returns an identity extractor function for use with rocco.NewEngine.
func (v *Validator) Extractor() func(context.Context, *http.Request) (rocco.Identity, error) {
	return func(ctx context.Context, r *http.Request) (rocco.Identity, error) {
		token, err := extractBearerToken(r)
		if err != nil {
			capitan.Warn(ctx, rocco.AuthenticationFailed,
				rocco.MethodKey.Field(r.Method),
				rocco.PathKey.Field(r.URL.Path),
				rocco.ErrorKey.Field(err.Error()),
			)
			return nil, err
		}

		identity, err := v.Validate(ctx, token)
		if err != nil {
			capitan.Warn(ctx, rocco.AuthenticationFailed,
				rocco.MethodKey.Field(r.Method),
				rocco.PathKey.Field(r.URL.Path),
				rocco.ErrorKey.Field(err.Error()),
			)
			return nil, err
		}

		return identity, nil
	}
}

// extractBearerToken extracts the token from the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", errors.New("github: missing Authorization header")
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("github: invalid Authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("github: empty bearer token")
	}

	return token, nil
}

// ClearCache clears the identity cache. Useful for testing.
func (v *Validator) ClearCache() {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	v.cache = make(map[string]*cacheEntry)
}
