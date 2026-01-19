package auth0

import (
	"strings"
	"time"
)

// extractIdentity builds an Identity from JWT claims.
func extractIdentity(claims map[string]any, cfg *Config) *Identity {
	identity := &Identity{
		claims: claims,
	}

	// Extract subject (required)
	identity.subject = extractString(claims, "sub")

	// Extract email if present
	identity.email = extractString(claims, "email")

	// Extract expiration
	identity.expiresAt = extractTime(claims, "exp")

	// Extract roles from configured claim
	identity.roles = extractStringSlice(claims, cfg.RolesClaim)

	// Extract scopes - try array first, then fall back to space-separated string
	if scopes := extractStringSliceOnly(claims, cfg.ScopesClaim); len(scopes) > 0 {
		identity.scopes = scopes
	} else if scopeStr := extractString(claims, cfg.ScopesClaim); scopeStr != "" {
		identity.scopes = strings.Fields(scopeStr)
	}

	// Extract tenant from configured claim if set
	if cfg.TenantClaim != "" {
		identity.tenant = extractString(claims, cfg.TenantClaim)
	}

	return identity
}

// extractString extracts a string value from claims.
// Returns empty string if not found or not a string.
func extractString(claims map[string]any, key string) string {
	v, ok := claims[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// extractStringSlice extracts a string slice from claims.
// Handles both []string and []any representations.
// Also handles single string values by wrapping them.
func extractStringSlice(claims map[string]any, key string) []string {
	v, ok := claims[key]
	if !ok {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case string:
		// Handle single string value (some Auth0 configs return this)
		if val != "" {
			return []string{val}
		}
		return nil
	default:
		return nil
	}
}

// extractStringSliceOnly extracts a string slice from claims.
// Only handles actual arrays ([]string and []any), not strings.
// Use this when strings should be processed differently (e.g., space-split).
func extractStringSliceOnly(claims map[string]any, key string) []string {
	v, ok := claims[key]
	if !ok {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// extractTime extracts a time.Time from claims (Unix timestamp).
func extractTime(claims map[string]any, key string) time.Time {
	v, ok := claims[key]
	if !ok {
		return time.Time{}
	}

	switch val := v.(type) {
	case float64:
		return time.Unix(int64(val), 0)
	case int64:
		return time.Unix(val, 0)
	case int:
		return time.Unix(int64(val), 0)
	default:
		return time.Time{}
	}
}
