package session

import "github.com/zoobzio/rocco"

// Identity implements [rocco.Identity] backed by session [Data].
type Identity struct {
	data Data
}

var _ rocco.Identity = (*Identity)(nil)

// ID returns the user ID from the session.
func (i *Identity) ID() string { return i.data.UserID }

// TenantID returns the tenant ID from the session.
func (i *Identity) TenantID() string { return i.data.TenantID }

// Email returns the email from the session.
func (i *Identity) Email() string { return i.data.Email }

// Scopes returns the scopes from the session.
func (i *Identity) Scopes() []string { return i.data.Scopes }

// Roles returns the roles from the session.
func (i *Identity) Roles() []string { return i.data.Roles }

// HasScope checks if the session has the given scope.
func (i *Identity) HasScope(scope string) bool {
	for _, s := range i.data.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole checks if the session has the given role.
func (i *Identity) HasRole(role string) bool {
	for _, r := range i.data.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Stats returns nil. Session-based identities do not track usage stats.
func (*Identity) Stats() map[string]int { return nil }
