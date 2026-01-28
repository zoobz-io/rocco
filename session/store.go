package session

import "context"

// Store manages session and OAuth state persistence.
// Implement this interface for your storage backend (Redis, database, etc.).
// Use [NewMemoryStore] for development and testing.
type Store interface {
	// CreateState persists a CSRF state token for later verification.
	CreateState(ctx context.Context, state string) error

	// VerifyState checks that the state token exists and is valid.
	// Implementations should delete the state after verification (single-use).
	VerifyState(ctx context.Context, state string) (bool, error)

	// Create persists a new session with the given ID and data.
	Create(ctx context.Context, id string, data Data) error

	// Get retrieves session data by ID. Returns an error if the session does not exist.
	Get(ctx context.Context, id string) (*Data, error)

	// Refresh extends the session's expiry. Returns an error if the session does not exist.
	Refresh(ctx context.Context, id string) error

	// Delete removes a session by ID.
	Delete(ctx context.Context, id string) error
}

// Data holds the session payload.
type Data struct {
	UserID   string
	TenantID string
	Email    string
	Scopes   []string
	Roles    []string
	Meta     map[string]any
}
