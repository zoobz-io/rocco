package session

import (
	"context"
	"fmt"
	"net/http"

	"github.com/zoobzio/rocco"
)

// Extractor returns an identity extraction function for use with
// [rocco.Engine.WithAuthenticator]. It reads the session cookie, verifies
// the signature, and loads the session from the store.
func Extractor(store Store, cookie CookieConfig) func(context.Context, *http.Request) (rocco.Identity, error) {
	cookie.defaults()

	return func(ctx context.Context, r *http.Request) (rocco.Identity, error) {
		// Read session cookie.
		c, err := r.Cookie(cookie.Name)
		if err != nil {
			return nil, fmt.Errorf("session: cookie not found")
		}

		// Verify signature and extract session ID.
		sessionID, ok := verifyValue(c.Value, cookie.SignKey)
		if !ok {
			return nil, fmt.Errorf("session: invalid cookie signature")
		}

		// Load session from store.
		data, err := store.Get(ctx, sessionID)
		if err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}

		return &Identity{data: *data}, nil
	}
}
