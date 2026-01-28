package session

import (
	"fmt"
	"net/http"

	"github.com/zoobzio/rocco"
	"github.com/zoobzio/rocco/oauth"
)

// NewLoginHandler creates a GET handler that initiates the OAuth login flow.
// It generates a CSRF state token, stores it, and redirects the user to the
// OAuth provider's authorization endpoint.
func NewLoginHandler(path string, cfg Config) (*rocco.Handler[rocco.NoBody, rocco.Redirect], error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("session: invalid config: %w", err)
	}
	cfg.Cookie.defaults()
	genState := GenerateState(cfg.Store)

	return rocco.GET[rocco.NoBody, rocco.Redirect](path, func(req *rocco.Request[rocco.NoBody]) (rocco.Redirect, error) {
		// Generate and store CSRF state.
		state, err := genState(req.Context)
		if err != nil {
			return rocco.Redirect{}, rocco.ErrInternalServer.WithMessage("failed to generate state").WithCause(err)
		}

		// Build authorization URL.
		authURL, err := oauth.AuthURL(cfg.OAuth, state)
		if err != nil {
			return rocco.Redirect{}, rocco.ErrInternalServer.WithMessage("failed to build authorization URL").WithCause(err)
		}

		return rocco.Redirect{URL: authURL}, nil
	}).
		WithName(cfg.OAuth.Name + "-login").
		WithSummary("Initiate " + cfg.OAuth.Name + " OAuth login").
		WithDescription("Redirects to " + cfg.OAuth.Name + " for OAuth authorization.").
		WithErrors(rocco.ErrInternalServer), nil
}

// NewCallbackHandler creates a GET handler that processes the OAuth callback.
// It verifies the CSRF state, exchanges the authorization code for tokens,
// resolves session data, creates a session, and redirects with a session cookie.
func NewCallbackHandler(path string, cfg Config) (*rocco.Handler[rocco.NoBody, rocco.Redirect], error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("session: invalid config: %w", err)
	}
	cfg.Cookie.defaults()

	return rocco.GET[rocco.NoBody, rocco.Redirect](path, func(req *rocco.Request[rocco.NoBody]) (rocco.Redirect, error) {
		// Extract code and state from query params.
		code := req.URL.Query().Get("code")
		state := req.URL.Query().Get("state")

		if code == "" {
			if errCode := req.URL.Query().Get("error"); errCode != "" {
				errDesc := req.URL.Query().Get("error_description")
				if errDesc == "" {
					errDesc = errCode
				}
				return rocco.Redirect{}, rocco.ErrBadRequest.WithMessage("provider error: " + errDesc)
			}
			return rocco.Redirect{}, rocco.ErrBadRequest.WithMessage("authorization code not provided")
		}

		// Verify CSRF state.
		valid, err := cfg.Store.VerifyState(req.Context, state)
		if err != nil {
			return rocco.Redirect{}, rocco.ErrBadRequest.WithMessage("invalid or expired state parameter").WithCause(err)
		}
		if !valid {
			return rocco.Redirect{}, rocco.ErrBadRequest.WithMessage("invalid or expired state parameter")
		}

		// Exchange code for tokens.
		tokens, err := oauth.Exchange(req.Context, cfg.OAuth, code)
		if err != nil {
			return rocco.Redirect{}, rocco.ErrBadGateway.WithMessage("token exchange failed").WithCause(err)
		}

		// Resolve tokens to session data.
		data, err := cfg.Resolve(req.Context, tokens)
		if err != nil {
			return rocco.Redirect{}, rocco.ErrInternalServer.WithMessage("failed to resolve session data").WithCause(err)
		}

		// Create session.
		sessionID, err := generateID()
		if err != nil {
			return rocco.Redirect{}, rocco.ErrInternalServer.WithMessage("failed to generate session ID").WithCause(err)
		}

		if err := cfg.Store.Create(req.Context, sessionID, *data); err != nil {
			return rocco.Redirect{}, rocco.ErrInternalServer.WithMessage("failed to create session").WithCause(err)
		}

		// Build redirect with session cookie.
		cookie := newSetCookie(cfg.Cookie, sessionID)
		headers := http.Header{}
		headers.Add("Set-Cookie", cookie.String())

		return rocco.Redirect{
			URL:     cfg.RedirectURL,
			Headers: headers,
		}, nil
	}).
		WithName(cfg.OAuth.Name + "-callback").
		WithSummary("Handle " + cfg.OAuth.Name + " OAuth callback").
		WithDescription("Processes the OAuth callback, creates a session, and redirects.").
		WithQueryParams("code", "state").
		WithErrors(rocco.ErrBadRequest, rocco.ErrBadGateway, rocco.ErrInternalServer), nil
}

// NewLogoutHandler creates a GET handler that destroys the session and redirects.
// It reads the session cookie, deletes the session from the store, clears the cookie,
// and redirects to the given URL.
func NewLogoutHandler(path string, cfg Config, redirectURL string) (*rocco.Handler[rocco.NoBody, rocco.Redirect], error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("session: Store is required")
	}
	if len(cfg.Cookie.SignKey) == 0 {
		return nil, fmt.Errorf("session: Cookie.SignKey is required")
	}
	cfg.Cookie.defaults()

	return rocco.GET[rocco.NoBody, rocco.Redirect](path, func(req *rocco.Request[rocco.NoBody]) (rocco.Redirect, error) {
		// Read session cookie.
		c, err := req.Cookie(cfg.Cookie.Name)
		if err == nil {
			// Verify and extract session ID.
			if sessionID, ok := verifyValue(c.Value, cfg.Cookie.SignKey); ok {
				// Best-effort delete — don't fail logout if store errors.
				_ = cfg.Store.Delete(req.Context, sessionID)
			}
		}

		// Clear cookie and redirect.
		clearCookie := newClearCookie(cfg.Cookie)
		headers := http.Header{}
		headers.Add("Set-Cookie", clearCookie.String())

		return rocco.Redirect{
			URL:     redirectURL,
			Headers: headers,
		}, nil
	}).
		WithName("logout").
		WithSummary("Logout and destroy session").
		WithDescription("Destroys the session and redirects."), nil
}
