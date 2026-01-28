package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zoobzio/rocco"
)

// BadGatewayDetails provides context for upstream provider errors.
type BadGatewayDetails struct {
	Provider string `json:"provider,omitempty" description:"The OAuth provider that failed"`
	Reason   string `json:"reason,omitempty" description:"Error details from the provider"`
}

// ErrBadGateway indicates the upstream OAuth provider returned an error (502).
var ErrBadGateway = rocco.NewError[BadGatewayDetails]("BAD_GATEWAY", http.StatusBadGateway, "upstream provider error")

// NewLoginHandler creates a handler that redirects users to the OAuth provider's
// authorization endpoint. The handler generates a state parameter using the
// configured GenerateState callback for CSRF protection.
//
// Returns an error if the config is invalid (missing required fields or callbacks).
//
// Example:
//
//	login, err := oauth.NewLoginHandler("/auth/github", cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	engine.WithHandlers(login)
func NewLoginHandler(path string, cfg Config) (*rocco.Handler[rocco.NoBody, rocco.Redirect], error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("oauth: invalid config: %w", err)
	}

	return rocco.GET[rocco.NoBody, rocco.Redirect](path, func(req *rocco.Request[rocco.NoBody]) (rocco.Redirect, error) {
		// Generate state for CSRF protection
		state, err := cfg.GenerateState(req.Context)
		if err != nil {
			return rocco.Redirect{}, rocco.ErrInternalServer.WithMessage("failed to generate state parameter").WithCause(err)
		}

		// Build authorization URL
		authURL, err := buildAuthURL(cfg, state)
		if err != nil {
			return rocco.Redirect{}, rocco.ErrInternalServer.WithMessage("failed to build authorization URL").WithCause(err)
		}

		return rocco.Redirect{URL: authURL}, nil
	}).
		WithName(cfg.Name + "-login").
		WithSummary("Initiate " + cfg.Name + " OAuth login").
		WithDescription("Redirects to " + cfg.Name + " for OAuth authorization.").
		WithErrors(rocco.ErrInternalServer), nil
}

// NewCallbackHandler creates a handler that processes the OAuth callback.
// It verifies the state parameter, exchanges the authorization code for tokens,
// calls OnSuccess with the tokens, and returns the result of the respond function.
//
// The respond function determines what is returned to the client. Common patterns:
//
//   - Redirect to dashboard: func(ctx context.Context, t *TokenResponse) (rocco.Redirect, error) { return rocco.Redirect{URL: "/dashboard"}, nil }
//   - Return JSON: func(ctx context.Context, t *TokenResponse) (MyResponse, error) { return MyResponse{Token: t.AccessToken}, nil }
//
// Returns an error if the config is invalid (missing required fields or callbacks).
//
// Example:
//
//	callback, err := oauth.NewCallbackHandler("/auth/github/callback", cfg,
//	    func(ctx context.Context, tokens *oauth.TokenResponse) (rocco.Redirect, error) {
//	        return rocco.Redirect{URL: "/dashboard"}, nil
//	    })
//	if err != nil {
//	    log.Fatal(err)
//	}
//	engine.WithHandlers(callback)
func NewCallbackHandler[Out any](path string, cfg Config, respond func(context.Context, *TokenResponse) (Out, error)) (*rocco.Handler[rocco.NoBody, Out], error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("oauth: invalid config: %w", err)
	}
	if respond == nil {
		return nil, fmt.Errorf("oauth: respond function is required")
	}

	return rocco.GET[rocco.NoBody, Out](path, func(req *rocco.Request[rocco.NoBody]) (Out, error) {
		var zero Out

		// Extract code and state from query params
		code := req.URL.Query().Get("code")
		state := req.URL.Query().Get("state")

		if code == "" {
			// Check for error response from provider
			if errCode := req.URL.Query().Get("error"); errCode != "" {
				errDesc := req.URL.Query().Get("error_description")
				if errDesc == "" {
					errDesc = errCode
				}
				return zero, ErrBadGateway.WithDetails(BadGatewayDetails{
					Provider: cfg.Name,
					Reason:   errDesc,
				})
			}
			return zero, rocco.ErrBadRequest.WithMessage("authorization code not provided")
		}

		// Verify state
		valid, err := cfg.VerifyState(req.Context, state)
		if err != nil {
			return zero, rocco.ErrBadRequest.WithMessage("invalid or expired state parameter").WithCause(err)
		}
		if !valid {
			return zero, rocco.ErrBadRequest.WithMessage("invalid or expired state parameter")
		}

		// Exchange code for tokens
		tokens, err := exchangeCode(req.Context, cfg, code)
		if err != nil {
			return zero, err
		}

		// Call OnSuccess callback
		if err := cfg.OnSuccess(req.Context, tokens); err != nil {
			return zero, rocco.ErrInternalServer.WithMessage("failed to process authentication").WithCause(err)
		}

		// Return response via user-provided function
		return respond(req.Context, tokens)
	}).
		WithName(cfg.Name + "-callback").
		WithSummary("Handle " + cfg.Name + " OAuth callback").
		WithDescription("Processes the OAuth callback, exchanges code for tokens, and completes authentication.").
		WithQueryParams("code", "state").
		WithErrors(rocco.ErrBadRequest, ErrBadGateway, rocco.ErrInternalServer), nil
}

// Refresh exchanges a refresh token for new access and refresh tokens.
// This is a utility function for use in your own token refresh logic.
//
// Unlike NewLoginHandler and NewCallbackHandler, Refresh does not perform full
// config validation. It only requires TokenURL, ClientID, and ClientSecret to be set.
// The GenerateState, VerifyState, and OnSuccess callbacks are not used.
//
// Example:
//
//	newTokens, err := oauth.Refresh(ctx, cfg, oldRefreshToken)
//	if err != nil {
//	    // Handle error - user may need to re-authenticate
//	}
//	// Store newTokens
func Refresh(ctx context.Context, cfg Config, refreshToken string) (*TokenResponse, error) {
	cfg.defaults()

	data := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	return doTokenRequest(ctx, cfg, data)
}

// buildAuthURL constructs the OAuth authorization URL.
func buildAuthURL(cfg Config, state string) (string, error) {
	u, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return "", fmt.Errorf("invalid AuthURL: %w", err)
	}

	q := u.Query()
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("state", state)
	q.Set("response_type", "code")

	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// exchangeCode exchanges an authorization code for tokens.
func exchangeCode(ctx context.Context, cfg Config, code string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	}

	return doTokenRequest(ctx, cfg, data)
}

// doTokenRequest performs a token request to the OAuth provider.
func doTokenRequest(ctx context.Context, cfg Config, data url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, ErrBadGateway.WithDetails(BadGatewayDetails{Reason: "failed to create request"}).WithCause(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, ErrBadGateway.WithDetails(BadGatewayDetails{Reason: "failed to contact provider"}).WithCause(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrBadGateway.WithDetails(BadGatewayDetails{Reason: "failed to read response"}).WithCause(err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse error response
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			reason := errResp.ErrorDescription
			if reason == "" {
				reason = errResp.Error
			}
			return nil, ErrBadGateway.WithDetails(BadGatewayDetails{Reason: reason})
		}
		return nil, ErrBadGateway.WithDetails(BadGatewayDetails{
			Reason: fmt.Sprintf("token request failed with status %d", resp.StatusCode),
		})
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, ErrBadGateway.WithDetails(BadGatewayDetails{Reason: "invalid token response"}).WithCause(err)
	}

	return &tokens, nil
}
