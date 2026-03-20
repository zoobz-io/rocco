package auth0

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zoobz-io/capitan"
	"github.com/zoobz-io/clockz"
	"github.com/zoobz-io/rocco"
)

// Validator handles JWT validation and JWKS management.
type Validator struct {
	cfg        Config
	issuer     string
	jwksURL    string
	clock      clockz.Clock
	httpClient *http.Client
	keyCache   map[string]*rsa.PublicKey
	keyMu      sync.RWMutex
	lastFetch  time.Time
}

// NewValidator creates a new Validator with the given configuration.
func NewValidator(cfg Config) (*Validator, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	issuer := fmt.Sprintf("https://%s/", cfg.Domain)
	jwksURL := cfg.jwksURL
	if jwksURL == "" {
		jwksURL = fmt.Sprintf("https://%s/.well-known/jwks.json", cfg.Domain)
	}

	v := &Validator{
		cfg:        cfg,
		issuer:     issuer,
		jwksURL:    jwksURL,
		clock:      cfg.Clock,
		httpClient: cfg.HTTPClient,
		keyCache:   make(map[string]*rsa.PublicKey),
	}

	return v, nil
}

// Validate parses and validates a JWT token string.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Identity, error) {
	token, err := jwt.Parse(tokenString, v.keyFunc(ctx), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, fmt.Errorf("auth0: invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("auth0: invalid token claims")
	}

	// Validate issuer
	iss, _ := claims["iss"].(string)
	if iss != v.issuer {
		return nil, fmt.Errorf("auth0: invalid issuer: got %q, want %q", iss, v.issuer)
	}

	// Validate audience
	if err := v.validateAudience(claims); err != nil {
		return nil, err
	}

	// Validate expiration
	if err := v.validateExpiration(claims); err != nil {
		return nil, err
	}

	// Extract identity from claims
	identity := extractIdentity(claims, &v.cfg)
	return identity, nil
}

// validateAudience checks the aud claim.
func (v *Validator) validateAudience(claims jwt.MapClaims) error {
	aud, ok := claims["aud"]
	if !ok {
		return errors.New("auth0: missing audience claim")
	}

	switch a := aud.(type) {
	case string:
		if a != v.cfg.Audience {
			return fmt.Errorf("auth0: invalid audience: got %q, want %q", a, v.cfg.Audience)
		}
	case []any:
		found := false
		for _, item := range a {
			if s, ok := item.(string); ok && s == v.cfg.Audience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("auth0: audience %q not found in token", v.cfg.Audience)
		}
	default:
		return errors.New("auth0: invalid audience format")
	}
	return nil
}

// validateExpiration checks the exp claim.
func (v *Validator) validateExpiration(claims jwt.MapClaims) error {
	exp, ok := claims["exp"]
	if !ok {
		return errors.New("auth0: missing expiration claim")
	}

	var expTime time.Time
	switch e := exp.(type) {
	case float64:
		expTime = time.Unix(int64(e), 0)
	case json.Number:
		n, err := e.Int64()
		if err != nil {
			return fmt.Errorf("auth0: invalid expiration format: %w", err)
		}
		expTime = time.Unix(n, 0)
	default:
		return errors.New("auth0: invalid expiration format")
	}

	if v.clock.Now().After(expTime) {
		return errors.New("auth0: token expired")
	}
	return nil
}

// keyFunc returns a jwt.Keyfunc that fetches keys from JWKS.
func (v *Validator) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("auth0: missing kid in token header")
		}

		key, err := v.getKey(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}

// getKey retrieves a public key by kid, fetching JWKS if necessary.
func (v *Validator) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Check cache first
	v.keyMu.RLock()
	key, ok := v.keyCache[kid]
	cacheAge := v.clock.Now().Sub(v.lastFetch)
	v.keyMu.RUnlock()

	if ok {
		return key, nil
	}

	// Key not found - refresh if cache is stale or key is new
	if cacheAge > v.cfg.JWKSRefreshInterval || !ok {
		if err := v.refreshJWKS(ctx); err != nil {
			return nil, err
		}
	}

	// Try again after refresh
	v.keyMu.RLock()
	key, ok = v.keyCache[kid]
	v.keyMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("auth0: key %q not found in JWKS", kid)
	}
	return key, nil
}

// refreshJWKS fetches the JWKS from Auth0.
func (v *Validator) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("auth0: failed to create JWKS request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth0: failed to fetch JWKS: %w", err)
	}
	defer closeResponseBody(ctx, resp, v.jwksURL)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth0: JWKS request failed with status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("auth0: failed to decode JWKS: %w", err)
	}

	// Parse and cache keys
	v.keyMu.Lock()
	defer v.keyMu.Unlock()

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		pubKey, err := parseRSAPublicKey(key)
		if err != nil {
			continue // Skip invalid keys
		}
		v.keyCache[key.Kid] = pubKey
	}

	v.lastFetch = v.clock.Now()
	return nil
}

// jwksResponse represents the JWKS endpoint response.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey represents a single JWK.
type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parseRSAPublicKey converts a JWK to an RSA public key.
func parseRSAPublicKey(key jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("auth0: invalid modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("auth0: invalid exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
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

// extractBearerToken extracts the JWT from the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", errors.New("auth0: missing Authorization header")
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("auth0: invalid Authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("auth0: empty bearer token")
	}

	return token, nil
}

// closeResponseBody closes the response body and emits an event on error.
func closeResponseBody(ctx context.Context, resp *http.Response, endpoint string) {
	if err := resp.Body.Close(); err != nil {
		capitan.Warn(ctx, rocco.ResponseBodyCloseError,
			rocco.EndpointKey.Field(endpoint),
			rocco.ErrorKey.Field(err.Error()),
		)
	}
}
