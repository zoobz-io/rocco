package auth0

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zoobzio/capitan"
	"github.com/zoobzio/clockz"
	"github.com/zoobzio/rocco"
)

// TestMain sets up capitan in sync mode for all tests.
func TestMain(m *testing.M) {
	capitan.Configure(capitan.WithSyncMode())
	os.Exit(m.Run())
}

// testSetup creates a mock JWKS server and returns all test fixtures.
func testSetup(t *testing.T) (*httptest.Server, *rsa.PrivateKey, Config) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubKey := &privateKey.PublicKey
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "test-key-id",
				"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Errorf("failed to encode JWKS: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	cfg := Config{
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}.WithJWKSURL(server.URL)

	return server, privateKey, cfg
}

// generateToken creates a signed JWT token with the given claims.
func generateToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-id"

	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

// validClaims returns standard valid claims.
func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   "https://test.auth0.com/",
		"aud":   "https://api.test.com",
		"sub":   "user-123",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read:users write:users",
		"roles": []string{"admin", "user"},
		"email": "test@example.com",
	}
}

func TestNewValidator(t *testing.T) {
	_, key, cfg := testSetup(t)

	v, err := NewValidator(cfg)
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}

	if v.issuer != "https://test.auth0.com/" {
		t.Errorf("issuer = %q, want %q", v.issuer, "https://test.auth0.com/")
	}

	// Test validation works
	token := generateToken(t, key, validClaims())
	identity, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if identity.ID() != "user-123" {
		t.Errorf("ID() = %q, want %q", identity.ID(), "user-123")
	}
}

func TestValidator_Validate_success(t *testing.T) {
	_, key, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	claims := validClaims()
	token := generateToken(t, key, claims)

	identity, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if identity.ID() != "user-123" {
		t.Errorf("ID() = %q, want %q", identity.ID(), "user-123")
	}
	if identity.Email() != "test@example.com" {
		t.Errorf("Email() = %q, want %q", identity.Email(), "test@example.com")
	}
	if !identity.HasScope("read:users") {
		t.Error("HasScope(read:users) = false, want true")
	}
	if !identity.HasRole("admin") {
		t.Error("HasRole(admin) = false, want true")
	}
}

func TestValidator_Validate_invalid_issuer(t *testing.T) {
	_, key, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	claims := validClaims()
	claims["iss"] = "https://wrong.auth0.com/"
	token := generateToken(t, key, claims)

	_, err := v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail with wrong issuer")
	}
}

func TestValidator_Validate_invalid_audience(t *testing.T) {
	_, key, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	claims := validClaims()
	claims["aud"] = "https://wrong.api.com"
	token := generateToken(t, key, claims)

	_, err := v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail with wrong audience")
	}
}

func TestValidator_Validate_audience_array(t *testing.T) {
	_, key, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	claims := validClaims()
	claims["aud"] = []any{"https://other.api.com", "https://api.test.com"}
	token := generateToken(t, key, claims)

	_, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Errorf("Validate() should accept audience in array: %v", err)
	}
}

func TestValidator_Validate_audience_array_not_found(t *testing.T) {
	_, key, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	claims := validClaims()
	claims["aud"] = []any{"https://other.api.com", "https://another.api.com"}
	token := generateToken(t, key, claims)

	_, err := v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail when audience not in array")
	}
}

func TestValidator_Validate_expired_token(t *testing.T) {
	_, key, cfg := testSetup(t)

	// Use a mock clock set to "now"
	now := time.Now()
	cfg.Clock = clockz.NewFakeClockAt(now)
	v, _ := NewValidator(cfg)

	claims := validClaims()
	claims["exp"] = now.Add(-time.Hour).Unix() // Expired 1 hour ago
	token := generateToken(t, key, claims)

	_, err := v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail with expired token")
	}
}

func TestValidator_Validate_missing_expiration(t *testing.T) {
	_, key, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	claims := validClaims()
	delete(claims, "exp")
	token := generateToken(t, key, claims)

	_, err := v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail with missing expiration")
	}
}

func TestValidator_Validate_missing_audience(t *testing.T) {
	_, key, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	claims := validClaims()
	delete(claims, "aud")
	token := generateToken(t, key, claims)

	_, err := v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail with missing audience")
	}
}

func TestValidator_Validate_invalid_token(t *testing.T) {
	_, _, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	_, err := v.Validate(context.Background(), "not-a-valid-token")
	if err == nil {
		t.Error("Validate() should fail with invalid token")
	}
}

func TestValidator_Validate_wrong_signing_key(t *testing.T) {
	_, _, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	// Generate a different key
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	token := generateToken(t, wrongKey, validClaims())

	_, err = v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail with wrong signing key")
	}
}

func TestValidator_Extractor(t *testing.T) {
	_, key, cfg := testSetup(t)
	v, _ := NewValidator(cfg)

	extractor := v.Extractor()

	t.Run("valid token", func(t *testing.T) {
		token := generateToken(t, key, validClaims())
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		identity, err := extractor(context.Background(), req)
		if err != nil {
			t.Fatalf("Extractor() error = %v", err)
		}
		if identity.ID() != "user-123" {
			t.Errorf("ID() = %q, want %q", identity.ID(), "user-123")
		}
	})

	t.Run("missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		_, err := extractor(context.Background(), req)
		if err == nil {
			t.Error("Extractor() should fail without Authorization header")
		}
	})

	t.Run("invalid authorization format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

		_, err := extractor(context.Background(), req)
		if err == nil {
			t.Error("Extractor() should fail with non-Bearer auth")
		}
	})

	t.Run("empty bearer token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer ")

		_, err := extractor(context.Background(), req)
		if err == nil {
			t.Error("Extractor() should fail with empty bearer token")
		}
	})
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{
			name:    "valid bearer token",
			header:  "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			want:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr: false,
		},
		{
			name:    "lowercase bearer",
			header:  "bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			want:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr: false,
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
			name:    "bearer only",
			header:  "Bearer",
			wantErr: true,
		},
		{
			name:    "bearer with spaces only",
			header:  "Bearer   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			got, err := extractBearerToken(req)
			if tt.wantErr {
				if err == nil {
					t.Error("extractBearerToken() should fail")
				}
			} else {
				if err != nil {
					t.Errorf("extractBearerToken() error = %v", err)
				}
				if got != tt.want {
					t.Errorf("extractBearerToken() = %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestValidator_JWKS_caching(t *testing.T) {
	fetchCount := 0
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &privateKey.PublicKey
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "test-key-id",
				"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cfg := Config{
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}.WithJWKSURL(server.URL)

	v, _ := NewValidator(cfg)

	// First request should fetch JWKS
	token := generateToken(t, privateKey, validClaims())
	_, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("first Validate() error = %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d after first request, want 1", fetchCount)
	}

	// Second request should use cached key
	_, err = v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("second Validate() error = %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d after second request, want 1", fetchCount)
	}
}

func TestValidator_JWKS_refresh_on_missing_key(t *testing.T) {
	fetchCount := 0
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &privateKey.PublicKey

	// Second key that will be added after first fetch
	privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey2 := &privateKey2.PublicKey

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		keys := []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "test-key-id",
				"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
			},
		}
		// Add second key on second fetch
		if fetchCount > 1 {
			keys = append(keys, map[string]any{
				"kty": "RSA",
				"use": "sig",
				"kid": "test-key-id-2",
				"n":   base64.RawURLEncoding.EncodeToString(pubKey2.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey2.E)).Bytes()),
			})
		}
		jwks := map[string]any{"keys": keys}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cfg := Config{
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}.WithJWKSURL(server.URL)

	v, _ := NewValidator(cfg)

	// First request with first key
	claims := validClaims()
	token1 := generateToken(t, privateKey, claims)
	_, err := v.Validate(context.Background(), token1)
	if err != nil {
		t.Fatalf("first Validate() error = %v", err)
	}

	// Request with second key should trigger refresh
	token2 := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token2.Header["kid"] = "test-key-id-2"
	tokenString2, _ := token2.SignedString(privateKey2)

	_, err = v.Validate(context.Background(), tokenString2)
	if err != nil {
		t.Fatalf("second Validate() error = %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("fetchCount = %d, want 2 (should have refreshed)", fetchCount)
	}
}

func TestValidator_JWKS_fetch_error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := Config{
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}.WithJWKSURL(server.URL)

	v, _ := NewValidator(cfg)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := generateToken(t, privateKey, validClaims())

	_, err := v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail when JWKS fetch fails")
	}
}

func TestValidator_JWKS_invalid_json(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	cfg := Config{
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}.WithJWKSURL(server.URL)

	v, _ := NewValidator(cfg)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := generateToken(t, privateKey, validClaims())

	_, err := v.Validate(context.Background(), token)
	if err == nil {
		t.Error("Validate() should fail when JWKS is invalid JSON")
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &privateKey.PublicKey

	jwk := jwkKey{
		Kty: "RSA",
		Use: "sig",
		Kid: "test",
		N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}

	parsedKey, err := parseRSAPublicKey(jwk)
	if err != nil {
		t.Fatalf("parseRSAPublicKey() error = %v", err)
	}

	if parsedKey.N.Cmp(pubKey.N) != 0 {
		t.Error("parsed key N does not match original")
	}
	if parsedKey.E != pubKey.E {
		t.Error("parsed key E does not match original")
	}
}

func TestParseRSAPublicKey_invalid(t *testing.T) {
	tests := []struct {
		name string
		jwk  jwkKey
	}{
		{
			name: "invalid modulus",
			jwk: jwkKey{
				N: "!!!not-base64!!!",
				E: "AQAB",
			},
		},
		{
			name: "invalid exponent",
			jwk: jwkKey{
				N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				E: "!!!not-base64!!!",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRSAPublicKey(tt.jwk)
			if err == nil {
				t.Error("parseRSAPublicKey() should fail")
			}
		})
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

	closeResponseBody(context.Background(), resp, "https://test.auth0.com/.well-known/jwks.json")

	if !received {
		t.Error("ResponseBodyCloseError not emitted")
	}
	if endpoint != "https://test.auth0.com/.well-known/jwks.json" {
		t.Errorf("endpoint = %q, want %q", endpoint, "https://test.auth0.com/.well-known/jwks.json")
	}
	if errorMsg != "simulated close error" {
		t.Errorf("error = %q, want %q", errorMsg, "simulated close error")
	}
}
