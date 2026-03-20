package session

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoobz-io/rocco/oauth"
)

// failStore is a Store that returns errors for specified operations.
type failStore struct {
	Store
	failCreateState bool
	failVerifyState bool
	failCreate      bool
}

func (f *failStore) CreateState(ctx context.Context, state string) error {
	if f.failCreateState {
		return errors.New("store: CreateState failed")
	}
	return f.Store.CreateState(ctx, state)
}

func (f *failStore) VerifyState(ctx context.Context, state string) (bool, error) {
	if f.failVerifyState {
		return false, errors.New("store: VerifyState failed")
	}
	return f.Store.VerifyState(ctx, state)
}

func (f *failStore) Create(ctx context.Context, id string, data Data) error {
	if f.failCreate {
		return errors.New("store: Create failed")
	}
	return f.Store.Create(ctx, id, data)
}

func validConfig(tokenURL string) Config {
	return Config{
		OAuth: oauth.Config{
			Name:         "test",
			AuthURL:      "https://provider.com/auth",
			TokenURL:     tokenURL,
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURI:  "https://myapp.com/callback",
		},
		Store: NewMemoryStore(),
		Cookie: CookieConfig{
			SignKey: []byte("test-secret-key-for-signing-cookies"),
		},
		Resolve: func(ctx context.Context, tokens *oauth.TokenResponse) (*Data, error) {
			return &Data{
				UserID: "user-1",
				Email:  "user@example.com",
			}, nil
		},
		RedirectURL: "/dashboard",
	}
}

func TestNewLoginHandler(t *testing.T) {
	cfg := validConfig("https://provider.com/token")

	handler, err := NewLoginHandler("/auth/login", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	status, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, status)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}

	if !strings.Contains(location, "client_id=client-id") {
		t.Errorf("expected client_id in URL, got %s", location)
	}
	if !strings.Contains(location, "state=") {
		t.Errorf("expected state in URL, got %s", location)
	}
	if !strings.Contains(location, "response_type=code") {
		t.Errorf("expected response_type in URL, got %s", location)
	}
}

func TestNewLoginHandler_InvalidConfig(t *testing.T) {
	cfg := Config{} // Empty config.
	_, err := NewLoginHandler("/auth/login", cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewCallbackHandler_Success(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oauth.TokenResponse{
			AccessToken: "access-token-xyz",
			TokenType:   "Bearer",
		})
	}))
	defer mockServer.Close()

	cfg := validConfig(mockServer.URL)

	// Pre-create state.
	cfg.Store.CreateState(context.Background(), "valid-state")

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code&state=valid-state", nil)
	w := httptest.NewRecorder()

	status, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, status)
	}

	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected Location '/dashboard', got %q", loc)
	}

	// Should have Set-Cookie header.
	cookies := w.Header().Values("Set-Cookie")
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header")
	}
	if !strings.Contains(cookies[0], "sid=") {
		t.Errorf("expected session cookie, got %q", cookies[0])
	}
}

func TestNewCallbackHandler_InvalidState(t *testing.T) {
	cfg := validConfig("https://provider.com/token")

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=wrong", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, status)
	}
}

func TestNewCallbackHandler_MissingCode(t *testing.T) {
	cfg := validConfig("https://provider.com/token")

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, status)
	}
}

func TestNewCallbackHandler_ProviderError(t *testing.T) {
	cfg := validConfig("https://provider.com/token")

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&error_description=User+denied", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, status)
	}
}

func TestNewCallbackHandler_ExchangeFailure(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Code expired",
		})
	}))
	defer mockServer.Close()

	cfg := validConfig(mockServer.URL)
	cfg.Store.CreateState(context.Background(), "valid-state")

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=expired&state=valid-state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, status)
	}
}

func TestNewCallbackHandler_ResolveFailure(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oauth.TokenResponse{
			AccessToken: "token",
			TokenType:   "Bearer",
		})
	}))
	defer mockServer.Close()

	cfg := validConfig(mockServer.URL)
	cfg.Resolve = func(ctx context.Context, tokens *oauth.TokenResponse) (*Data, error) {
		return nil, errors.New("resolve failed")
	}
	cfg.Store.CreateState(context.Background(), "valid-state")

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=valid-state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestNewCallbackHandler_InvalidConfig(t *testing.T) {
	cfg := Config{}
	_, err := NewCallbackHandler("/auth/callback", cfg)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewLogoutHandler(t *testing.T) {
	store := NewMemoryStore()
	cookie := CookieConfig{SignKey: []byte("test-key")}
	cookie.defaults()

	// Create a session.
	store.Create(context.Background(), "sess-1", Data{UserID: "user-1"})
	signedValue := signValue("sess-1", cookie.SignKey)

	cfg := Config{Store: store, Cookie: cookie}

	handler, err := NewLogoutHandler("/auth/logout", cfg, "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: signedValue})
	w := httptest.NewRecorder()

	status, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, status)
	}

	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("expected Location '/', got %q", loc)
	}

	// Cookie should be cleared.
	cookies := w.Header().Values("Set-Cookie")
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header to clear cookie")
	}
	if !strings.Contains(cookies[0], "Max-Age=0") {
		t.Errorf("expected Max-Age=0 in clear cookie, got %q", cookies[0])
	}

	// Session should be deleted from store.
	_, err = store.Get(context.Background(), "sess-1")
	if err == nil {
		t.Error("expected session to be deleted")
	}
}

func TestNewLogoutHandler_NoCookie(t *testing.T) {
	store := NewMemoryStore()
	cookie := CookieConfig{SignKey: []byte("test-key")}

	cfg := Config{Store: store, Cookie: cookie}

	handler, err := NewLogoutHandler("/auth/logout", cfg, "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	w := httptest.NewRecorder()

	status, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, status)
	}
}

func TestNewLogoutHandler_InvalidConfig(t *testing.T) {
	cfg := Config{}
	_, err := NewLogoutHandler("/auth/logout", cfg, "/")
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewLogoutHandler_MissingSignKey(t *testing.T) {
	cfg := Config{Store: NewMemoryStore()}
	_, err := NewLogoutHandler("/auth/logout", cfg, "/")
	if err == nil {
		t.Fatal("expected error for missing SignKey")
	}
}

func TestNewCallbackHandler_ProviderErrorNoDescription(t *testing.T) {
	cfg := validConfig("https://provider.com/token")

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, status)
	}
}

func TestConfig_Validate(t *testing.T) {
	base := func() Config {
		return validConfig("https://provider.com/token")
	}

	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"missing store", func(c *Config) { c.Store = nil }},
		{"missing sign key", func(c *Config) { c.Cookie.SignKey = nil }},
		{"missing resolve", func(c *Config) { c.Resolve = nil }},
		{"missing redirect URL", func(c *Config) { c.RedirectURL = "" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.modify(&cfg)
			if err := cfg.validate(); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestNewLoginHandler_StateGenerationFailure(t *testing.T) {
	cfg := validConfig("https://provider.com/token")
	cfg.Store = &failStore{Store: NewMemoryStore(), failCreateState: true}

	handler, err := NewLoginHandler("/auth/login", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestNewLoginHandler_InvalidAuthURL(t *testing.T) {
	cfg := validConfig("https://provider.com/token")
	cfg.OAuth.AuthURL = "://invalid"

	handler, err := NewLoginHandler("/auth/login", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestNewCallbackHandler_StateVerifyError(t *testing.T) {
	cfg := validConfig("https://provider.com/token")
	cfg.Store = &failStore{Store: NewMemoryStore(), failVerifyState: true}

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, status)
	}
}

func TestNewCallbackHandler_StoreCreateFailure(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oauth.TokenResponse{
			AccessToken: "token",
			TokenType:   "Bearer",
		})
	}))
	defer mockServer.Close()

	mem := NewMemoryStore()
	cfg := validConfig(mockServer.URL)
	cfg.Store = &failStore{Store: mem, failCreate: true}

	// Pre-create state in the underlying store.
	mem.CreateState(context.Background(), "valid-state")

	handler, err := NewCallbackHandler("/auth/callback", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code&state=valid-state", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)
	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestGenerateState_StoreFailure(t *testing.T) {
	store := &failStore{Store: NewMemoryStore(), failCreateState: true}
	genState := GenerateState(store)

	_, err := genState(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to store state") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerateState_And_VerifyState(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	genState := GenerateState(store)
	state, err := genState(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state == "" {
		t.Fatal("expected non-empty state")
	}

	verify := VerifyState(store)
	ok, err := verify(ctx, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected state to be valid")
	}

	// Second verify should fail (single-use).
	ok, err = verify(ctx, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected state to be consumed")
	}
}
