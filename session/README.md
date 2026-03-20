# rocco/session

Cookie-based session management for rocco APIs.

## Installation

```bash
go get github.com/zoobz-io/rocco/session
```

## Usage

```go
store := session.NewMemoryStore()

cfg := session.Config{
    OAuth: oauth.GitHub(),
    Store: store,
    Cookie: session.CookieConfig{
        SignKey: []byte(os.Getenv("SESSION_KEY")),
    },
    Resolve: func(ctx context.Context, tokens *oauth.TokenResponse) (*session.Data, error) {
        // Call provider API to get user info
        return &session.Data{UserID: "123", Email: "user@example.com"}, nil
    },
    RedirectURL: "/dashboard",
}
cfg.OAuth.ClientID = os.Getenv("CLIENT_ID")
cfg.OAuth.ClientSecret = os.Getenv("CLIENT_SECRET")
cfg.OAuth.RedirectURI = "https://myapp.com/auth/callback"

// Create handlers
login, _ := session.NewLoginHandler("/auth/login", cfg)
callback, _ := session.NewCallbackHandler("/auth/callback", cfg)
logout, _ := session.NewLogoutHandler("/auth/logout", cfg, "/")

// Wire up engine
engine := rocco.NewEngine().
    WithAuthenticator(session.Extractor(store, cfg.Cookie)).
    WithHandlers(login, callback, logout)
```

## Store Interface

Implement `session.Store` for your storage backend:

```go
type Store interface {
    CreateState(ctx context.Context, state string) error
    VerifyState(ctx context.Context, state string) (bool, error)
    Create(ctx context.Context, id string, data Data) error
    Get(ctx context.Context, id string) (*Data, error)
    Refresh(ctx context.Context, id string) error
    Delete(ctx context.Context, id string) error
}
```

Use `session.NewMemoryStore()` for development and testing.

## Design

This package bridges [rocco/oauth](../oauth) with `rocco.Identity` by managing:

- OAuth login initiation and callback handling
- CSRF state token generation and verification
- Session creation, retrieval, and destruction
- Signed cookie management
