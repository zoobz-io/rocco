# rocco/oauth

OAuth 2.0 authorization code flow primitives.

## Installation

```bash
go get github.com/zoobzio/rocco/oauth
```

## Usage

```go
cfg := oauth.GitHub()
cfg.ClientID = os.Getenv("GITHUB_CLIENT_ID")
cfg.ClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
cfg.RedirectURI = "https://myapp.com/auth/callback"

// Build authorization URL
authURL, err := oauth.AuthURL(cfg, state)

// Exchange code for tokens
tokens, err := oauth.Exchange(ctx, cfg, code)

// Refresh tokens
newTokens, err := oauth.Refresh(ctx, cfg, refreshToken)
```

## Providers

Built-in configurations:

- `oauth.GitHub()` - GitHub OAuth
- `oauth.GitHubEnterprise(baseURL)` - GitHub Enterprise Server

Custom providers work with any OAuth 2.0 compliant endpoint:

```go
cfg := oauth.Config{
    Name:     "custom",
    AuthURL:  "https://provider.com/oauth/authorize",
    TokenURL: "https://provider.com/oauth/token",
}
```

## Design

This package handles protocol mechanics only. It does not manage HTTP handlers, sessions, or cookies. For complete session management, see [rocco/session](../session).
