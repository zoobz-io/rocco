# rocco/auth0

Auth0 JWT authentication for rocco APIs.

## Installation

```bash
go get github.com/zoobzio/rocco/auth0
```

## Usage

```go
extractor, err := auth0.NewExtractor(auth0.Config{
    Domain:   "your-tenant.auth0.com",
    Audience: "https://your-api.example.com",
})
if err != nil {
    log.Fatal(err)
}

engine := rocco.NewEngine().WithAuthenticator(extractor)
```

## Configuration

```go
auth0.Config{
    // Required
    Domain:   "your-tenant.auth0.com",
    Audience: "https://your-api.example.com",

    // Optional - claim paths
    RolesClaim:  "https://myapp.com/roles",  // default: "roles"
    ScopesClaim: "scope",                     // default: "scope"
    TenantClaim: "https://myapp.com/tenant",  // for multi-tenancy

    // Optional - tuning
    JWKSRefreshInterval: time.Hour,           // default: 1 hour
}
```

## Advanced Usage

For more control, use the Validator directly:

```go
validator, err := auth0.NewValidator(auth0.Config{
    Domain:      "your-tenant.auth0.com",
    Audience:    "https://your-api.example.com",
    RolesClaim:  "https://myapp.com/roles",
    TenantClaim: "https://myapp.com/tenant_id",
})
if err != nil {
    log.Fatal(err)
}

// Use as extractor
engine := rocco.NewEngine().WithAuthenticator(validator.Extractor())

// Or validate tokens directly
identity, err := validator.Validate(ctx, tokenString)
```

## Design

This package validates Auth0-issued JWTs and extracts identity information compatible with `rocco.Identity`. It handles:

- JWKS fetching and caching
- RS256 signature verification
- Issuer and audience validation
- Token expiration checking
- Claim extraction (subject, email, roles, scopes, tenant)
