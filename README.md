# rocco

[![CI Status](https://github.com/zoobzio/rocco/workflows/CI/badge.svg)](https://github.com/zoobzio/rocco/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/zoobzio/rocco/graph/badge.svg?branch=main)](https://codecov.io/gh/zoobzio/rocco)
[![Go Report Card](https://goreportcard.com/badge/github.com/zoobzio/rocco)](https://goreportcard.com/report/github.com/zoobzio/rocco)
[![CodeQL](https://github.com/zoobzio/rocco/workflows/CodeQL/badge.svg)](https://github.com/zoobzio/rocco/security/code-scanning)
[![Go Reference](https://pkg.go.dev/badge/github.com/zoobzio/rocco.svg)](https://pkg.go.dev/github.com/zoobzio/rocco)
[![License](https://img.shields.io/github/license/zoobzio/rocco)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/zoobzio/rocco)](go.mod)
[![Release](https://img.shields.io/github/v/release/rocco)](https://github.com/zoobzio/rocco/releases)

Type-safe HTTP framework for Go with automatic OpenAPI generation.

Define your request and response types, wire up handlers, and get a fully-documented API with validation baked in.

## Types Become Endpoints

```go
type CreateUserInput struct {
    Name  string `json:"name" validate:"required,min=2"`
    Email string `json:"email" validate:"required,email"`
}

type UserOutput struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

handler := rocco.NewHandler[CreateUserInput, UserOutput](
    "create-user", "POST", "/users",
    func(req *rocco.Request[CreateUserInput]) (UserOutput, error) {
        return UserOutput{
            ID:    "usr_123",
            Name:  req.Body.Name,
            Email: req.Body.Email,
        }, nil
    },
).WithErrors(rocco.ErrBadRequest, rocco.ErrConflict)
```

Your types define the contract. Rocco handles validation, serialization, error responses, and OpenAPI schema generation — all derived from the same source of truth.

## Install

```bash
go get github.com/zoobzio/rocco
```

Requires Go 1.24+.

## Quick Start

```go
package main

import (
    "fmt"

    "github.com/zoobzio/openapi"
    "github.com/zoobzio/rocco"
)

type CreateUserInput struct {
    Name  string `json:"name" validate:"required,min=2"`
    Email string `json:"email" validate:"required,email"`
}

type UserOutput struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

func main() {
    engine := rocco.NewEngine()

    // Configure OpenAPI metadata
    engine.WithOpenAPIInfo(openapi.Info{
        Title:   "User API",
        Version: "1.0.0",
    })

    handler := rocco.NewHandler[CreateUserInput, UserOutput](
        "create-user", "POST", "/users",
        func(req *rocco.Request[CreateUserInput]) (UserOutput, error) {
            return UserOutput{
                ID:    "usr_123",
                Name:  req.Body.Name,
                Email: req.Body.Email,
            }, nil
        },
    ).
        WithSummary("Create a new user").
        WithTags("users").
        WithSuccessStatus(201).
        WithErrors(rocco.ErrBadRequest, rocco.ErrUnprocessableEntity)

    engine.WithHandlers(handler)

    // OpenAPI spec at /openapi, interactive docs at /docs
    fmt.Println("Server listening on :8080")
    engine.Start(rocco.HostAll, 8080)
}
```

## Capabilities

| Feature            | Description                                         | Docs                                      |
| ------------------ | --------------------------------------------------- | ----------------------------------------- |
| Type-Safe Handlers | Generic handlers with compile-time type checking    | [Handlers](docs/3.guides/1.handlers.md)   |
| Server-Sent Events | Built-in SSE support for real-time streaming        | [Streaming](docs/3.guides/6.streaming.md) |
| Automatic OpenAPI  | Generate OpenAPI 3.1.0 specs from your types        | [OpenAPI](docs/3.guides/4.openapi.md)     |
| Request Validation | Struct tag validation with detailed error responses | [Concepts](docs/2.learn/2.concepts.md)    |
| Sentinel Errors    | Typed HTTP errors with OpenAPI schema generation    | [Errors](docs/3.guides/2.errors.md)       |
| Lifecycle Events   | Observable signals for logging, metrics, tracing    | [Events](docs/5.reference/3.events.md)    |

## Why rocco?

- **Type-safe** — Generic handlers catch errors at compile time, not runtime
- **Self-documenting** — OpenAPI specs generated from the same types that validate requests
- **Explicit** — No magic, no hidden behaviors, no struct tag DSLs for routing
- **Chi-powered** — Built on the battle-tested Chi router with full middleware compatibility
- **Observable** — Lifecycle events via [capitan](https://github.com/zoobzio/capitan) for metrics and tracing
- **Streaming-native** — First-class SSE support with typed event streams

## Contract-First by Default

Rocco enables a pattern: **define types once, derive everything else**.

Your request and response structs become the single source of truth. From them, rocco derives validation rules, OpenAPI schemas, error contracts, and documentation.

**Define a type:**

```go
type CreateOrderInput struct {
    CustomerID string  `json:"customer_id" validate:"required,uuid4" description:"Customer UUID"`
    Items      []Item  `json:"items" validate:"required,min=1" description:"Order line items"`
    Total      float64 `json:"total" validate:"required,gt=0" description:"Order total in USD"`
}
```

**Get an OpenAPI schema:**

```yaml
CreateOrderInput:
  type: object
  required: [customer_id, items, total]
  properties:
    customer_id:
      type: string
      format: uuid
      description: Customer UUID
    items:
      type: array
      minItems: 1
      description: Order line items
      items:
        $ref: '#/components/schemas/Item'
    total:
      type: number
      exclusiveMinimum: 0
      description: Order total in USD
```

**Get consistent validation errors:**

```json
{
  "code": "VALIDATION_FAILED",
  "message": "validation failed",
  "details": {
    "fields": [
      {"field": "customer_id", "message": "must be a valid UUID"},
      {"field": "total", "message": "must be greater than 0"}
    ]
  }
}
```

No separate schema files. No manual sync between code and docs. The types ARE the contract.

## Documentation

- [Overview](docs/1.overview.md) — Design philosophy and architecture

### Learn

- [Quickstart](docs/2.learn/1.quickstart.md) — Get started in minutes
- [Concepts](docs/2.learn/2.concepts.md) — Handlers, requests, validation, errors
- [Architecture](docs/2.learn/3.architecture.md) — Internal design and components

### Guides

- [Handlers](docs/3.guides/1.handlers.md) — Request/response handlers and streaming
- [Errors](docs/3.guides/2.errors.md) — Sentinel errors and custom error types
- [Authentication](docs/3.guides/3.authentication.md) — Identity extraction and middleware
- [OpenAPI](docs/3.guides/4.openapi.md) — Schema generation and customization
- [Best Practices](docs/3.guides/5.best-practices.md) — Patterns and recommendations
- [Streaming](docs/3.guides/6.streaming.md) — Server-Sent Events

### Cookbook

- [CRUD API](docs/4.cookbook/1.crud-api.md) — Complete REST API example
- [Authentication](docs/4.cookbook/2.authentication.md) — JWT and session patterns
- [Observability](docs/4.cookbook/3.observability.md) — Logging, metrics, tracing
- [Realtime](docs/4.cookbook/4.realtime.md) — SSE patterns and use cases

### Reference

- [API](docs/5.reference/1.api.md) — Complete function documentation
- [Errors](docs/5.reference/2.errors.md) — All sentinel errors and detail types
- [Events](docs/5.reference/3.events.md) — Lifecycle signals and field keys

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
