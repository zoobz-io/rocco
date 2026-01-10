# Integration Tests

End-to-end tests validating complete request flows through rocco.

## Purpose

Integration tests verify that rocco components work together correctly in realistic scenarios. Unlike unit tests that isolate individual functions, these tests exercise full request lifecycles including routing, middleware, parsing, validation, and response serialization.

## Test Files

| File | Purpose |
|------|---------|
| `concurrency_test.go` | Concurrent request handling, race condition detection |
| `real_world_test.go` | CRUD operations, multi-step API workflows |
| `stream_test.go` | Server-Sent Events (SSE) streaming behavior |

## Running Tests

```bash
# Run all integration tests
go test ./testing/integration/...

# Run with race detector (recommended)
go test -race ./testing/integration/...

# Run with verbose output
go test -v ./testing/integration/...

# Run specific test
go test -v -run TestConcurrentRequests ./testing/integration/...
```

## Writing Integration Tests

### Guidelines

1. **Test complete flows** - Start with an HTTP request and verify the response
2. **Use httptest** - Create real HTTP requests via `httptest.NewRequest`
3. **Verify both paths** - Test success cases and error handling
4. **Include concurrency** - Test simultaneous request handling
5. **Clean up resources** - Use `defer` for cleanup

### Example Pattern

```go
func TestUserCreation(t *testing.T) {
    engine := testing.NewTestEngine()

    handler := rocco.NewHandler[CreateUserInput, UserOutput](
        "create-user",
        "POST",
        "/users",
        func(req *rocco.Request[CreateUserInput]) (UserOutput, error) {
            return UserOutput{ID: "123", Name: req.Body.Name}, nil
        },
    )
    engine.WithHandlers(handler)

    // Create request
    req := testing.NewRequestBuilder("POST", "/users").
        WithJSON(CreateUserInput{Name: "test"}).
        Build()

    // Execute
    capture := testing.NewResponseCapture()
    engine.ServeHTTP(capture, req)

    // Verify
    if capture.StatusCode() != 201 {
        t.Errorf("status = %d, want 201", capture.StatusCode())
    }
}
```

### Concurrency Testing

Use `t.Parallel()` and `sync.WaitGroup` for concurrent tests:

```go
func TestConcurrentAccess(t *testing.T) {
    engine := setupEngine()

    var wg sync.WaitGroup
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            req := httptest.NewRequest("GET", "/resource", nil)
            w := httptest.NewRecorder()
            engine.ServeHTTP(w, req)
        }()
    }
    wg.Wait()
}
```

## Build Tags

Integration tests use the `integration` build tag when they require external resources or long execution times:

```go
//go:build integration

package integration
```

Run tagged tests with:

```bash
go test -tags=integration ./testing/integration/...
```
