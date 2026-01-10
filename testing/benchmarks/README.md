# Benchmarks

Performance tests measuring rocco's throughput and resource usage.

## Purpose

Benchmarks quantify the performance characteristics of rocco components. Results inform optimization decisions and establish baselines for detecting performance regressions.

## Benchmark Files

| File | Purpose |
|------|---------|
| `handler_test.go` | Handler processing (parsing, validation, execution) |
| `routing_test.go` | Route matching with various path patterns |
| `openapi_test.go` | OpenAPI specification generation |
| `stream_test.go` | Server-Sent Events streaming performance |

## Running Benchmarks

```bash
# Run all benchmarks
go test -bench=. ./testing/benchmarks/...

# Run with memory allocation stats
go test -bench=. -benchmem ./testing/benchmarks/...

# Run with multiple iterations for stability
go test -bench=. -benchmem -count=5 ./testing/benchmarks/...

# Run specific benchmark
go test -bench=BenchmarkHandlerProcess -benchmem ./testing/benchmarks/...

# Profile CPU usage
go test -bench=. -cpuprofile=cpu.prof ./testing/benchmarks/...

# Profile memory allocations
go test -bench=. -memprofile=mem.prof ./testing/benchmarks/...
```

## Interpreting Results

```
BenchmarkHandlerProcess-8    500000    2340 ns/op    512 B/op    8 allocs/op
```

| Field | Meaning |
|-------|---------|
| `BenchmarkHandlerProcess-8` | Benchmark name, 8 CPUs |
| `500000` | Iterations executed |
| `2340 ns/op` | Nanoseconds per operation |
| `512 B/op` | Bytes allocated per operation |
| `8 allocs/op` | Allocations per operation |

## Writing Benchmarks

### Guidelines

1. **Use `b.ReportAllocs()`** - Track memory allocations
2. **Use sub-benchmarks** - Test variations with `b.Run()`
3. **Reset timer after setup** - Call `b.ResetTimer()` after initialization
4. **Loop correctly** - Run operations exactly `b.N` times
5. **Avoid dead code elimination** - Store results in package-level variables

### Example Pattern

```go
var benchResult any // Prevent dead code elimination

func BenchmarkHandlerProcess(b *testing.B) {
    engine := setupEngine()
    handler := createHandler()
    engine.WithHandlers(handler)

    req := httptest.NewRequest("POST", "/users", strings.NewReader(`{"name":"test"}`))
    req.Header.Set("Content-Type", "application/json")

    b.ReportAllocs()
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        w := httptest.NewRecorder()
        engine.ServeHTTP(w, req)
        benchResult = w.Result()
    }
}
```

### Sub-benchmarks

Test multiple scenarios:

```go
func BenchmarkRouting(b *testing.B) {
    cases := []struct {
        name string
        path string
    }{
        {"static", "/users"},
        {"single_param", "/users/123"},
        {"multi_param", "/users/123/posts/456"},
    }

    for _, tc := range cases {
        b.Run(tc.name, func(b *testing.B) {
            req := httptest.NewRequest("GET", tc.path, nil)
            b.ReportAllocs()
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                w := httptest.NewRecorder()
                engine.ServeHTTP(w, req)
            }
        })
    }
}
```

## Performance Targets

| Operation | Target | Acceptable |
|-----------|--------|------------|
| Handler processing | < 5μs | < 10μs |
| Route matching | < 500ns | < 1μs |
| OpenAPI generation | < 100ms | < 500ms |
| SSE event send | < 1μs | < 5μs |

## Comparing Results

Use `benchstat` for statistical comparison:

```bash
# Install benchstat
go install golang.org/x/perf/cmd/benchstat@latest

# Run benchmarks and save results
go test -bench=. -count=10 ./testing/benchmarks/... > old.txt

# After changes
go test -bench=. -count=10 ./testing/benchmarks/... > new.txt

# Compare
benchstat old.txt new.txt
```
