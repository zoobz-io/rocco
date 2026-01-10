// Package rocco provides a type-safe HTTP framework for Go with automatic OpenAPI generation.
//
// Rocco enables building HTTP APIs with compile-time type safety, automatic request
// validation, and OpenAPI 3.1.0 specification generation from your Go types.
//
// # Core Types
//
// The framework is built around these primary types:
//
//   - [Engine]: HTTP server managing routing, middleware, and handler registration
//   - [Handler]: Type-safe request handler with generic input/output types
//   - [StreamHandler]: Handler for Server-Sent Events (SSE) streaming
//   - [Request]: Typed request container with body, parameters, and identity
//   - [Error]: Structured API error with typed details for OpenAPI generation
//
// # Creating an Engine
//
// Create an engine with host, port, and optional identity extraction:
//
//	engine := rocco.NewEngine("", 8080, nil)
//
// For authenticated APIs, provide an identity extractor:
//
//	engine := rocco.NewEngine("", 8080, func(ctx context.Context, r *http.Request) (rocco.Identity, error) {
//	    // Extract identity from request (e.g., JWT token)
//	    return identity, nil
//	})
//
// # Defining Handlers
//
// Handlers are generic over input and output types:
//
//	handler := rocco.NewHandler[CreateUserInput, UserOutput](
//	    "create-user",
//	    "POST",
//	    "/users",
//	    func(req *rocco.Request[CreateUserInput]) (UserOutput, error) {
//	        return UserOutput{ID: "123", Name: req.Body.Name}, nil
//	    },
//	)
//
// For handlers without a request body, use [NoBody]:
//
//	handler := rocco.NewHandler[rocco.NoBody, UserOutput](
//	    "get-user",
//	    "GET",
//	    "/users/{id}",
//	    func(req *rocco.Request[rocco.NoBody]) (UserOutput, error) {
//	        userID := req.Params.Path["id"]
//	        return UserOutput{ID: userID}, nil
//	    },
//	).WithPathParams("id")
//
// # Streaming (SSE)
//
// For real-time server-to-client communication:
//
//	handler := rocco.NewStreamHandler[rocco.NoBody, PriceUpdate](
//	    "price-stream",
//	    "GET",
//	    "/prices/stream",
//	    func(req *rocco.Request[rocco.NoBody], stream rocco.Stream[PriceUpdate]) error {
//	        for {
//	            select {
//	            case <-stream.Done():
//	                return nil
//	            default:
//	                stream.Send(PriceUpdate{Price: 100.0})
//	            }
//	        }
//	    },
//	)
//
// # Error Handling
//
// Use sentinel errors for typed HTTP error responses:
//
//	if user == nil {
//	    return UserOutput{}, rocco.ErrNotFound.WithMessage("user not found")
//	}
//
// Declare errors in handler configuration:
//
//	handler.WithErrors(rocco.ErrNotFound, rocco.ErrBadRequest)
//
// # OpenAPI Generation
//
// Register an OpenAPI endpoint to serve the generated specification:
//
//	engine.RegisterOpenAPIHandler("/openapi.json", rocco.Info{
//	    Title:   "My API",
//	    Version: "1.0.0",
//	})
//
// # Observability
//
// Rocco emits lifecycle events via capitan for observability integration:
//
//	capitan.Hook(rocco.RequestReceived, func(ctx context.Context, e *capitan.Event) {
//	    method, _ := rocco.MethodKey.From(e)
//	    path, _ := rocco.PathKey.From(e)
//	    log.Printf("Request: %s %s", method, path)
//	})
package rocco
