package rocco

import "context"

// Entryable is implemented by input types that transform themselves before handler execution.
// Hooks run after body parsing and validation, before the handler function.
type Entryable interface {
	OnEntry(ctx context.Context) error
}

// Sendable is implemented by output types that transform themselves before marshaling.
// Hooks run after the handler function, before output validation and marshaling.
type Sendable interface {
	OnSend(ctx context.Context) error
}
