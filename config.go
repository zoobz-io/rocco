// Package rocco provides a type-safe HTTP framework for Go with automatic OpenAPI generation.
package rocco

import "time"

// Common host constants for use with Engine.Start().
const (
	HostAll      = ""          // Bind to all interfaces (0.0.0.0)
	HostLocal    = "localhost" // Bind to loopback (localhost)
	HostLoopback = "127.0.0.1" // Bind to loopback (127.0.0.1)
)

// EngineConfig holds configuration for the Engine.
type EngineConfig struct {
	ReadTimeout  time.Duration // Maximum duration for reading entire request
	WriteTimeout time.Duration // Maximum duration for writing response
	IdleTimeout  time.Duration // Maximum time to wait for next request on keep-alive
}

// DefaultConfig returns an EngineConfig with sensible defaults.
func DefaultConfig() *EngineConfig {
	return &EngineConfig{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}
