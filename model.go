package rocco

import "github.com/zoobz-io/sentinel"

// Model holds sentinel metadata for a type that should appear in the OpenAPI
// component schemas without being a handler input or output type.
type Model struct {
	meta sentinel.Metadata
}

// NewModel scans T with sentinel and returns a Model for schema registration.
func NewModel[T any]() *Model {
	return &Model{
		meta: sentinel.Scan[T](),
	}
}
