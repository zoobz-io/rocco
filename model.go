package rocco

import (
	"github.com/zoobz-io/openapi"
	"github.com/zoobz-io/sentinel"
)

// Model holds schema information for a type that should appear in the OpenAPI
// component schemas without being a handler input or output type.
type Model struct {
	meta   sentinel.Metadata
	name   string
	schema *openapi.Schema
}

// NewModel scans T with sentinel and returns a Model for schema registration.
func NewModel[T any]() *Model {
	return &Model{
		meta: sentinel.Scan[T](),
	}
}

// NewEnumModel creates a Model for a string enum type with explicit values.
func NewEnumModel[T ~string](name string, values ...T) *Model {
	enumValues := make([]any, len(values))
	for i, v := range values {
		enumValues[i] = string(v)
	}
	return &Model{
		name: name,
		schema: &openapi.Schema{
			Type: openapi.NewSchemaType("string"),
			Enum: enumValues,
		},
	}
}

// NewSchemaModel creates a Model from an arbitrary OpenAPI schema.
// This is an escape hatch for types that the typed constructors don't cover.
func NewSchemaModel(name string, schema *openapi.Schema) *Model {
	return &Model{
		name:   name,
		schema: schema,
	}
}
