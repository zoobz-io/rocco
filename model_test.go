package rocco

import (
	"testing"

	"github.com/zoobz-io/openapi"
)

type testModelType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func TestNewModel(t *testing.T) {
	model := NewModel[testModelType]()

	if model.meta.TypeName != "testModelType" {
		t.Errorf("expected type name 'testModelType', got %q", model.meta.TypeName)
	}
	if len(model.meta.Fields) != 2 {
		t.Errorf("expected 2 fields, got %d", len(model.meta.Fields))
	}
}

func TestWithModels(t *testing.T) {
	engine := newTestEngine()

	engine.WithModels(
		NewModel[testModelType](),
	)

	if len(engine.models) != 1 {
		t.Fatalf("expected 1 model, got %d", len(engine.models))
	}
	if engine.models[0].meta.TypeName != "testModelType" {
		t.Errorf("expected model type 'testModelType', got %q", engine.models[0].meta.TypeName)
	}
}

func TestWithModels_AppearsInOpenAPI(t *testing.T) {
	engine := newTestEngine()

	engine.WithModels(
		NewModel[testModelType](),
	)

	spec := engine.GenerateOpenAPI(nil)

	schema, exists := spec.Components.Schemas["testModelType"]
	if !exists {
		t.Fatal("expected testModelType in component schemas")
	}
	if schema.Type == nil || schema.Type.String() != "object" {
		t.Errorf("expected object type, got %v", schema.Type)
	}
	if _, exists := schema.Properties["id"]; !exists {
		t.Error("expected 'id' property")
	}
	if _, exists := schema.Properties["name"]; !exists {
		t.Error("expected 'name' property")
	}
}

type ProviderType string

const (
	ProviderGoogleDrive ProviderType = "google_drive"
	ProviderOneDrive    ProviderType = "onedrive"
	ProviderDropbox     ProviderType = "dropbox"
)

func TestNewEnumModel(t *testing.T) {
	model := NewEnumModel("ProviderType", ProviderGoogleDrive, ProviderOneDrive, ProviderDropbox)

	if model.name != "ProviderType" {
		t.Errorf("expected name 'ProviderType', got %q", model.name)
	}
	if model.schema == nil {
		t.Fatal("expected schema to be set")
	}
	if model.schema.Type == nil || model.schema.Type.String() != "string" {
		t.Errorf("expected string type, got %v", model.schema.Type)
	}
	if len(model.schema.Enum) != 3 {
		t.Fatalf("expected 3 enum values, got %d", len(model.schema.Enum))
	}
	expected := []string{"google_drive", "onedrive", "dropbox"}
	for i, v := range model.schema.Enum {
		if v != expected[i] {
			t.Errorf("enum[%d]: expected %q, got %v", i, expected[i], v)
		}
	}
}

func TestNewEnumModel_AppearsInOpenAPI(t *testing.T) {
	engine := newTestEngine()

	engine.WithModels(
		NewEnumModel("ProviderType", ProviderGoogleDrive, ProviderOneDrive, ProviderDropbox),
	)

	spec := engine.GenerateOpenAPI(nil)

	schema, exists := spec.Components.Schemas["ProviderType"]
	if !exists {
		t.Fatal("expected ProviderType in component schemas")
	}
	if schema.Type == nil || schema.Type.String() != "string" {
		t.Errorf("expected string type, got %v", schema.Type)
	}
	if len(schema.Enum) != 3 {
		t.Errorf("expected 3 enum values, got %d", len(schema.Enum))
	}
}

func TestNewSchemaModel(t *testing.T) {
	schema := &openapi.Schema{
		Type: openapi.NewSchemaType("object"),
		AdditionalProperties: &openapi.Schema{
			Ref: "#/components/schemas/FacetCount",
		},
	}
	model := NewSchemaModel("SearchFacets", schema)

	if model.name != "SearchFacets" {
		t.Errorf("expected name 'SearchFacets', got %q", model.name)
	}
	if model.schema != schema {
		t.Error("expected schema to be the same pointer")
	}
}

func TestNewSchemaModel_AppearsInOpenAPI(t *testing.T) {
	engine := newTestEngine()

	engine.WithModels(
		NewSchemaModel("SearchFacets", &openapi.Schema{
			Type: openapi.NewSchemaType("object"),
			AdditionalProperties: &openapi.Schema{
				Ref: "#/components/schemas/FacetCount",
			},
		}),
	)

	spec := engine.GenerateOpenAPI(nil)

	schema, exists := spec.Components.Schemas["SearchFacets"]
	if !exists {
		t.Fatal("expected SearchFacets in component schemas")
	}
	if schema.Type == nil || schema.Type.String() != "object" {
		t.Errorf("expected object type, got %v", schema.Type)
	}
}
