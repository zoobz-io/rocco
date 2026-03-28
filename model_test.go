package rocco

import (
	"testing"
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
