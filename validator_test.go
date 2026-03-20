package rocco

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoobz-io/check"
)

func TestNewValidationError(t *testing.T) {
	fields := []ValidationFieldError{
		{Field: "name", Message: "is required"},
		{Field: "email", Message: "must be a valid email"},
	}

	err := NewValidationError(fields)
	if err == nil {
		t.Fatal("NewValidationError should return non-nil error")
	}

	// Should be extractable via errors.As
	var details ValidationDetails
	if !errors.As(err, &details) {
		t.Fatal("NewValidationError should return error extractable as ValidationDetails")
	}

	if len(details.Fields) != 2 {
		t.Errorf("expected 2 fields, got %d", len(details.Fields))
	}
	if details.Fields[0].Field != "name" {
		t.Errorf("expected field 'name', got %q", details.Fields[0].Field)
	}
	if details.Fields[1].Message != "must be a valid email" {
		t.Errorf("expected message 'must be a valid email', got %q", details.Fields[1].Message)
	}
}

func TestValidationDetails_Error(t *testing.T) {
	tests := []struct {
		name     string
		details  ValidationDetails
		expected string
	}{
		{
			name:     "empty fields",
			details:  ValidationDetails{Fields: nil},
			expected: "validation failed",
		},
		{
			name:     "single field",
			details:  ValidationDetails{Fields: []ValidationFieldError{{Field: "name"}}},
			expected: "validation failed: 1 field(s)",
		},
		{
			name: "multiple fields",
			details: ValidationDetails{Fields: []ValidationFieldError{
				{Field: "name"},
				{Field: "email"},
				{Field: "age"},
			}},
			expected: "validation failed: 3 field(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.details.Error()
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// validatableInput implements Validatable using check.
type validatableInput struct {
	Name string `json:"name"`
}

func (v validatableInput) Validate() error {
	return check.All(
		check.Required(v.Name, "name"),
	)
}

// nonValidatableInput does NOT implement Validatable.
type nonValidatableInput struct {
	Name string `json:"name"`
}

func TestHandler_InputValidatable_Detection(t *testing.T) {
	// Handler with validatable input should detect it
	handler := NewHandler[validatableInput, testOutput](
		"test", "POST", "/test",
		func(_ *Request[validatableInput]) (testOutput, error) {
			return testOutput{}, nil
		},
	)

	if !handler.inputValidatable {
		t.Error("expected inputValidatable to be true for validatableInput")
	}

	// Handler with non-validatable input should not detect it
	handler2 := NewHandler[nonValidatableInput, testOutput](
		"test", "POST", "/test",
		func(_ *Request[nonValidatableInput]) (testOutput, error) {
			return testOutput{}, nil
		},
	)

	if handler2.inputValidatable {
		t.Error("expected inputValidatable to be false for nonValidatableInput")
	}
}

func TestHandler_OutputValidatable_Detection(t *testing.T) {
	// Handler with validatable output should detect it
	handler := NewHandler[testInput, validatableInput](
		"test", "POST", "/test",
		func(_ *Request[testInput]) (validatableInput, error) {
			return validatableInput{}, nil
		},
	)

	if !handler.outputValidatable {
		t.Error("expected outputValidatable to be true for validatableInput")
	}

	// Handler with non-validatable output should not detect it
	handler2 := NewHandler[testInput, testOutput](
		"test", "POST", "/test",
		func(_ *Request[testInput]) (testOutput, error) {
			return testOutput{}, nil
		},
	)

	if handler2.outputValidatable {
		t.Error("expected outputValidatable to be false for testOutput")
	}
}

func TestStreamHandler_InputValidatable_Detection(t *testing.T) {
	// StreamHandler with validatable input should detect it
	handler := NewStreamHandler[validatableInput, streamEvent](
		"test", "POST", "/events",
		func(_ *Request[validatableInput], _ Stream[streamEvent]) error {
			return nil
		},
	)

	if !handler.inputValidatable {
		t.Error("expected inputValidatable to be true for validatableInput")
	}

	// StreamHandler with non-validatable input should not detect it
	handler2 := NewStreamHandler[nonValidatableInput, streamEvent](
		"test", "POST", "/events",
		func(_ *Request[nonValidatableInput], _ Stream[streamEvent]) error {
			return nil
		},
	)

	if handler2.inputValidatable {
		t.Error("expected inputValidatable to be false for nonValidatableInput")
	}
}

func TestCheckIntegration(t *testing.T) {
	// Test that check.Result is properly handled by writeValidationErrorResponse
	handler := NewHandler[failingValidatableInput, testOutput](
		"test", "POST", "/test",
		func(_ *Request[failingValidatableInput]) (testOutput, error) {
			return testOutput{Message: "ok"}, nil
		},
	)

	body := `{"email":"test@example.com","age":25}`
	req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
	w := httptest.NewRecorder()

	_, err := handler.Process(context.Background(), req, w)
	if err == nil {
		t.Fatal("expected validation error")
	}

	if w.Code != 422 {
		t.Errorf("expected status 422, got %d", w.Code)
	}

	// Verify response has field error with message
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	details, ok := resp["details"].(map[string]any)
	if !ok {
		t.Fatal("expected details in response")
	}

	fields, ok := details["fields"].([]any)
	if !ok || len(fields) == 0 {
		t.Fatal("expected fields in details")
	}

	firstField := fields[0].(map[string]any)
	if firstField["field"] != "test" {
		t.Errorf("expected field 'test', got %v", firstField["field"])
	}
	if firstField["message"] == nil || firstField["message"] == "" {
		t.Error("expected message to be set")
	}
}
