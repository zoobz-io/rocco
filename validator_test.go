package rocco

import (
	"errors"
	"testing"
)

func TestNoOpValidator_ValidateInput(t *testing.T) {
	v := NoOpValidator[testInput, testOutput]{}

	err := v.ValidateInput(testInput{Name: "test", Count: 5})
	if err != nil {
		t.Errorf("NoOpValidator.ValidateInput should return nil, got %v", err)
	}
}

func TestNoOpValidator_ValidateOutput(t *testing.T) {
	v := NoOpValidator[testInput, testOutput]{}

	err := v.ValidateOutput(testOutput{Message: "test"})
	if err != nil {
		t.Errorf("NoOpValidator.ValidateOutput should return nil, got %v", err)
	}
}

func TestNewValidationError(t *testing.T) {
	fields := []ValidationFieldError{
		{Field: "name", Tag: "required", Value: ""},
		{Field: "email", Tag: "email", Value: "invalid"},
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
	if details.Fields[1].Tag != "email" {
		t.Errorf("expected tag 'email', got %q", details.Fields[1].Tag)
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

func TestHandler_WithValidator(t *testing.T) {
	called := false

	handler := NewHandler[testInput, testOutput](
		"test",
		"POST",
		"/test",
		func(_ *Request[testInput]) (testOutput, error) {
			return testOutput{Message: "ok"}, nil
		},
	)

	// Default should be NoOpValidator
	if handler.validator == nil {
		t.Fatal("handler.validator should not be nil")
	}

	// Create a custom validator
	customValidator := &customTestValidator[testInput, testOutput]{
		inputFn: func(in testInput) error {
			called = true
			return nil
		},
	}

	handler.WithValidator(customValidator)

	// Verify WithValidator returns the handler for chaining
	if handler.validator != customValidator {
		t.Error("WithValidator should set the validator")
	}

	// Verify the validator is actually used
	handler.validator.ValidateInput(testInput{})
	if !called {
		t.Error("custom validator should have been called")
	}
}

func TestStreamHandler_WithValidator(t *testing.T) {
	called := false

	handler := NewStreamHandler[testInput, streamEvent](
		"test-stream",
		"POST",
		"/events",
		func(_ *Request[testInput], _ Stream[streamEvent]) error {
			return nil
		},
	)

	// Default should be NoOpValidator
	if handler.validator == nil {
		t.Fatal("handler.validator should not be nil")
	}

	customValidator := &customTestValidator[testInput, streamEvent]{
		inputFn: func(in testInput) error {
			called = true
			return nil
		},
	}

	handler.WithValidator(customValidator)

	if handler.validator != customValidator {
		t.Error("WithValidator should set the validator")
	}

	handler.validator.ValidateInput(testInput{})
	if !called {
		t.Error("custom validator should have been called")
	}
}

// customTestValidator is a configurable validator for testing.
type customTestValidator[In, Out any] struct {
	inputFn  func(In) error
	outputFn func(Out) error
}

func (v *customTestValidator[In, Out]) ValidateInput(in In) error {
	if v.inputFn != nil {
		return v.inputFn(in)
	}
	return nil
}

func (v *customTestValidator[In, Out]) ValidateOutput(out Out) error {
	if v.outputFn != nil {
		return v.outputFn(out)
	}
	return nil
}
