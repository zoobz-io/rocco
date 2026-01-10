package rocco

// Validator defines the interface for request/response validation.
// Generic over input (In) and output (Out) types to provide type-safe validation.
type Validator[In, Out any] interface {
	// ValidateInput validates the request input before processing.
	ValidateInput(In) error
	// ValidateOutput validates the response output before sending.
	ValidateOutput(Out) error
}

// NoOpValidator is a validator that accepts all input and output.
type NoOpValidator[In, Out any] struct{}

// ValidateInput always returns nil, accepting any input.
func (NoOpValidator[In, Out]) ValidateInput(In) error { return nil }

// ValidateOutput always returns nil, accepting any output.
func (NoOpValidator[In, Out]) ValidateOutput(Out) error { return nil }
