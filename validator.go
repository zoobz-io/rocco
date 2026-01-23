package rocco

// Validatable is implemented by types that can validate themselves.
// Input and output structs can implement this interface to opt-in to validation.
type Validatable interface {
	Validate() error
}
