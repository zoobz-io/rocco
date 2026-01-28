package rocco

import "encoding/json"

// ContentTypeJSON is the MIME type for JSON content.
const ContentTypeJSON = "application/json"

// Codec defines the interface for request/response serialization.
// Implementations handle marshaling and unmarshaling of handler payloads.
type Codec interface {
	// ContentType returns the MIME type for this codec (e.g., "application/json").
	ContentType() string
	// Marshal encodes a value to bytes.
	Marshal(v any) ([]byte, error)
	// Unmarshal decodes bytes into a value.
	Unmarshal(data []byte, v any) error
}

// JSONCodec implements Codec using encoding/json.
type JSONCodec struct{}

// ContentType returns "application/json".
func (JSONCodec) ContentType() string {
	return ContentTypeJSON
}

// Marshal encodes v as JSON.
func (JSONCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal decodes JSON data into v.
func (JSONCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// defaultCodec is the package-level default codec.
var defaultCodec Codec = JSONCodec{}

// codecApplier is implemented by handlers that support engine-level codec defaults.
type codecApplier interface {
	applyDefaultCodec(Codec)
}
