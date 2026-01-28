package rocco

import (
	"testing"
)

func TestContentTypeJSON(t *testing.T) {
	if ContentTypeJSON != "application/json" {
		t.Errorf("ContentTypeJSON = %q, want %q", ContentTypeJSON, "application/json")
	}
}

func TestJSONCodec_ContentType(t *testing.T) {
	codec := JSONCodec{}
	if got := codec.ContentType(); got != ContentTypeJSON {
		t.Errorf("ContentType() = %q, want %q", got, ContentTypeJSON)
	}
}

func TestJSONCodec_Marshal(t *testing.T) {
	codec := JSONCodec{}

	tests := []struct {
		name    string
		input   any
		want    string
		wantErr bool
	}{
		{
			name:  "struct",
			input: struct{ Name string }{Name: "test"},
			want:  `{"Name":"test"}`,
		},
		{
			name:  "map",
			input: map[string]int{"count": 42},
			want:  `{"count":42}`,
		},
		{
			name:  "slice",
			input: []string{"a", "b"},
			want:  `["a","b"]`,
		},
		{
			name:  "nil",
			input: nil,
			want:  "null",
		},
		{
			name:    "channel",
			input:   make(chan int),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := codec.Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != tt.want {
				t.Errorf("Marshal() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestJSONCodec_Unmarshal(t *testing.T) {
	codec := JSONCodec{}

	t.Run("struct", func(t *testing.T) {
		var result struct{ Name string }
		err := codec.Unmarshal([]byte(`{"Name":"test"}`), &result)
		if err != nil {
			t.Errorf("Unmarshal() error = %v", err)
			return
		}
		if result.Name != "test" {
			t.Errorf("Unmarshal() Name = %q, want %q", result.Name, "test")
		}
	})

	t.Run("map", func(t *testing.T) {
		var result map[string]int
		err := codec.Unmarshal([]byte(`{"count":42}`), &result)
		if err != nil {
			t.Errorf("Unmarshal() error = %v", err)
			return
		}
		if result["count"] != 42 {
			t.Errorf("Unmarshal() count = %d, want %d", result["count"], 42)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		var result struct{}
		err := codec.Unmarshal([]byte(`{invalid}`), &result)
		if err == nil {
			t.Error("Unmarshal() expected error for invalid JSON")
		}
	})
}

func TestDefaultCodec(t *testing.T) {
	if defaultCodec == nil {
		t.Fatal("defaultCodec is nil")
	}
	if defaultCodec.ContentType() != ContentTypeJSON {
		t.Errorf("defaultCodec.ContentType() = %q, want %q", defaultCodec.ContentType(), ContentTypeJSON)
	}
}
