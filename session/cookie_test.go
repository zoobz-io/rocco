package session

import (
	"net/http"
	"testing"
)

func TestSignVerify_RoundTrip(t *testing.T) {
	key := []byte("test-secret-key")
	id := "session-abc-123"

	signed := signValue(id, key)
	got, ok := verifyValue(signed, key)
	if !ok {
		t.Fatal("expected valid signature")
	}
	if got != id {
		t.Errorf("expected id %q, got %q", id, got)
	}
}

func TestVerifyValue_TamperedSignature(t *testing.T) {
	key := []byte("test-secret-key")
	signed := signValue("session-123", key)

	// Tamper with the signature.
	tampered := signed[:len(signed)-1] + "x"
	_, ok := verifyValue(tampered, key)
	if ok {
		t.Error("expected tampered signature to fail")
	}
}

func TestVerifyValue_WrongKey(t *testing.T) {
	signed := signValue("session-123", []byte("key-one"))
	_, ok := verifyValue(signed, []byte("key-two"))
	if ok {
		t.Error("expected wrong key to fail")
	}
}

func TestVerifyValue_MalformedInput(t *testing.T) {
	key := []byte("key")

	cases := []string{
		"",
		"no-dot",
		".leading-dot",
	}
	for _, input := range cases {
		_, ok := verifyValue(input, key)
		if ok {
			t.Errorf("expected %q to fail verification", input)
		}
	}
}

func TestNewSetCookie(t *testing.T) {
	cfg := CookieConfig{
		Name:     "sid",
		MaxAge:   3600,
		Path:     "/",
		Domain:   "example.com",
		Secure:   true,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
		SignKey:  []byte("key"),
	}

	cookie := newSetCookie(cfg, "session-123")

	if cookie.Name != "sid" {
		t.Errorf("expected name 'sid', got %q", cookie.Name)
	}
	if cookie.MaxAge != 3600 {
		t.Errorf("expected MaxAge 3600, got %d", cookie.MaxAge)
	}
	if cookie.Path != "/" {
		t.Errorf("expected path '/', got %q", cookie.Path)
	}
	if cookie.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", cookie.Domain)
	}
	if !cookie.Secure {
		t.Error("expected Secure")
	}
	if !cookie.HttpOnly {
		t.Error("expected HTTPOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSiteLax, got %d", cookie.SameSite)
	}

	// Value should be signed.
	id, ok := verifyValue(cookie.Value, []byte("key"))
	if !ok {
		t.Fatal("expected valid signed value")
	}
	if id != "session-123" {
		t.Errorf("expected session ID 'session-123', got %q", id)
	}
}

func TestNewClearCookie(t *testing.T) {
	cfg := CookieConfig{
		Name:    "sid",
		Path:    "/",
		SignKey: []byte("key"),
	}

	cookie := newClearCookie(cfg)

	if cookie.Name != "sid" {
		t.Errorf("expected name 'sid', got %q", cookie.Name)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", cookie.MaxAge)
	}
	if cookie.Value != "" {
		t.Errorf("expected empty value, got %q", cookie.Value)
	}
}

func TestCookieConfig_Defaults(t *testing.T) {
	cfg := CookieConfig{SignKey: []byte("key")}
	cfg.defaults()

	if cfg.Name != "sid" {
		t.Errorf("expected default name 'sid', got %q", cfg.Name)
	}
	if cfg.MaxAge != 86400 {
		t.Errorf("expected default MaxAge 86400, got %d", cfg.MaxAge)
	}
	if cfg.Path != "/" {
		t.Errorf("expected default path '/', got %q", cfg.Path)
	}
	if cfg.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected default SameSiteLax, got %d", cfg.SameSite)
	}
}
