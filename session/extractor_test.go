package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractor_ValidSession(t *testing.T) {
	store := NewMemoryStore()
	cookie := CookieConfig{SignKey: []byte("test-key")}
	cookie.defaults()

	// Create a session.
	data := Data{UserID: "user-1", Email: "user@example.com", Roles: []string{"admin"}}
	store.Create(context.Background(), "sess-1", data)

	extractor := Extractor(store, cookie)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "sid",
		Value: signValue("sess-1", cookie.SignKey),
	})

	identity, err := extractor(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.ID() != "user-1" {
		t.Errorf("expected ID 'user-1', got %q", identity.ID())
	}
	if identity.Email() != "user@example.com" {
		t.Errorf("expected Email 'user@example.com', got %q", identity.Email())
	}
	if !identity.HasRole("admin") {
		t.Error("expected HasRole('admin') to be true")
	}
}

func TestExtractor_MissingCookie(t *testing.T) {
	store := NewMemoryStore()
	cookie := CookieConfig{SignKey: []byte("test-key")}

	extractor := Extractor(store, cookie)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	_, err := extractor(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing cookie")
	}
}

func TestExtractor_InvalidSignature(t *testing.T) {
	store := NewMemoryStore()
	cookie := CookieConfig{SignKey: []byte("test-key")}
	cookie.defaults()

	extractor := Extractor(store, cookie)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "sess-1.invalidsignature"})

	_, err := extractor(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestExtractor_DeletedSession(t *testing.T) {
	store := NewMemoryStore()
	cookie := CookieConfig{SignKey: []byte("test-key")}
	cookie.defaults()

	// Create and delete a session.
	store.Create(context.Background(), "sess-1", Data{UserID: "user-1"})
	store.Delete(context.Background(), "sess-1")

	extractor := Extractor(store, cookie)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "sid",
		Value: signValue("sess-1", cookie.SignKey),
	})

	_, err := extractor(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for deleted session")
	}
}
