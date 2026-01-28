package rocco

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirect_DefaultStatus(t *testing.T) {
	handler := NewHandler[NoBody, Redirect](
		"redirect-test",
		"GET",
		"/redirect",
		func(_ *Request[NoBody]) (Redirect, error) {
			return Redirect{URL: "https://example.com"}, nil
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/redirect", nil)
	w := httptest.NewRecorder()

	status, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, status)
	}
	if w.Code != http.StatusFound {
		t.Errorf("expected response code %d, got %d", http.StatusFound, w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://example.com" {
		t.Errorf("expected Location 'https://example.com', got %q", loc)
	}
	if w.Body.Len() != 0 {
		t.Errorf("expected empty body, got %d bytes", w.Body.Len())
	}
}

func TestRedirect_ExplicitStatus(t *testing.T) {
	testCases := []struct {
		name   string
		status int
	}{
		{"MovedPermanently", http.StatusMovedPermanently},
		{"Found", http.StatusFound},
		{"SeeOther", http.StatusSeeOther},
		{"TemporaryRedirect", http.StatusTemporaryRedirect},
		{"PermanentRedirect", http.StatusPermanentRedirect},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewHandler[NoBody, Redirect](
				"redirect-test",
				"GET",
				"/redirect",
				func(_ *Request[NoBody]) (Redirect, error) {
					return Redirect{URL: "/target", Status: tc.status}, nil
				},
			)

			req := httptest.NewRequest(http.MethodGet, "/redirect", nil)
			w := httptest.NewRecorder()

			status, err := handler.Process(context.Background(), req, w)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if status != tc.status {
				t.Errorf("expected status %d, got %d", tc.status, status)
			}
			if w.Code != tc.status {
				t.Errorf("expected response code %d, got %d", tc.status, w.Code)
			}
		})
	}
}

func TestRedirect_WithResponseHeaders(t *testing.T) {
	handler := NewHandler[NoBody, Redirect](
		"redirect-test",
		"GET",
		"/redirect",
		func(_ *Request[NoBody]) (Redirect, error) {
			return Redirect{URL: "/target"}, nil
		},
	).WithResponseHeaders(map[string]string{
		"Set-Cookie": "session=abc123; Path=/",
		"X-Custom":   "value",
	})

	req := httptest.NewRequest(http.MethodGet, "/redirect", nil)
	w := httptest.NewRecorder()

	_, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cookie := w.Header().Get("Set-Cookie"); cookie != "session=abc123; Path=/" {
		t.Errorf("expected Set-Cookie header, got %q", cookie)
	}
	if custom := w.Header().Get("X-Custom"); custom != "value" {
		t.Errorf("expected X-Custom header 'value', got %q", custom)
	}
	// Content-Type should NOT be set for redirects
	if ct := w.Header().Get("Content-Type"); ct != "" {
		t.Errorf("expected no Content-Type header, got %q", ct)
	}
}

func TestRedirect_WithQueryParameters(t *testing.T) {
	handler := NewHandler[NoBody, Redirect](
		"redirect-test",
		"GET",
		"/redirect",
		func(_ *Request[NoBody]) (Redirect, error) {
			return Redirect{URL: "/target?foo=bar&baz=qux"}, nil
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/redirect", nil)
	w := httptest.NewRecorder()

	_, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if loc := w.Header().Get("Location"); loc != "/target?foo=bar&baz=qux" {
		t.Errorf("expected Location with query params, got %q", loc)
	}
}

func TestRedirect_RelativeURL(t *testing.T) {
	handler := NewHandler[NoBody, Redirect](
		"redirect-test",
		"GET",
		"/redirect",
		func(_ *Request[NoBody]) (Redirect, error) {
			return Redirect{URL: "../other/path"}, nil
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/redirect", nil)
	w := httptest.NewRecorder()

	_, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if loc := w.Header().Get("Location"); loc != "../other/path" {
		t.Errorf("expected relative Location, got %q", loc)
	}
}

func TestRedirect_EmptyURL(t *testing.T) {
	handler := NewHandler[NoBody, Redirect](
		"redirect-test",
		"GET",
		"/redirect",
		func(_ *Request[NoBody]) (Redirect, error) {
			return Redirect{URL: ""}, nil // Empty URL
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/redirect", nil)
	w := httptest.NewRecorder()

	status, _ := handler.Process(context.Background(), req, w)

	if status != http.StatusInternalServerError {
		t.Errorf("expected status %d for empty URL, got %d", http.StatusInternalServerError, status)
	}

	// Should not set Location header
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("expected no Location header for empty URL, got %q", loc)
	}
}

func TestRedirect_ContentTypeNotForwarded(t *testing.T) {
	handler := NewHandler[NoBody, Redirect](
		"redirect-test",
		"GET",
		"/redirect",
		func(_ *Request[NoBody]) (Redirect, error) {
			return Redirect{URL: "/target"}, nil
		},
	).WithResponseHeaders(map[string]string{
		"Content-Type": "application/json", // Should be ignored
		"Set-Cookie":   "session=abc",      // Should be forwarded
	})

	req := httptest.NewRequest(http.MethodGet, "/redirect", nil)
	w := httptest.NewRecorder()

	_, err := handler.Process(context.Background(), req, w)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Content-Type should NOT be set for redirects
	if ct := w.Header().Get("Content-Type"); ct != "" {
		t.Errorf("expected Content-Type to be filtered out, got %q", ct)
	}

	// Other headers should still be forwarded
	if cookie := w.Header().Get("Set-Cookie"); cookie != "session=abc" {
		t.Errorf("expected Set-Cookie header, got %q", cookie)
	}
}
