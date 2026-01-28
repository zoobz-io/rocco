package rocco

import "net/http"

// Redirect represents an HTTP redirect response.
// Return this from a handler to redirect the client instead of returning a body.
//
// Headers are written to the response before the redirect. Use this to set
// cookies or other headers on the redirect response (e.g., Set-Cookie for sessions).
//
// Example:
//
//	handler := rocco.GET[rocco.NoBody, rocco.Redirect]("/old-path", func(req *rocco.Request[rocco.NoBody]) (rocco.Redirect, error) {
//	    return rocco.Redirect{URL: "/new-path"}, nil
//	})
type Redirect struct {
	URL     string      // Target URL (required)
	Status  int         // HTTP status code (default: 302 Found)
	Headers http.Header // Additional response headers (e.g., Set-Cookie)
}

// DefaultRedirectStatus is used when Redirect.Status is 0.
const DefaultRedirectStatus = http.StatusFound
