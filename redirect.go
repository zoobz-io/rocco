package rocco

import "net/http"

// Redirect represents an HTTP redirect response.
// Return this from a handler to redirect the client instead of returning a body.
//
// Example:
//
//	handler := rocco.GET[rocco.NoBody, rocco.Redirect]("/old-path", func(req *rocco.Request[rocco.NoBody]) (rocco.Redirect, error) {
//	    return rocco.Redirect{URL: "/new-path"}, nil
//	})
type Redirect struct {
	URL    string // Target URL (required)
	Status int    // HTTP status code (default: 302 Found)
}

// DefaultRedirectStatus is used when Redirect.Status is 0.
const DefaultRedirectStatus = http.StatusFound
