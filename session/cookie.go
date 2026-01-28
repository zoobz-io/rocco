package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

const defaultCookieName = "sid"

// CookieConfig controls session cookie behavior.
type CookieConfig struct {
	Name     string        // Cookie name (default: "sid")
	MaxAge   int           // Max age in seconds (default: 86400)
	Path     string        // Cookie path (default: "/")
	Domain   string        // Cookie domain
	Secure   bool          // HTTPS only (default: true)
	HTTPOnly bool          // No JavaScript access (default: true)
	SameSite http.SameSite // SameSite policy (default: Lax)
	SignKey  []byte        // HMAC-SHA256 signing key (required)
}

func (c *CookieConfig) defaults() {
	if c.Name == "" {
		c.Name = defaultCookieName
	}
	if c.MaxAge == 0 {
		c.MaxAge = 86400
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteLaxMode
	}
	if !c.Secure {
		c.Secure = true
	}
	if !c.HTTPOnly {
		c.HTTPOnly = true
	}
}

// signValue returns "id.hex(hmac-sha256(id, key))".
func signValue(id string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	sig := hex.EncodeToString(mac.Sum(nil))
	return id + "." + sig
}

// verifyValue parses "id.signature", verifies the HMAC, and returns the id.
// Returns the id and true if valid, or empty string and false if not.
func verifyValue(value string, key []byte) (string, bool) {
	idx := strings.LastIndex(value, ".")
	if idx < 1 {
		return "", false
	}

	id := value[:idx]
	sig := value[idx+1:]

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", false
	}

	return id, true
}

// newSetCookie builds an http.Cookie for setting a session.
func newSetCookie(cfg CookieConfig, sessionID string) *http.Cookie {
	return &http.Cookie{
		Name:     cfg.Name,
		Value:    signValue(sessionID, cfg.SignKey),
		MaxAge:   cfg.MaxAge,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
	}
}

// newClearCookie builds an expired cookie to delete the session.
func newClearCookie(cfg CookieConfig) *http.Cookie {
	return &http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		MaxAge:   -1,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
	}
}
