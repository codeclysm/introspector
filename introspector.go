// Package introspector abstracts the process of gaining info from an
// authentication token.
// In a perfect world you'll have to handle authentication only once, and only from
// a perfectly standard Oauthx solution that you can plug in every project.
// Reality is different. In reality you have to handle a messy authentication system with oauth2, along with some hardcoded api keys that no one knows who put there, and on top of it all you have to introduce a brand new (but still messy) authentication system.
// apps.
// Introspector introduces the concept of collections. It returns info from the first system that understands what you're talking about.
package introspector

import (
	"errors"
	"time"
)

// Introspection contains an access token's session data as specified by IETF RFC 7662, see:
// https://tools.ietf.org/html/rfc7662
type Introspection struct {
	// Active is a boolean indicator of whether or not the presented token
	// is currently active.  The specifics of a token's "active" state
	// will vary depending on the implementation of the authorization
	// server and the information it keeps about its tokens, but a "true"
	// value return for the "active" property will generally indicate
	// that a given token has been issued by this authorization server,
	// has not been revoked by the resource owner, and is within its
	// given time window of validity (e.g., after its issuance time and
	// before its expiration time).
	Active bool `json:"active"`

	// Scope is a JSON string containing a space-separated list of
	// scopes associated with this token.
	Scope string `json:"scope,omitempty"`

	// ClientID is aclient identifier for the OAuth 2.0 client that
	// requested this token.
	ClientID string `json:"client_id,omitempty"`

	// Subject of the token, as defined in JWT [RFC7519].
	// Usually a machine-readable identifier of the resource owner who
	// authorized this token.
	Subject string `json:"sub,omitempty"`

	// Expires at is an integer timestamp, measured in the number of seconds
	// since January 1 1970 UTC, indicating when this token will expire.
	ExpiresAt int64 `json:"exp,omitempty"`

	// Issued at is an integer timestamp, measured in the number of seconds
	// since January 1 1970 UTC, indicating when this token was
	// originally issued.
	IssuedAt int64 `json:"iat,omitempty"`

	// NotBefore is an integer timestamp, measured in the number of seconds
	// since January 1 1970 UTC, indicating when this token is not to be
	// used before.
	NotBefore int64 `json:"nbf,omitempty"`

	// Username is a human-readable identifier for the resource owner who
	// authorized this token.
	Username string `json:"username,omitempty"`

	// Audience is a service-specific string identifier or list of string
	// identifiers representing the intended audience for this token.
	Audience string `json:"aud,omitempty"`

	// Issuer is a string representing the issuer of this token
	Issuer string `json:"iss,omitempty"`

	// Extra is arbitrary data set by the session.
	Extra map[string]interface{} `json:"ext,omitempty"`
}

var ErrIssuedFuture = errors.New("token issued in the future")
var ErrNotYetValid = errors.New("token not yet valid")
var ErrExpired = errors.New("token expired")
var ErrNotActive = errors.New("token not active")

// Valid checks the validity of the introspection, aka whether its IssuedAt, NotBefore, ExpiresAt fields make sense
func (i Introspection) Valid() error {
	now := time.Now()

	if time.Unix(i.IssuedAt, 0).After(now) {
		return ErrIssuedFuture
	}

	if time.Unix(i.NotBefore, 0).After(now) {
		return ErrNotYetValid
	}

	if time.Unix(i.ExpiresAt, 0).Before(now) {
		return ErrExpired
	}

	if !i.Active {
		return ErrNotActive
	}
	return nil
}

// Introspector is an abstraction that allows you to retrieve the authentication info from a context, and to validate them
type Introspector interface {
	// Introspect returns an introspection of the token
	// It returns an empty Introspection plus an error if the token is malformed or signed with the wrong key.
	// It must not return an error if the token is simply expired, or not valid
	Introspect(token string) (Introspection, error)
}
