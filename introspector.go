// Package introspector abstracts the process of gaining info from an
// authentication token.
// In a perfect world you'll have to handle authentication only once, and only from
// a perfectly standard Oauthx solution that you can plug in every project.
// Reality is different. In reality you have to handle a messy authentication system with oauth2, along with some hardcoded api keys that no one knows who put there, and on top of it all you have to introduce a brand new (but still messy) authentication system.
// apps.
// Introspector introduces the concept of collections. It returns info from the first system that understands what you're talking about.
package introspector

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

// Introspector is an abstraction that allows you to retrieve the authentication info from a context
type Introspector interface {
	Introspect(token string) (*Introspection, error)
}

// Permission is a request of permission that can be accepted or denied
type Permission struct {
	// Resource is the resource that access is requested to.
	Resource string `json:"resource"`

	// Action is the action that is requested on the resource.
	Action string `json:"action"`

	// Context is the permission's environmental context.
	Context map[string]string `json:"context"`
}
