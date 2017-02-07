use 'godoc cmd/github.com/codeclysm/introspector' for documentation on the github.com/codeclysm/introspector command 

Package introspector
=====================

    import "github.com/codeclysm/introspector"

Package introspector abstracts the process of gaining info from an
authentication token.

In a perfect world you'll have to handle authentication only once, and only from
a perfectly standard Oauthx solution that you can plug in every project.

Reality is different. In reality we had to change our authenticaton system from
a messy cas+sso+oauth2+jwt system to a messy oauth2 system, leaving apps able to
understand token and authentication headers coming from very different auth
apps.

```go
Example:
	j1 := introspector.JWT{
	    Key: []byte("key"),
	}
	
	j2 := introspector.JWT{
	    Key: []byte("other key"),
	}
	
	endpoint, _ := url.Parse("/auth/token")
	
	o := introspector.Oauth{
	    Endpoint: endpoint,
	    Client:   &http.Client{},
	}
	
	collection := introspector.Collection{j1, j2, o}
	
	i, err := collection.Introspect("token")
	log.Println(i, err)


```

Types
-----


```go
type Collection []Introspector
```
Collection queries every introspector returning the result of the first one that
succeeds or a collection of errors


```go
func (c Collection) Introspect(token string, scopes ...string) (*Introspection, error)
```


```go
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
```
Introspection contains an access token's session data as specified by IETF RFC
7662, see: https://tools.ietf.org/html/rfc7662


```go
type Introspector interface {
    Introspect(token string, scopes ...string) (*Introspection, error)
}
```
Introspector is an abstraction that allows you to retrieve the info of a token


```go
type JWT struct {
    // Key is the signing key for the JWT token
    Key []byte
}
```
JWT extracts info from a token if it manages to decrypt it


```go
func (j JWT) Introspect(token string, scopes ...string) (*Introspection, error)
```
Introspect extracts the info from the standard jwt claims, which you can read
here: https://tools.ietf.org/html/rfc7519#section-4.1 Scope is not used, and the
Active flag is set to the Valid value of the token. Extra fields, such as jit,
will end up in Extra


```go
type Oauth struct {
    // Endpoint is the url to query
    Endpoint *url.URL

    // Client is the http client which will make the request
    Client *http.Client
}
```
Oauth queries an endpoint to obtain info about the given token


```go
func (o Oauth) Introspect(token string, scopes ...string) (*Introspection, error)
```


