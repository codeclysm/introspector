package auth0

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"net/http"

	"github.com/codeclysm/introspector/v2"
	"github.com/pkg/errors"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// Auth0 implements the introspection of tokens issued by https://auth0.com
type Auth0 struct {
	// Key is a public key or certificate used to verify the jwt tokens
	Key interface{}

	// ProfileURL is the url containing the profile urls. It's only used if the token has the scope profile
	ProfileURL string

	// Claims is a list of claims that a token must have to be valid. Leave Time empty to validate the token against the time of the call to Introspect()
	Claims jwt.Expected
}

// WithKeyPath reads the file at the provided path and decodes the key
func (a *Auth0) WithKeyPath(path string) error {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = a.WithKey(bytes)
	if err != nil {
		return err
	}
	return nil
}

// WithKey decodes the provided key
func (a *Auth0) WithKey(bytes []byte) error {
	block, _ := pem.Decode(bytes)
	if block != nil {
		bytes = block.Bytes
	}

	// Try to load SubjectPublicKeyInfo
	pub, err0 := x509.ParsePKIXPublicKey(bytes)
	if err0 == nil {
		a.Key = pub
		return nil
	}

	cert, err1 := x509.ParseCertificate(bytes)
	if err1 == nil {
		a.Key = cert.PublicKey
		return nil
	}

	return fmt.Errorf("parse error, got '%s' and '%s'", err0, err1)
}

// Introspect validates the jwt using the RS256 algorythm. If the token is valid and has the scope 'profile' it proceeds to query the profileURL to get additional info about the user
func (a Auth0) Introspect(token string) (*introspector.Introspection, error) {
	// Check signature
	t, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrap(err, "introspect: parse token")
	}

	header := t.Headers[0]
	if header.Algorithm != "RS256" {
		return nil, errors.New("introspect: invalid token algorithm")
	}

	// Build the introspection
	claims := jwt.Claims{}
	err = t.Claims(a.Key, &claims)
	if err != nil {
		return nil, errors.Wrap(err, "introspect: verify token")
	}

	// We use this to access scope easily
	claims2 := map[string]interface{}{}
	err = t.Claims(a.Key, &claims2)
	if err != nil {
		return nil, errors.Wrap(err, "introspect: verify token")
	}

	i := introspector.Introspection{
		Active:    false,
		Scope:     claims2["scope"].(string),
		ClientID:  "",
		Subject:   claims.Subject,
		ExpiresAt: claims.Expiry.Time().Unix(),
		IssuedAt:  claims.IssuedAt.Time().Unix(),
		NotBefore: 0,
		Username:  "",
		Audience:  strings.Join(claims.Audience, " "),
		Issuer:    claims.Issuer,
		Extra:     map[string]interface{}{},
	}

	// Check validity
	expected := a.Claims
	time0 := time.Time{}
	if expected.Time == time0 {
		expected.Time = time.Now()
	}

	err = claims.Validate(expected)
	if err != nil {
		return &i, errors.Wrap(err, "introspect: validate claims")
	}

	i.Active = true

	// Get profile
	scopes := strings.Split(i.Scope, " ")
	if a.ProfileURL != "" && in(scopes, "profile") {
		profile, err := a.getProfile(token)
		if err != nil {
			return &i, errors.Wrap(err, "introspect: get profile")
		}

		for key, value := range profile {
			if key == "sub" {
				i.Subject = value
			} else if key == "nickname" {
				i.Username = value
			} else {
				i.Extra[key] = value
			}
		}
	}

	return &i, nil
}

func (a Auth0) getProfile(token string) (map[string]string, error) {
	req, err := http.NewRequest("GET", "https://matteosuppo.eu.auth0.com/userinfo", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+token)

	client := http.Client{
		Timeout: 5 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	log.Println(string(body))

	data := map[string]string{}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func in(slice []string, el string) bool {
	for key := range slice {
		if slice[key] == el {
			return true
		}
	}
	return false
}
