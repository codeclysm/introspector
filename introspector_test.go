package introspector_test

import (
	"log"
	"net/http"
	"reflect"
	"testing"

	"github.com/codeclysm/introspector"
)

func Example() {
	j1 := introspector.JWT{
		Key: []byte("key"),
	}

	j2 := introspector.JWT{
		Key: []byte("other key"),
	}

	o := introspector.Oauth{
		Endpoint: "https://example.com/auth/token",
		Client:   &http.Client{},
	}

	collection := introspector.Collection{j1, j2, o}

	i, err := collection.Introspect("token")
	log.Println(i, err)
}

func equal(t *testing.T, a, b *introspector.Introspection) {
	if a == nil {
		t.Fatalf("the first introspection is nil")
		return
	}

	if b == nil {
		t.Fatalf("the second introspection is nil")
		return
	}

	if a.Active != b.Active {
		t.Errorf(".Active differs: (first: %v) (second: %v)", a.Active, b.Active)
	}
	if a.Scope != b.Scope {
		t.Errorf(".Scope differs: (first: %v) (second: %v)", a.Scope, b.Scope)
	}
	if a.ClientID != b.ClientID {
		t.Errorf(".ClientID differs: (first: %v) (second: %v)", a.ClientID, b.ClientID)
	}
	if a.Subject != b.Subject {
		t.Errorf(".Subject differs: (first: %v) (second: %v)", a.Subject, b.Subject)
	}
	if a.ExpiresAt != b.ExpiresAt {
		t.Errorf(".ExpiresAt differs: (first: %v) (second: %v)", a.ExpiresAt, b.ExpiresAt)
	}
	if a.IssuedAt != b.IssuedAt {
		t.Errorf(".IssuedAt differs: (first: %v) (second: %v)", a.IssuedAt, b.IssuedAt)
	}
	if a.NotBefore != b.NotBefore {
		t.Errorf(".NotBefore differs: (first: %v) (second: %v)", a.NotBefore, b.NotBefore)
	}
	if a.Username != b.Username {
		t.Errorf(".Username differs: (first: %v) (second: %v)", a.Username, b.Username)
	}
	if a.Audience != b.Audience {
		t.Errorf(".Audience differs: (first: %v) (second: %v)", a.Audience, b.Audience)
	}
	if a.Issuer != b.Issuer {
		t.Errorf(".Issuer differs: (first: %v) (second: %v)", a.Issuer, b.Issuer)
	}
	if !reflect.DeepEqual(a.Extra, b.Extra) {
		t.Errorf(".Extra differs: (first: %#v) (second: %v)", a.Extra, b.Extra)
	}
}
