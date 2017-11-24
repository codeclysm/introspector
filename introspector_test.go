package introspector_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/serjlee/introspector"
)

func Example() {
	j1 := introspector.JWT{
		Key: []byte("secret"),
	}

	j2 := introspector.JWT{
		Key: []byte("terces"),
	}

	collection := introspector.Collection{j1, j2}

	i, err := collection.Introspect("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJleGFtcGxlIiwiZXhwIjoxNDg2Mzk0Nzc5LCJqdGkiOiJmODVjNTM0Yy03M2JhLTQ3NjMtYTU4MS0yMzkxN2I5Nzc5MjUiLCJpYXQiOjE0ODYzODg3NzksImlzcyI6ImFwaS5leGFtcGxlLmNjIiwibmJmIjoxNDg2Mzg4Nzc5LCJzdWIiOiJ0ZXN0IiwidXNlciI6eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJpZCI6InRlc3QiLCJ1aWQiOiJ0ZXN0In19.mpRwH7Klc2P1X93N1f0Qf_W3RcNfxm97xwSLEpgSlIw")
	fmt.Println(err)
	fmt.Println(i.Subject)
	fmt.Println(i.Active)
	fmt.Println(i.ExpiresAt)
	// Output:
	// <nil>
	// test
	// false
	// 1486394779
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
