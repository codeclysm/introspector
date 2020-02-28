package introspector_test

import (
	"errors"
	"testing"

	"github.com/codeclysm/introspector/v3"
)

func TestCollection(t *testing.T) {
	t.Run("three introspector, no valid token", func(t *testing.T) {
		list := introspector.Collection{
			mock{errors.New("invalid token")},
			mock{errors.New("invalid signature")},
			mock{errors.New("wrong algorhytm")},
		}

		_, err := list.Introspect("token")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("three introspector, valid token for the second", func(t *testing.T) {
		list := introspector.Collection{
			mock{errors.New("invalid token")},
			mock{nil},
			mock{errors.New("wrong algorhytm")},
		}

		_, err := list.Introspect("token")
		if err != nil {
			t.Fatal("expected nil, got", err)
		}
	})
}

type mock struct {
	err error
}

func (m mock) Introspect(string) (introspector.Introspection, error) {
	return introspector.Introspection{}, m.err
}
