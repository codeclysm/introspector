package introspector_test

import (
	"testing"
	"time"

	"github.com/codeclysm/introspector/v3"
)

func TestIntrospection_Valid(t *testing.T) {
	tests := []struct {
		name string
		i    introspector.Introspection
		err  string
	}{
		{
			name: "future",
			i: introspector.Introspection{
				IssuedAt: time.Now().Add(1 * time.Hour).Unix(),
			},
			err: "token issued in the future",
		},
		{
			name: "not yet valid",
			i: introspector.Introspection{
				IssuedAt:  time.Now().Add(-1 * time.Hour).Unix(),
				NotBefore: time.Now().Add(1 * time.Hour).Unix(),
			},
			err: "token not yet valid",
		},
		{
			name: "expired",
			i: introspector.Introspection{
				IssuedAt:  time.Now().Add(-1 * time.Hour).Unix(),
				NotBefore: time.Now().Add(-1 * time.Hour).Unix(),
				ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
			},
			err: "token expired",
		},
		{
			name: "not active",
			i: introspector.Introspection{
				IssuedAt:  time.Now().Add(-1 * time.Hour).Unix(),
				NotBefore: time.Now().Add(-1 * time.Hour).Unix(),
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			},
			err: "token not active",
		},
		{
			name: "valid",
			i: introspector.Introspection{
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				Active:    true,
			},
			err: "nil",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.i.Valid()
			errString := "nil"
			if err != nil {
				errString = err.Error()
			}

			if errString != tt.err {
				t.Errorf("Introspection.Valid() error = '%v', wanted '%v'", err, tt.err)
				return
			}
		})
	}
}
