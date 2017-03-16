package introspector

import (
	"fmt"

	"github.com/fluxio/multierror"
)

// Collection allows you to query multiple introspector
type Collection []Warden

// Introspect queries every introspector returning the result of the first one
// that succeeds or a collection of errors
func (c Collection) Introspect(token string) (*Introspection, error) {
	errs := multierror.Accumulator{}

	for i := range c {
		intro, err := c[i].Introspect(token)
		if err == nil {
			return intro, nil
		}
		errs.Push(err)
	}

	return nil, errs.Error()
}

// Allowed queries every introspector returning the result of the first one
// that succeeds or a collection of errors
func (c Collection) Allowed(token string, perm Permission, scopes ...string) (*Introspection, bool, error) {
	errs := multierror.Accumulator{}

	for i := range c {
		intro, can, err := c[i].Allowed(token, perm, scopes...)
		if err != nil {
			errs.Push(err)
			continue
		}
		if can {
			return intro, can, nil
		}
		errs.Push(fmt.Errorf("Not allowed for %T", c[i]))
	}

	return nil, false, errs.Error()
}
