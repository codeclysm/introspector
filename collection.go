package introspector

import (
	"github.com/fluxio/multierror"
)

// Collection allows you to query multiple introspector
type Collection []Introspector

// Introspect queries every introspector returning the result of the first one
// that succeeds or a collection of errors
func (c Collection) Introspect(token string, scopes ...string) (*Introspection, error) {
	errs := multierror.Accumulator{}

	for i := range c {
		intro, err := c[i].Introspect(token, scopes...)
		if err == nil {
			return intro, nil
		}
		errs.Push(err)
	}

	return nil, errs.Error()
}
