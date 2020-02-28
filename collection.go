package introspector

import (
	"github.com/joeshaw/multierror"
)

// Collection allows you to query multiple introspector
type Collection []Introspector

// Introspect queries every introspector returning the result of the first one
// that succeeds or a collection of errors
func (c Collection) Introspect(token string) (Introspection, error) {
	errs := multierror.Errors{}

	for i := range c {
		intro, err := c[i].Introspect(token)
		if err == nil {
			return intro, nil
		}
		errs = append(errs, err)
	}

	return Introspection{}, errs.Err()
}
