package introspector

import (
	"errors"
	"strings"
)

// Mock returns fictitious introspections
type Mock struct {
}

// Introspect accepts a token in this form:
//   "userid.scope1,scope2.[allow|deny]"
// and will return an appropriate introspection
func (m Mock) Introspect(token string) (*Introspection, error) {
	introspection := new(Introspection)

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("The token must be in the form 'userid.scope1,scope2.[allow|deny]'")
	}

	if len(parts) == 3 {
		introspection.Extra = map[string]interface{}{}
		introspection.Extra[parts[2]] = true
	}

	introspection.Subject = parts[0]

	parts = strings.Split(parts[1], ",")

	introspection.Scope = strings.Join(parts, " ")

	introspection.Active = true

	return introspection, nil
}

// Allowed accepts a token in this form:
//   "userid.scope1,scope2.[allow|deny]"
// where scope1 and scope2 are in the form action:resource.
// Example: "123456.create:users.allow"
func (m Mock) Allowed(token string, perm Permission, scopes ...string) (i *Introspection, can bool, err error) {
	i, err = m.Introspect(token)
	if err != nil {
		return i, false, err
	}

	for _, scope := range scopes {
		if !in(strings.Split(i.Scope, " "), scope) {
			i.Active = false
		}
	}

	if !i.Active {
		return i, false, nil
	}

	if _, ok := i.Extra["allow"]; ok {
		can = true
	}

	return i, can, nil
}

func in(slice []string, a string) bool {
	for _, item := range slice {
		if a == item {
			return true
		}
	}

	return false
}
