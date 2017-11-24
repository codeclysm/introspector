package introspector

import (
	"errors"
	"strings"
)

// WardenMock returns fictitious introspections
// it can be used to test the presence of checks for both specific scopes and specific Warden permissions
type WardenMock struct {
}

// Introspect accepts a token in this form:
//   "subject.scope1,scope2.action1,action2.resource1,resource2.context:value,context2:value"
// and will return an appropriate introspection
func (m WardenMock) Introspect(token string) (*Introspection, error) {
	introspection := new(Introspection)

	parts := strings.Split(token, ".")
	if len(parts) < 5 {
		return nil, errors.New("The token must be in the form 'subject.scope1,scope2.action1,action2.resource1,resource2.context:value,context2:value'")
	}

	introspection.Subject = parts[0]

	introspection.Scope = strings.Join(strings.Split(parts[1], ","), " ")

	introspection.Extra = map[string]interface{}{}
	introspection.Extra["actions"] = strings.Split(parts[2], ",")
	introspection.Extra["resources"] = strings.Split(parts[3], ",")
	introspection.Extra["context"] = strings.Split(parts[4], ",")

	introspection.Active = true

	return introspection, nil
}

// Allowed accepts a token in this form:
//   "subject.scope1,scope2.action1,action2.resource1,resource2.context:value,context2:value"
//
// scope1 and scope2 are granted oauth2 scopes
// action1 and action2 are some actions the subject can perform on the resources
// resource1 and resource2 are some resource the subject has access to
// context:value and context2:value2 are some context values
//
// Example: "123456.profile:public.drive,sell.car.owner_id:123456"
func (m WardenMock) Allowed(token string, perm Permission, scopes ...string) (i *Introspection, can bool, err error) {
	i, err = m.Introspect(token)
	if err != nil {
		return i, false, err
	}

	// Check scopes
	for _, scope := range scopes {
		if !in(strings.Split(i.Scope, " "), scope) {
			return i, false, nil
		}
	}

	// Check resource
	if res, ok := i.Extra["resources"]; ok {
		resources := res.([]string)
		if !in(resources, perm.Resource) {
			return i, false, nil
		}
	}

	// Check action
	if res, ok := i.Extra["actions"]; ok {
		actions := res.([]string)
		if !in(actions, perm.Action) {
			return i, false, nil
		}
	}

	// Check context
	if res, ok := i.Extra["context"]; ok {
		for key, value := range perm.Context {
			if !in(res.([]string), key+":"+value) {
				return i, false, nil
			}
		}
	}

	return i, true, nil
}
