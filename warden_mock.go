package introspector

import (
	"encoding/json"
	"errors"
	"strings"
)

// WardenMock returns fictitious introspections
// it can be used to test the presence of checks for both specific scopes and specific Warden permissions
type WardenMock struct {
}

// holds the grants for a user, kinda like a ladon policy
type mockGrants struct {
	Actions   []string          `json:"actions"`
	Context   map[string]string `json:"context"`
	Resources []string          `json:"resources"`
	Scopes    []string          `json:"scopes"`
	Subject   string            `json:"subject"`
}

// Introspect accepts a token in this form:
// `{"subject":"123456","scopes":["profile:cars","car:seats"],"actions":["drive","sell"],"resources":["car:777"],"context":{"weather":"windy"}}`
// and will return an appropriate introspection
func (m WardenMock) Introspect(token string) (*Introspection, error) {
	introspection := new(Introspection)

	var grants mockGrants
	if err := json.Unmarshal([]byte(token), &grants); err != nil {
		return nil, errors.New(`The token is malformed, should look like {"subject":"123456","scopes":["profile:cars","car:seats"],"actions":["drive","sell"],"resources":["car:777"],"context":{"weather":"windy"}}`)
	}

	introspection.Subject = grants.Subject

	introspection.Scope = strings.Join(grants.Scopes, " ")

	introspection.Active = true

	return introspection, nil
}

// Allowed accepts a token in this form:
//  `{"subject":"subject","scopes":["scope1","scope2"],"actions":["action1","action2"],"resources":["resource1","resource2"],"context":{"context":"value","context2":"value2"}}`
//
// This form is kinda the same form as the JSON-encoded ladon policies.
//
// scope1 and scope2 are granted oauth2 scopes
// action1 and action2 are some actions the subject can perform on the resources
// resource1 and resource2 are some resource the subject has access to
// context:value and context2:value2 are some context values
//
// Example: `{"subject":"123456","scopes":["profile:cars","car:seats"],"actions":["drive","sell"],"resources":["car:777"],"context":{"weather":"windy"}}`
func (m WardenMock) Allowed(token string, perm Permission, scopes ...string) (i *Introspection, can bool, err error) {
	i, err = m.Introspect(token)
	if err != nil {
		return i, false, err
	}

	var grants mockGrants
	if err := json.Unmarshal([]byte(token), &grants); err != nil {
		return nil, false, errors.New(`The token is malformed, should look like {"subject":"123456","scopes":["profile:cars","car:seats"],"actions":["drive","sell"],"resources":["car:777"],"context":{"weather":"windy"}}`)
	}

	// Check scopes
	for _, scope := range scopes {
		if !in(grants.Scopes, scope) {
			return i, false, nil
		}
	}

	// Check resource
	if perm.Resource != "" {
		if !in(grants.Resources, perm.Resource) {
			return i, false, nil
		}
	}

	// Check action
	if perm.Action != "" {
		if !in(grants.Actions, perm.Action) {
			return i, false, nil
		}
	}

	// Check context
	for key, value := range perm.Context {
		if res, ok := grants.Context[key]; !ok || res != value {
			return i, false, nil
		}
	}

	return i, true, nil
}
