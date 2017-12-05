package introspector_test

import (
	"fmt"
	"testing"

	"github.com/codeclysm/introspector"
)

func TestWardenMock(t *testing.T) {
	cases := []struct {
		Token            string
		Permission       introspector.Permission
		Scopes           []string
		Expected         bool
		ExpIntrospection introspector.Introspection
	}{
		{`{"subject":"123456","scopes":["profile:cars","car:seats"],"actions":["drive","sell"],"resources":["car:777"],"context":{"dayofweek":"friday","weather":"windy"}}`,
			introspector.Permission{
				Action:   "drive",
				Resource: "car:777",
				Context:  map[string]string{"weather": "windy"},
			},
			[]string{"profile:cars"},
			true,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars car:seats"}},
		// Only check scopes
		{`{"subject":"123456","scopes":["profile:cars"]}`,
			introspector.Permission{},
			[]string{"profile:cars"},
			true,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars"}},
		// Wrong context
		{`{"subject":"123456","scopes":["profile:cars","car:seats"],"actions":["drive","sell"],"resources":["car:777"],"context":{"dayofweek":"friday","weather":"windy"}}`,
			introspector.Permission{
				Action:   "drive",
				Resource: "car:777",
				Context:  map[string]string{"weather": "doomsday"},
			},
			[]string{"profile:cars"},
			false,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars car:seats"}},
		// Missing resource
		{`{"subject":"123456","scopes":["profile:cars","car:seats"],"actions":["drive","sell"],"resources":["car:779"],"context":{"weather":"windy"}}`,
			introspector.Permission{
				Action:   "drive",
				Resource: "car:777",
			},
			[]string{"profile:cars"},
			false,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars car:seats"}},
		// Missing action
		{`{"subject":"123456","scopes":["profile:cars","car:seats"],"actions":["drive","sell"],"resources":["car:777"],"context":{"weather":"windy"}}`,
			introspector.Permission{
				Action:   "destroy",
				Resource: "car:777",
			},
			[]string{"profile:cars"},
			false,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars car:seats"}},
		// Missing scope
		{`{"subject":"123456","scopes":["profile:cars"],"actions":["drive"],"resources":["car:777"],"context":{"weather":"windy"}}`,
			introspector.Permission{
				Action:   "drive",
				Resource: "car:777",
				Context:  map[string]string{"weather": "windy"},
			},
			[]string{"car:seats"},
			false,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars"}},
	}
	for _, tc := range cases {
		mock := introspector.WardenMock{}

		t.Run(fmt.Sprintf("%s", tc.Token), func(t *testing.T) {
			i, can, err := mock.Allowed(tc.Token, tc.Permission, tc.Scopes...)
			if err != nil {
				t.Fatalf("err: %s", err.Error())
			}

			if can != tc.Expected {
				t.Fatalf("can: %v instead of %v", can, tc.Expected)
			}
			equal(t, i, &tc.ExpIntrospection)

		})
	}
}
