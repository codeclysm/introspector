package introspector_test

import (
	"fmt"
	"testing"

	"github.com/serjlee/introspector"
)

func TestWardenMock(t *testing.T) {
	cases := []struct {
		Token            string
		Permission       introspector.Permission
		Scopes           []string
		Expected         bool
		ExpIntrospection introspector.Introspection
	}{
		{"123456.profile:cars,car:seats.drive,sell.car:777,car:779.dayofweek:friday,weather:windy",
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
				Scope:   "profile:cars car:seats",
				Extra: map[string]interface{}{
					"resources": []string{"car:777", "car:779"},
					"actions":   []string{"drive", "sell"},
					"context":   []string{"dayofweek:friday", "weather:windy"},
				}}},
		// Only check scopes
		{"123456.profile:cars...",
			introspector.Permission{},
			[]string{"profile:cars"},
			true,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars",
				Extra: map[string]interface{}{
					"resources": []string{""},
					"actions":   []string{""},
					"context":   []string{""},
				}}},
		// Wrong context
		{"123456.profile:cars,car:seats.drive,sell.car:777,car:779.dayofweek:friday,weather:windy",
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
				Scope:   "profile:cars car:seats",
				Extra: map[string]interface{}{
					"resources": []string{"car:777", "car:779"},
					"actions":   []string{"drive", "sell"},
					"context":   []string{"dayofweek:friday", "weather:windy"},
				}}},
		// Missing resource
		{"123456.profile:cars,car:seats.drive,sell.car:779.dayofweek:friday,weather:windy",
			introspector.Permission{
				Action:   "drive",
				Resource: "car:777",
			},
			[]string{"profile:cars"},
			false,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars car:seats",
				Extra: map[string]interface{}{
					"resources": []string{"car:779"},
					"actions":   []string{"drive", "sell"},
					"context":   []string{"dayofweek:friday", "weather:windy"},
				}}},
		// Missing action
		{"123456.profile:cars,car:seats.drive,sell.car:777.dayofweek:friday,weather:windy",
			introspector.Permission{
				Action:   "destroy",
				Resource: "car:777",
			},
			[]string{"profile:cars"},
			false,
			introspector.Introspection{
				Active:  true,
				Subject: "123456",
				Scope:   "profile:cars car:seats",
				Extra: map[string]interface{}{
					"resources": []string{"car:777"},
					"actions":   []string{"drive", "sell"},
					"context":   []string{"dayofweek:friday", "weather:windy"},
				}}},
		// Missing scope
		{"123456.profile:cars.drive,sell.car:777,car:779.dayofweek:friday,weather:windy",
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
				Scope:   "profile:cars",
				Extra: map[string]interface{}{
					"resources": []string{"car:777", "car:779"},
					"actions":   []string{"drive", "sell"},
					"context":   []string{"dayofweek:friday", "weather:windy"},
				}}},
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
