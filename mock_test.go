package introspector_test

import (
	"fmt"
	"testing"

	"github.com/codeclysm/introspector"
)

func TestMock(t *testing.T) {
	cases := []struct {
		Token            string
		Action           string
		Resource         string
		Expected         bool
		ExpIntrospection introspector.Introspection
	}{
		{"test.users:create", "users", "modify", false,
			introspector.Introspection{
				Active: true, Subject: "test", Scope: "users:create"}},
		{"test.users:create,users:modify", "users", "modify", false,
			introspector.Introspection{
				Active: true, Subject: "test", Scope: "users:create users:modify"}},
		{"test.users:create,users:modify.allow", "users", "modify", true,
			introspector.Introspection{
				Active: true, Subject: "test", Scope: "users:create users:modify",
				Extra: map[string]interface{}{"allow": true}}},
	}
	for _, tc := range cases {
		mock := introspector.Mock{}

		t.Run(fmt.Sprintf("%s", tc.Token), func(t *testing.T) {
			i, can, err := mock.Allowed(tc.Token, introspector.Permission{Action: tc.Action, Resource: tc.Resource})
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
