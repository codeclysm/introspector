package auth0_test

import (
	"encoding/json"
	"testing"

	jwt "gopkg.in/square/go-jose.v2/jwt"

	"time"

	"io/ioutil"

	"github.com/serjlee/introspector/auth0"
)

func TestValidity(t *testing.T) {
	cases := []struct {
		ID    string
		Token string
		Key   string
		Error string
	}{}

	readCases(t, "testdata/validity.json", &cases)

	for _, tc := range cases {
		auth := auth0.Auth0{
			Claims: jwt.Expected{
				Time: time.Unix(1500585990, 0),
			},
		}

		err := auth.WithKeyPath(tc.Key)
		if err != nil {
			t.Errorf(tc.ID + ": " + err.Error())
		}
		_, err = auth.Introspect(tc.Token)

		if err == nil && tc.Error != "" {
			t.Errorf(tc.ID+": err is nil but should be '%s'", tc.Error)
			return
		}
		if err != nil && err.Error() != tc.Error {
			t.Errorf(tc.ID+": err is '%s' but should be '%s'", err.Error(), tc.Error)
		}
	}
}

func readCases(t *testing.T, path string, cases interface{}) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = json.Unmarshal(data, cases)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
}
