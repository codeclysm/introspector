package introspector

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/juju/errors"
)

// Oauth queries an endpoint to obtain info about the given token
type Oauth struct {
	// Endpoint is the url to query
	Endpoint string

	// Client is the http client which will make the request
	Client *http.Client
}

// NewOauth returns a Oauth connected to an oauth2 service
// it can fail if the tokenURL is not a valid url, or if the id and secret don't work
// It's basically a convenience wrapper around golang.org/x/oauth2/clientcredentials
func NewOauth(id, secret, tokenURL, endpoint string, scopes []string) (*Oauth, error) {
	client, err := authenticate(id, secret, tokenURL, scopes)
	if err != nil {
		return nil, errors.Annotate(err, "Instantiate Oauth")
	}

	manager := Oauth{
		Endpoint: endpoint,
		Client:   client,
	}
	return &manager, nil
}

func authenticate(id, secret, tokenURL string, scopes []string) (*http.Client, error) {
	credentials := clientcredentials.Config{
		ClientID:     id,
		ClientSecret: secret,
		TokenURL:     tokenURL,
		Scopes:       scopes,
	}

	ctx := context.Background()
	_, err := credentials.Token(ctx)
	if err != nil {
		return nil, errors.Annotatef(err, "connect to tokenURL %s", tokenURL)
	}
	return credentials.Client(ctx), nil
}

// Introspect queries the endpoint with an http request. It expects that the endpoint
// implements https://tools.ietf.org/html/rfc7662
func (o Oauth) Introspect(token string, scopes ...string) (*Introspection, error) {
	data := url.Values{
		"token": []string{token},
		"scope": []string{strings.Join(scopes, " ")},
	}

	req, err := http.NewRequest("POST", o.Endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, errors.Annotatef(err, "new request for %s", o.Endpoint)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	var introspection *Introspection
	err = bind(o.Client, req, introspection)
	if err != nil {
		return nil, err
	}
	return introspection, nil

}

// bind does a get request and binds the body to the given interface
func bind(client *http.Client, req *http.Request, o interface{}) error {
	resp, err := client.Do(req)
	if err != nil {
		return errors.Annotatef(err, "execute request %+v", req)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return errors.Errorf("Expected status code %d, got %d.\n%s\n", http.StatusOK, resp.StatusCode, body)
	} else if err := json.NewDecoder(resp.Body).Decode(o); err != nil {
		return errors.Annotatef(err, "decode json %s", resp.Body)
	}
	return nil
}
