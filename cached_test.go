package introspector_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/codeclysm/introspector/v3"
)

func TestCached(t *testing.T) {
	t.Run("no result in cache", func(t *testing.T) {
		cache := mockCache{}

		intro := mockIntro(0)

		cached := introspector.Cached{
			Cache:        &cache,
			Introspector: &intro,
		}

		i, err := cached.Introspect("token")
		if err != nil {
			t.Fatal("expected err to be nil, got", err.Error())
		}
		if i.ClientID != "1" {
			t.Fatal("expected client id to be 1")
		}

		// Check that the result is now in cache
		data, ok := cache["introspect:token"]
		if !ok {
			t.Fatal("expected cache to be filled")
		}

		if string(data) != `{"I":{"active":false,"client_id":"1"},"Err":""}` {
			t.Fatal(`expected data to be '{"I":{"active":false,"client_id":"1"},"Err":""}', got`, string(data))
		}
	})

	t.Run("ensure mockintro works", func(t *testing.T) {
		intro := mockIntro(0)
		for i := 1; i < 10; i++ {
			introspection, err := intro.Introspect("token")
			if err != nil {
				t.Fatal("expected err to be nil, got", err)
			}
			client, _ := strconv.Atoi(introspection.ClientID)
			if client != i {
				t.Fatal("expected client to be", i, "got", client)
			}
		}
	})

	t.Run("ensure results are cached", func(t *testing.T) {
		cache := mockCache{}
		intro := mockIntro(0)

		cached := introspector.Cached{
			Cache:        &cache,
			Introspector: &intro,
		}

		for i := 0; i < 10; i++ {
			i, err := cached.Introspect("token")
			if err != nil {
				t.Fatal("expected err to be nil, got", err)
			}
			if i.ClientID != "1" {
				t.Fatal("expected client id to be 1")
			}
		}
	})

	t.Run("ensure mockintroerr works", func(t *testing.T) {
		intro := mockIntroErr(0)
		for i := 1; i < 10; i++ {
			_, err := intro.Introspect("token")
			if err == nil {
				t.Fatal("expected err not to be nil, got", err)
			}
			erro, _ := strconv.Atoi(err.Error())
			if erro != i {
				t.Fatal("expected error to be", i, "got", erro)
			}
		}
	})

	t.Run("ensure results are cached", func(t *testing.T) {
		cache := mockCache{}
		intro := mockIntroErr(0)

		cached := introspector.Cached{
			Cache:        &cache,
			Introspector: &intro,
		}

		for i := 0; i < 10; i++ {
			_, err := cached.Introspect("token")
			if err == nil {
				t.Fatal("expected err not to be nil, got", err)
			}
			if err.Error() != "1" {
				t.Fatal("expected error to be 1, got", err)
			}
		}
	})

}

type mockCache map[string][]byte

func (m mockCache) Get(key string) ([]byte, error) {
	data, ok := m[key]
	if !ok {
		return nil, errors.New("Not found")
	}
	return data, nil
}

func (m mockCache) Set(key string, data []byte) error {
	m[key] = data
	return nil
}

type mockIntro int

func (m *mockIntro) Introspect(string) (introspector.Introspection, error) {
	*m++
	return introspector.Introspection{
		ClientID: strconv.Itoa(int(*m)),
	}, nil
}

type mockIntroErr int

func (m *mockIntroErr) Introspect(string) (introspector.Introspection, error) {
	*m++
	return introspector.Introspection{}, errors.New(strconv.Itoa(int(*m)))
}
