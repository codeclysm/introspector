package introspector

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Cached allows you to query multiple introspector
type Cached struct {
	Introspector Introspector
	Cache        interface {
		Get(key string) ([]byte, error)
		Set(key string, entry []byte) error
	}
}

type result struct {
	I   Introspection
	Err string
}

// Introspect returns a cached version of the introspection of the token
func (c Cached) Introspect(token string) (i Introspection, err error) {
	res := result{}

	// Attempt to retrieve from cache
	data, err := c.Cache.Get("introspect:" + token)
	if err == nil {
		err = json.Unmarshal(data, &res)
		if err != nil {
			return res.I, fmt.Errorf("unmarshal %s from cache: %w", string(data), err)
		}

		return res.I, errOrNil(res.Err)
	}

	// Retrieve from Introspector
	res.I, err = c.Introspector.Introspect(token)
	if err != nil {
		res.Err = err.Error()
	}

	// Marshal data
	data, err = json.Marshal(res)
	if err != nil {
		return res.I, fmt.Errorf("marshal %+v to cache: %w", res, err)
	}

	// Save in cache
	err = c.Cache.Set("introspect:"+token, data)
	if err != nil {
		return res.I, fmt.Errorf("save %s in cache: %w", string(data), err)
	}
	return res.I, errOrNil(res.Err)
}

func errOrNil(str string) error {
	if str == "" {
		return nil
	}

	return errors.New(str)
}
