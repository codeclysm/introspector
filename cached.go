package introspector

import "encoding/json"

// Cached allows you to query multiple introspector
type Cached struct {
	Introspector Introspector
	Cache        interface {
		Get(key string) ([]byte, error)
		Set(key string, entry []byte) error
	}
}

// Introspect returns a cached version of the introspection of the token
func (c Cached) Introspect(token string) (i *Introspection, err error) {
	// Attempt to retrieve from cache
	data, err := c.Cache.Get("introspect:" + token)
	if err == nil {
		i = &Introspection{}
		err = json.Unmarshal(data, i)
		if err != nil {
			return nil, err
		}

		return i, nil
	}

	// Retrieve from Introspector
	i, err = c.Introspector.Introspect(token)
	if err != nil {
		return nil, err
	}

	// Marshal data
	data, err = json.Marshal(i)
	if err != nil {
		return nil, err
	}

	// Save in cache
	err = c.Cache.Set("introspect:"+token, data)
	if err != nil {
		return nil, err
	}
	return i, nil
}
