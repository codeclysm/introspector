package introspector

import "encoding/json"

// Cached allows you to query multiple introspector
type Cached struct {
	Warden Warden
	Cache  interface {
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

	// Retrieve from warden
	i, err = c.Warden.Introspect(token)
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

// Allowed returns a cached version of the permission of the token
func (c Cached) Allowed(token string, perm Permission, scopes ...string) (i *Introspection, can bool, err error) {
	req := struct {
		Token  string
		Perm   Permission
		Scopes []string
	}{
		Token:  token,
		Perm:   perm,
		Scopes: scopes,
	}

	// Marshal req
	datareq, err := json.Marshal(req)
	if err != nil {
		return nil, false, err
	}

	resp := struct {
		I   *Introspection
		Can bool
	}{}

	// Attempt to retrieve from cache
	data, err := c.Cache.Get("allowed:" + string(datareq))
	if err == nil {
		err = json.Unmarshal(data, &resp)
		if err != nil {
			return nil, false, err
		}

		return resp.I, resp.Can, nil
	}

	// Retrieve from warden
	resp.I, resp.Can, err = c.Warden.Allowed(token, perm, scopes...)
	if err != nil {
		return nil, false, err
	}

	// Marshal data
	data, err = json.Marshal(resp)
	if err != nil {
		return nil, false, err
	}

	// Save in cache
	err = c.Cache.Set("allowed:"+string(datareq), data)
	if err != nil {
		return nil, false, err
	}
	return resp.I, resp.Can, nil
}
