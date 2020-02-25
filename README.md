use 'godoc cmd/github.com/codeclysm/introspector' for documentation on the github.com/codeclysm/introspector command 

Package introspector
=====================

    import "github.com/codeclysm/introspector/v3"

Package introspector abstracts the process of gaining info from an
authentication token.

In a perfect world you'll have to handle authentication only once, and only from
a perfectly standard Oauthx solution that you can plug in every project.

Reality is different. In reality you have to handle a messy authentication system with oauth2, along with some hardcoded api keys that no one knows who put there, and on top of it all you have to introduce a brand new (but still messy) authentication system.
apps.

Introspector introduces the concept of collections. It returns info from the first system that understands what you're talking about.

```go
	j1 := introspector.JWT{
		Key: []byte("secret"),
	}

	j2 := introspector.JWT{
		Key: []byte("terces"),
	}

	collection := introspector.Collection{j1, j2}

	i, err := collection.Introspect("eyJh...lIw")
	fmt.Println(err)
	fmt.Println(i.Subject)
	fmt.Println(i.Active)
	fmt.Println(i.ExpiresAt)
	// Output:
	// <nil>
	// test
	// false
	// 1486394779
```

You can implement your own introspectors, as long as you satisfy the necessary interface.

Learn more at https://godoc.org/github.com/codeclysm/introspector