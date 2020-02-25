package introspector

import (
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

// JWT extracts info from a token if it manages to decrypt it
type JWT struct {
	// Key is the signing key for the JWT token
	Key interface{}
	// Method is the Signing Method of the JWT. Can be one of [ECDSA, RSA, HMAC]. Defaults to HMAC
	Method string
}

// Introspect extracts the info from the standard jwt claims, which you can read
// here: https://tools.ietf.org/html/rfc7519#section-4.1
// Scope is not used, and the Active flag is set to the Valid value of the token.
// Extra fields, such as jit, will end up in Extra
func (j JWT) Introspect(token string) (*Introspection, error) {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Check the signing method
		switch j.Method {
		case "ECDSA":
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("introspect failed: unexpected signing method: %v", t.Header["alg"])
			}
		case "RSA":
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("introspect failed: unexpected signing method: %v", t.Header["alg"])
			}
		default:
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("introspect failed: unexpected signing method: %v", t.Header["alg"])
			}
		}

		return j.Key, nil
	})

	// We don't return an error if the token is not valid, but only if we cannot parse it
	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) == 0 {
			return nil, fmt.Errorf("introspect failed: %w", err)
		}
	}

	var claims jwt.MapClaims
	var ok bool

	if claims, ok = tok.Claims.(jwt.MapClaims); !ok {
		return nil, errors.New("introspect failed: couldn't understand claims")
	}

	i := Introspection{
		Active: tok.Valid,
		Scope:  "",
		Extra:  map[string]interface{}{},
	}

	// Loop through the keys to build the introspection object
	for key, value := range claims {
		switch key {
		case "iss":
			if i.Issuer, ok = value.(string); !ok {
				return nil, errors.New("introspect failed: claims['iss'] is not a string")
			}
		case "aud":
			if i.Audience, ok = value.(string); !ok {
				return nil, errors.New("introspect failed: claims['aud'] is not a string")
			}
		case "sub":
			if i.Subject, ok = value.(string); !ok {
				return nil, errors.New("introspect failed: claims['sub'] is not a string")
			}
		case "exp":
			// I don't know why it recognize it as a float64. ¯\_(ツ)_/¯
			var expires float64
			if expires, ok = value.(float64); !ok {
				return nil, errors.New("introspect failed: claims['exp'] is not an float64")
			}
			i.ExpiresAt = int64(expires)
		case "iat":
			// I don't know why it recognize it as a float64. ¯\_(ツ)_/¯
			var issued float64
			if issued, ok = value.(float64); !ok {
				return nil, errors.New("introspect failed: claims['iat'] is not an float64")
			}
			i.IssuedAt = int64(issued)
		case "nbf":
			// I don't know why it recognize it as a float64. ¯\_(ツ)_/¯
			var notbefore float64
			if notbefore, ok = value.(float64); !ok {
				return nil, errors.New("introspect failed: claims['nbf'] is not an float64")
			}
			i.NotBefore = int64(notbefore)
		default:
			i.Extra[key] = value
		}
	}

	return &i, nil

}
