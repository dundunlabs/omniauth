package omniauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func compare(t *testing.T, got any, want any) {
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}
}

func TestExchangeAuthInfoByToken(t *testing.T) {
	config := NewConfig(&oauth2.Config{})

	t.Run("valid token", func(t *testing.T) {
		token := new(oauth2.Token).WithExtra(map[string]any{
			"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbXktZG9tYWluLmF1dGgwLmNvbSIsInN1YiI6ImF1dGgwfDEyMzQ1NiIsImF1ZCI6Im15X2NsaWVudF9pZCIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwLCJuYW1lIjoiSmFuZSBEb2UiLCJnaXZlbl9uYW1lIjoiSmFuZSIsImZhbWlseV9uYW1lIjoiRG9lIiwiZ2VuZGVyIjoiZmVtYWxlIiwiYmlydGhkYXRlIjoiMDAwMC0xMC0zMSIsImVtYWlsIjoiamFuZWRvZUBleGFtcGxlLmNvbSIsInBpY3R1cmUiOiJodHRwOi8vZXhhbXBsZS5jb20vamFuZWRvZS9tZS5qcGcifQ.FKw0UVWANEqibD9VTC9WLzstlyc_IRnyPSpUMDP3hKc",
		})

		auth, err := config.ExchangeAuthInfoByToken(token)
		if err != nil {
			t.Error(err)
		}

		want := &Auth{
			ID:      "auth0|123456",
			Name:    "Jane Doe",
			Email:   "janedoe@example.com",
			Picture: "http://example.com/janedoe/me.jpg",
			RawInfo: RawInfo{
				"aud":         "my_client_id",
				"birthdate":   "0000-10-31",
				"email":       "janedoe@example.com",
				"exp":         json.Number("1311281970"),
				"family_name": "Doe",
				"gender":      "female",
				"given_name":  "Jane",
				"iat":         json.Number("1311280970"),
				"iss":         "http://my-domain.auth0.com",
				"name":        "Jane Doe",
				"picture":     "http://example.com/janedoe/me.jpg",
				"sub":         "auth0|123456",
			},
		}

		compare(t, auth, want)
	})

	t.Run("missing token", func(t *testing.T) {
		token := new(oauth2.Token)

		_, err := config.ExchangeAuthInfoByToken(token)
		compare(t, err, ErrMissingIdToken)
	})

	t.Run("invalid token", func(t *testing.T) {
		token := new(oauth2.Token).WithExtra(map[string]any{
			"id_token": base64.RawStdEncoding.EncodeToString([]byte(`{"foo":"bar"}`)),
		})

		_, err := config.ExchangeAuthInfoByToken(token)
		compare(t, err, ErrInvalidIdToken)
	})

	t.Run("bad token", func(t *testing.T) {
		token := new(oauth2.Token).WithExtra(map[string]any{
			"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{foo:bar}.FKw0UVWANEqibD9VTC9WLzstlyc_IRnyPSpUMDP3hKc",
		})

		_, err := config.ExchangeAuthInfoByToken(token)
		if _, ok := err.(base64.CorruptInputError); !ok {
			t.Errorf("got: %T, want: %T", err, base64.CorruptInputError(0))
		}
	})

	t.Run("bad payload", func(t *testing.T) {
		token := new(oauth2.Token).WithExtra(map[string]any{
			"id_token": strings.Join([]string{
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				base64.RawStdEncoding.EncodeToString([]byte(`{foo:bar}`)),
				"FKw0UVWANEqibD9VTC9WLzstlyc_IRnyPSpUMDP3hKc",
			}, "."),
		})

		_, err := config.ExchangeAuthInfoByToken(token)
		if _, ok := err.(*json.SyntaxError); !ok {
			t.Errorf("got: %T, want: %T", err, &json.SyntaxError{})
		}
	})
}

type mockConfig struct {
	*Config
}

func (c *mockConfig) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return new(oauth2.Token), nil
}

func TestExchangeAuthInfo(t *testing.T) {
	t.Run("exchange error", func(t *testing.T) {
		config := &Config{
			Config: &oauth2.Config{},
		}
		_, err := config.ExchangeAuthInfo(context.Background(), "123456")
		if _, ok := err.(*url.Error); !ok {
			t.Errorf("got: %T, want: %T", err, &url.Error{})
		}
	})

	t.Run("exchange ok", func(t *testing.T) {
		config := &mockConfig{
			Config: &Config{},
		}
		config.SetSelf(config)
		_, err := config.ExchangeAuthInfo(context.Background(), "123456")
		compare(t, err, ErrMissingIdToken)
	})
}
