package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/dundunlabs/omniauth"
	"golang.org/x/oauth2"
)

type Config struct {
	*omniauth.Config
}

func (c *Config) user(token *oauth2.Token) (map[string]any, error) {
	httpclient := &httpClient{
		token: token.AccessToken,
	}
	res, err := httpclient.fetch(http.MethodGet, "/user", nil)
	if err != nil {
		return nil, err
	}
	var user map[string]any
	decoder := json.NewDecoder(res.Body)
	decoder.UseNumber()
	err = decoder.Decode(&user)
	return user, err
}

func (c *Config) ExchangeAuthInfo(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*omniauth.Auth, error) {
	token, err := c.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}
	user, err := c.user(token)
	if err != nil {
		return nil, err
	}
	return &omniauth.Auth{
		ID:      user["id"].(string),
		Name:    user["name"].(string),
		Email:   user["email"].(string),
		Picture: user["avatar_url"].(string),
		RawInfo: user,
	}, nil
}

const API_URL = "https://api.github.com"

type httpClient struct {
	token string
}

func (c *httpClient) fetch(method string, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, API_URL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return http.DefaultClient.Do(req)
}
