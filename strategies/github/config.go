package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/dundunlabs/omniauth"
	"golang.org/x/oauth2"
)

const API_URL = "https://api.github.com"

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

func NewConfig(c *oauth2.Config) *Config {
	conf := &Config{
		Config:     omniauth.NewConfig(c),
		httpclient: http.DefaultClient,
	}
	conf.SetSelf(conf)
	return conf
}

type Config struct {
	*omniauth.Config
	httpclient httpClient
}

func (c *Config) ExchangeAuthInfo(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*omniauth.Auth, error) {
	token, err := c.GetSelf().Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}
	user, err := c.user(token)
	if err != nil {
		return nil, err
	}
	auth := &omniauth.Auth{
		ID:      user["id"].(json.Number).String(),
		RawInfo: user,
	}
	if name, ok := user["name"].(string); ok {
		auth.Name = name
	}
	if email, ok := user["email"].(string); ok {
		auth.Email = email
	}
	if pic, ok := user["avatar_url"].(string); ok {
		auth.Picture = pic
	}
	return auth, nil
}

func (c *Config) user(token *oauth2.Token) (map[string]any, error) {
	res, err := c.fetch(http.MethodGet, "/user", nil, token.AccessToken)
	if err != nil {
		return nil, err
	}
	var user map[string]any
	decoder := json.NewDecoder(res.Body)
	decoder.UseNumber()
	err = decoder.Decode(&user)
	return user, err
}

func (c *Config) fetch(method string, path string, body io.Reader, token string) (*http.Response, error) {
	req, _ := http.NewRequest(method, API_URL+path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	return c.httpclient.Do(req)
}
