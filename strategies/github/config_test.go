package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/dundunlabs/omniauth"
	"golang.org/x/oauth2"
)

var mockUser = map[string]any{
	"login":               "octocat",
	"id":                  json.Number("1"),
	"node_id":             "MDQ6VXNlcjE=",
	"avatar_url":          "https://github.com/images/error/octocat_happy.gif",
	"gravatar_id":         "",
	"url":                 "https://api.github.com/users/octocat",
	"html_url":            "https://github.com/octocat",
	"followers_url":       "https://api.github.com/users/octocat/followers",
	"following_url":       "https://api.github.com/users/octocat/following{/other_user}",
	"gists_url":           "https://api.github.com/users/octocat/gists{/gist_id}",
	"starred_url":         "https://api.github.com/users/octocat/starred{/owner}{/repo}",
	"subscriptions_url":   "https://api.github.com/users/octocat/subscriptions",
	"organizations_url":   "https://api.github.com/users/octocat/orgs",
	"repos_url":           "https://api.github.com/users/octocat/repos",
	"events_url":          "https://api.github.com/users/octocat/events{/privacy}",
	"received_events_url": "https://api.github.com/users/octocat/received_events",
	"type":                "User",
	"site_admin":          false,
	"name":                "monalisa octocat",
	"company":             "GitHub",
	"blog":                "https://github.com/blog",
	"location":            "San Francisco",
	"email":               "octocat@github.com",
	"hireable":            false,
	"bio":                 "There once was...",
	"twitter_username":    "monatheoctocat",
	"public_repos":        json.Number("2"),
	"public_gists":        json.Number("1"),
	"followers":           json.Number("20"),
	"following":           json.Number("0"),
	"created_at":          "2008-01-14T04:33:35Z",
	"updated_at":          "2008-01-14T04:33:35Z",
}

var (
	errResponse = errors.New("error response")
	errExchange = errors.New("error exchange")
)

func compare(t *testing.T, got any, want any) {
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}
}

type mockConfig struct {
	*Config
}

func (c *mockConfig) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	if code == "" {
		return nil, errExchange
	}
	return &oauth2.Token{
		AccessToken: "foobar",
	}, nil
}

type mockClientSuccess struct {
	*http.Client
}

func (c *mockClientSuccess) Do(req *http.Request) (*http.Response, error) {
	data, _ := json.Marshal(mockUser)
	return &http.Response{
		Body: io.NopCloser(bytes.NewReader(data)),
	}, nil
}

type mockClientError struct {
	*http.Client
}

func (c *mockClientError) Do(req *http.Request) (*http.Response, error) {
	return nil, errResponse
}

func TestExchangeAuthInfo(t *testing.T) {
	conf := &mockConfig{
		Config: NewConfig(&oauth2.Config{}),
	}
	conf.SetSelf(conf)

	t.Run("response success", func(t *testing.T) {
		conf.httpclient = &mockClientSuccess{}
		got, _ := conf.ExchangeAuthInfo(context.Background(), "123456")
		want := &omniauth.Auth{
			ID:      "1",
			Name:    "monalisa octocat",
			Email:   "octocat@github.com",
			Picture: "https://github.com/images/error/octocat_happy.gif",
			RawInfo: mockUser,
		}
		compare(t, got, want)
	})

	t.Run("response error", func(t *testing.T) {
		conf.httpclient = &mockClientError{}
		_, got := conf.ExchangeAuthInfo(context.Background(), "123456")
		compare(t, got, errResponse)
	})

	t.Run("exchange error", func(t *testing.T) {
		conf.httpclient = &mockClientSuccess{}
		_, got := conf.ExchangeAuthInfo(context.Background(), "")
		compare(t, got, errExchange)
	})
}
