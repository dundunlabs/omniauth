package omniauth

import (
	"context"

	"golang.org/x/oauth2"
)

func NewOmniAuth(config *oauth2.Config) OmniAuth {
	return &Config{
		Config: config,
	}
}

type OmniAuth interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	ExchangeAuthInfo(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*Auth, error)
}
