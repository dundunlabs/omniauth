package omniauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"golang.org/x/oauth2"
)

type IConfig interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	ExchangeAuthInfoByToken(token *oauth2.Token) (*Auth, error)
}

type Config struct {
	*oauth2.Config
	self IConfig
}

func (c *Config) GetSelf() IConfig {
	if c.self != nil {
		return c.self
	}
	return c
}

func (c *Config) SetSelf(self IConfig) *Config {
	c.self = self
	return c
}

type Claims struct {
	ID      string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
}

var (
	ErrMissingIdToken = errors.New("missing id_token")
	ErrInvalidIdToken = errors.New("invalid id_token")
)

func (c *Config) ExchangeAuthInfo(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*Auth, error) {
	token, err := c.GetSelf().Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}
	return c.GetSelf().ExchangeAuthInfoByToken(token)
}

func (c *Config) ExchangeAuthInfoByToken(token *oauth2.Token) (*Auth, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, ErrMissingIdToken
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidIdToken
	}
	payload, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	info := &RawInfo{}
	claims := &Claims{}
	for _, v := range []any{info, claims} {
		d := json.NewDecoder(bytes.NewReader(payload))
		d.UseNumber()
		if err := d.Decode(v); err != nil {
			return nil, err
		}
	}

	return &Auth{
		ID:      claims.ID,
		Name:    claims.Name,
		Email:   claims.Email,
		Picture: claims.Picture,
		RawInfo: *info,
	}, nil
}
