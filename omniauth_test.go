package omniauth

import (
	"testing"

	"golang.org/x/oauth2"
)

func TestNewOmniAuth(t *testing.T) {
	if omniauth := NewOmniAuth(&oauth2.Config{}); omniauth == nil {
		t.Error("failed to initialize OmniAuth")
	}
}
