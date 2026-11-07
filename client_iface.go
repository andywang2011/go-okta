package okta

import (
	"context"

	verifier "github.com/okta/okta-jwt-verifier-golang"
)

// Client is the Okta OIDC client surface (mock-friendly).
type Client interface {
	GetAuthUrl(nonce, state string) string
	CodeExchangeToken(c context.Context, code, state string) (*Exchange, error)
	GetUserInfo(c context.Context, accessToken string) (*UserInfo, error)
	VerifyToken(t, nonce string) (*verifier.Jwt, error)
	GenerateNonce() (string, error)
	Logout(c context.Context, accessToken string) error
}

// API is an alias for Client for backward compatibility.
type API = Client
