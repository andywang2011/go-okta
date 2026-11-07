package okta

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/andywang2011/go-httplib"

	verifier "github.com/okta/okta-jwt-verifier-golang"
)

type oktaClient struct {
	clientId     string
	clientSecret string
	issuer       string
	callback     string
	client       *httplib.Client
}

var _ Client = (*oktaClient)(nil)

var (
	// ErrEmptyState is returned when the OAuth state parameter is empty.
	ErrEmptyState = errors.New("okta: state must not be empty")
	// ErrEmptyNonce is returned when the OIDC nonce parameter is empty.
	ErrEmptyNonce = errors.New("okta: nonce must not be empty")
)

// NewClient creates an Okta client from Config.
func NewClient(cfg Config) (Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &oktaClient{
		clientId:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		issuer:       cfg.Issuer,
		callback:     cfg.Callback,
		client:       httplib.NewClient(httplib.WithTimeout(cfg.Timeout)),
	}, nil
}

// GetAuthUrl builds the authorization URL. It returns an empty string when
// nonce or state is empty; use ValidateAuthParams to obtain the error.
func (o *oktaClient) GetAuthUrl(nonce, state string) string {
	if ValidateAuthParams(nonce, state) != nil {
		return ""
	}
	values := url.Values{}
	values.Add("client_id", o.clientId)
	values.Add("response_type", "code")
	values.Add("response_mode", "query")
	values.Add("scope", "openid profile email")
	values.Add("redirect_uri", o.callback)
	values.Add("state", state)
	values.Add("nonce", nonce)
	return o.issuer + "/oauth2/v1/authorize?" + values.Encode()
}

// ValidateAuthParams returns ErrEmptyNonce or ErrEmptyState when a value is empty.
func ValidateAuthParams(nonce, state string) error {
	if nonce == "" {
		return ErrEmptyNonce
	}
	if state == "" {
		return ErrEmptyState
	}
	return nil
}

func (o *oktaClient) Logout(c context.Context, accessToken string) error {
	signoutURL := o.issuer + "/login/signout"

	req, err := http.NewRequestWithContext(c, http.MethodGet, signoutURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("okta logout request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta logout failed: http %d", resp.StatusCode)
	}
	return nil
}

func (o *oktaClient) VerifyToken(t, nonce string) (*verifier.Jwt, error) {
	if nonce == "" {
		return nil, ErrEmptyNonce
	}
	tv := map[string]string{
		"nonce": nonce,
		"aud":   o.clientId,
	}

	jv := verifier.JwtVerifier{
		Issuer:           o.issuer,
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("okta verify token: %w", err)
	}

	if result != nil {
		return result, nil
	}
	return nil, errors.New("token could not be verified")
}

func (o *oktaClient) GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("okta generate nonce: %w", err)
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}
