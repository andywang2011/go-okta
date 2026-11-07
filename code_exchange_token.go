package okta

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxResponseBytes caps token/userinfo response bodies read into memory.
const maxResponseBytes = 1 << 20

// Exchange is the OAuth token endpoint response.
type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

func (o *oktaClient) CodeExchangeToken(c context.Context, code, state string) (*Exchange, error) {
	if state == "" {
		return nil, ErrEmptyState
	}

	form := url.Values{}
	form.Set("state", state)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", o.callback)

	tokenURL := o.issuer + "/oauth2/v1/token"

	req, err := http.NewRequestWithContext(c, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	authHeader := base64.StdEncoding.EncodeToString([]byte(o.clientId + ":" + o.clientSecret))
	req.Header.Set("Authorization", "Basic "+authHeader)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("okta token read body: %w", err)
	}

	var exchange Exchange
	if err := json.Unmarshal(body, &exchange); err != nil {
		if resp.StatusCode >= http.StatusBadRequest {
			return nil, fmt.Errorf("okta token http %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("okta token decode: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		if exchange.Error != "" {
			return &exchange, fmt.Errorf("okta token error: %s", exchange.Error)
		}
		return &exchange, fmt.Errorf("okta token http %d", resp.StatusCode)
	}
	return &exchange, nil
}
