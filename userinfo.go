package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// UserInfo is the OIDC userinfo response.
type UserInfo struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	FamilyName        string `json:"family_name"`
	GivenName         string `json:"given_name"`
	Locale            string `json:"locales"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Sub               string `json:"sub"`
	Zoneinfo          string `json:"zoneinfo"`
}

func (o *oktaClient) GetUserInfo(c context.Context, accessToken string) (*UserInfo, error) {
	userinfoURL := o.issuer + "/oauth2/v1/userinfo"

	req, err := http.NewRequestWithContext(c, http.MethodGet, userinfoURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("okta userinfo read body: %w", err)
	}

	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("okta userinfo decode: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return &info, fmt.Errorf("okta userinfo http %d", resp.StatusCode)
	}
	return &info, nil
}
