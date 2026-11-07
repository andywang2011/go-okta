package okta

import (
	"errors"
	"time"
)

// Config holds Okta OIDC settings.
type Config struct {
	// ClientID is the Okta application client ID.
	ClientID string
	// ClientSecret is the Okta application client secret.
	ClientSecret string
	// Issuer is the Okta authorization server issuer URL.
	Issuer string
	// Callback is the OAuth redirect URI registered in Okta.
	Callback string
	// Timeout is the HTTP client timeout for token and userinfo calls.
	Timeout time.Duration
}

// DefaultConfig returns defaults with a 6s HTTP timeout.
func DefaultConfig() Config {
	return Config{Timeout: 6 * time.Second}
}

// ConfigDefault is an alias for DefaultConfig (naming consistency across go-* libs).
func ConfigDefault() Config { return DefaultConfig() }

// Validate checks required fields.
func (c Config) Validate() error {
	if c.ClientID == "" || c.ClientSecret == "" || c.Issuer == "" || c.Callback == "" {
		return errors.New("okta config incomplete")
	}
	if c.Timeout <= 0 {
		return errors.New("okta timeout must be positive")
	}
	return nil
}
