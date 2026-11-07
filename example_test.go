package okta_test

import (
	"time"

	"github.com/andywang2011/go-okta"
)

func ExampleNewClient() {
	api, err := okta.NewClient(okta.Config{
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret",
		Issuer:       "https://dev-123456.okta.com/oauth2/default",
		Callback:     "http://localhost:8080/login/callback",
		Timeout:      6 * time.Second,
	})
	if err != nil {
		return
	}
	_ = api
}
