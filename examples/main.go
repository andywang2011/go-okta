// Example: OIDC login flow against a local mock Okta server (no real tenant needed).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	libokta "github.com/andywang2011/go-okta"
)

func main() {
	srv := httptest.NewServer(http.HandlerFunc(mockOkta))
	defer srv.Close()

	api, err := libokta.NewClient(libokta.Config{
		ClientID:     "demo-client",
		ClientSecret: "demo-secret",
		Issuer:       srv.URL,
		Callback:     "http://localhost:8080/login/callback",
		Timeout:      3 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	nonce, err := api.GenerateNonce()
	if err != nil {
		log.Fatal(err)
	}
	state := "example-state"
	authURL := api.GetAuthUrl(nonce, state)
	fmt.Println("auth URL:", authURL)
	if !strings.Contains(authURL, "client_id=demo-client") {
		log.Fatal("unexpected auth URL")
	}

	ctx := context.Background()
	exchange, err := api.CodeExchangeToken(ctx, "auth-code-123", state)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("access_token:", exchange.AccessToken)

	info, err := api.GetUserInfo(ctx, exchange.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("user: email=%s sub=%s\n", info.Email, info.Sub)
}

func mockOkta(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/oauth2/v1/token":
		_ = json.NewEncoder(w).Encode(libokta.Exchange{
			AccessToken: "mock-access-token",
			IdToken:     "mock-id-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	case "/oauth2/v1/userinfo":
		_ = json.NewEncoder(w).Encode(libokta.UserInfo{
			Email: "alice@example.com",
			Sub:   "okta-user-1",
			Name:  "Alice",
		})
	default:
		http.NotFound(w, r)
	}
}
