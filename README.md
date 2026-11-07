# go-okta

Deprecated Okta OIDC client (prefer [go-oidc](../go-oidc) for PKCE and JWKS); kept for compatibility.

## Install

```bash
go get github.com/andywang2011/go-okta@v0.1.0
```

## Quick start

```go
api, err := okta.NewClient(okta.Config{
	ClientID:     "your-client-id",
	ClientSecret: "your-client-secret",
	Issuer:       "https://dev-123456.okta.com/oauth2/default",
	Callback:     "http://localhost:8080/login/callback",
	Timeout:      6 * time.Second,
})
if err != nil {
	// handle
}
_ = api
```

## Examples

```bash
cd go-okta/examples && go run .
```

## License

MIT — see [LICENSE](LICENSE).
