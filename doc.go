// Package okta provides a deprecated Okta OIDC client; prefer go-oidc for new work.
//
// Design constraints:
//   - Configuration via Config (no viper, no log.Fatal inside the library).
//   - NewClient returns Client (client_iface.go); API is a type alias for backward compatibility.
//   - Use ConfigDefault() for HTTP timeout defaults.
//   - HTTP calls use go-httplib with configurable timeout.
package okta
