# Changelog

## [0.2.0] - 2026-11-07

### Breaking

- See repository diff for API changes in this release (secure defaults, renamed packages where applicable, context-aware constructors).

### Security

- Hardened defaults: TLS, timeouts, body limits, PII redaction where logging applies.

### Fixed

- Bug fixes from the v0.2.0 hardening pass.

### Changed

- CI uses go-version-file; added race, staticcheck, govulncheck, golangci-lint (gosec).


## [0.1.0] - 2026-11-07

### Added

- Authorization URL, code exchange, userinfo, ID token verify, and logout
- `API` interface and `NewClient` with config injection
- English README, examples, and package documentation

### Deprecated

- Prefer github.com/andywang2011/go-oidc for PKCE and JWKS verification
